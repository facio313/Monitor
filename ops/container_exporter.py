#!/usr/bin/env python3
"""Ephemeral, cks-owned Docker telemetry exporter.

The root host collector consumes only this reduced file and never receives a
Docker socket in its mount namespace.  This helper intentionally runs as the
same unprivileged account that owns the one allow-listed rootless daemon.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import os
import sys
from pathlib import Path
from typing import Sequence

import collector


EXPECTED_UID = 1001
EXPECTED_SOCKET = Path("/run/user/1001/docker.sock")
MAX_TIMEOUT_SECONDS = 5.0


def config_from_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=str(EXPECTED_SOCKET))
    parser.add_argument("--output", default="/run/monitor-container-exporter/containers.json")
    parser.add_argument("--state", default="/run/monitor-container-exporter/cpu-state.json")
    parser.add_argument("--curl", default="/usr/bin/curl")
    parser.add_argument("--timeout", type=float, default=2.0)
    values = parser.parse_args(arguments)
    if Path(values.socket) != EXPECTED_SOCKET:
        parser.error("only the cks rootless Docker socket is allowed")
    values.timeout = max(0.25, min(MAX_TIMEOUT_SECONDS, values.timeout))
    return values


def run(arguments: Sequence[str] | None = None) -> None:
    if os.geteuid() != EXPECTED_UID:
        raise PermissionError("container exporter must run as cks")
    values = config_from_arguments(arguments)
    socket_path = Path(values.socket)
    output_path = Path(values.output)
    state_path = Path(values.state)
    if output_path.parent != state_path.parent:
        raise ValueError("output and private state must share one runtime directory")

    collector.ensure_directory(output_path.parent, 0o750)
    lock_path = output_path.parent / "exporter.lock"
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

        prior = collector.load_json(state_path)
        previous_containers: list[dict[str, object]] = []
        previous_observed_at: str | None = None
        try:
            previous_containers, previous_collection = collector.load_container_snapshot_state(
                output_path,
                dt.datetime.now(dt.timezone.utc),
                expected_uid=EXPECTED_UID,
                expected_gid=EXPECTED_UID,
            )
            previous_observed_at = previous_collection["observedAt"]
        except (OSError, RuntimeError, ValueError):
            pass

        try:
            containers, next_cpu_state = collector.collect_containers(
                {"cks": socket_path}, values.curl, values.timeout, prior.get("containers")
            )
        except PermissionError:
            generated_at = collector.iso_timestamp(dt.datetime.now(dt.timezone.utc))
            collector.atomic_write_json(
                output_path,
                {
                    "generatedAt": generated_at,
                    "containerCollection": {
                        "status": "permission-denied",
                        "observedAt": previous_observed_at,
                    },
                    "containers": previous_containers if previous_observed_at is not None else [],
                },
                0o640,
            )
            return
        except (collector.ContainerSourceUnavailable, RuntimeError):
            generated_at = collector.iso_timestamp(dt.datetime.now(dt.timezone.utc))
            collector.atomic_write_json(
                output_path,
                {
                    "generatedAt": generated_at,
                    "containerCollection": {
                        "status": "last-known" if previous_observed_at is not None else "unavailable",
                        "observedAt": previous_observed_at,
                    },
                    "containers": previous_containers if previous_observed_at is not None else [],
                },
                0o640,
            )
            return
        if any(value.get("owner") != "cks" for value in containers):
            raise ValueError("unexpected container owner")

        generated_at = collector.iso_timestamp(dt.datetime.now(dt.timezone.utc))
        collector.atomic_write_json(
            output_path,
            {
                "generatedAt": generated_at,
                "containerCollection": {
                    "status": "fresh",
                    "observedAt": generated_at,
                },
                "containers": containers,
            },
            0o640,
        )
        collector.atomic_write_json(
            state_path,
            {"generatedAt": generated_at, "containers": next_cpu_state},
            0o600,
        )


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        run(arguments)
        return 0
    except BlockingIOError:
        return 0
    except Exception as error:
        print(f"monitor-container-exporter: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
