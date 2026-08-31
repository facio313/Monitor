"""Command-line entry point. Enrollment tokens are never accepted as arguments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import BinaryIO

from .config import ConfigError, MAX_ENQUEUE_BYTES, TransportConfig
from .storage import StorageError
from .transport import AgentTransport, AgentTransportError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="monitor-agent-transport")
    parser.add_argument("--config", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll", help="stage and submit a one-use enrollment token")
    enroll.add_argument(
        "--token-file",
        type=Path,
        help="mode-0600 token file; omit to read the token from standard input",
    )
    commands.add_parser("run-once", help="attempt due enrollment, heartbeat, and ingest work")
    commands.add_parser("status", help="print reduced local transport state")
    commands.add_parser(
        "quarantine-list",
        help="print reduced metadata for permanently rejected batches",
    )
    purge = commands.add_parser(
        "quarantine-purge",
        help="explicitly abandon one inspected permanently rejected batch",
    )
    purge.add_argument("batch_id", help="canonical rejected batch UUID")
    commands.add_parser("enqueue", help="read a JSON array of reduced records from standard input")
    return parser


def _read_records(stream: BinaryIO, maximum_bytes: int = MAX_ENQUEUE_BYTES) -> list[object]:
    encoded = stream.read(maximum_bytes + 1)
    if len(encoded) > maximum_bytes:
        raise AgentTransportError("one telemetry enqueue exceeds its bounded input size")
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentTransportError("telemetry input is not a UTF-8 JSON array") from error
    if not isinstance(value, list):
        raise AgentTransportError("telemetry input must be one JSON array")
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        config = TransportConfig.load(arguments.config)
        transport = AgentTransport(config)
        if arguments.command == "enroll":
            if arguments.token_file is not None:
                result = transport.enroll_from_file(arguments.token_file)
            else:
                if sys.stdin.isatty():
                    raise AgentTransportError(
                        "refusing to echo an enrollment token on a terminal; use a pipe or --token-file"
                    )
                result = transport.begin_enrollment(
                    AgentTransport.read_token_stdin(sys.stdin.buffer)
                )
            print(json.dumps({"enrollment": result}, separators=(",", ":")))
            return 0 if result == "acknowledged" else 75
        if arguments.command == "enqueue":
            batch_ids = transport.enqueue(_read_records(sys.stdin.buffer))
            print(json.dumps({"queued": True, "batchIds": batch_ids}, separators=(",", ":")))
            return 0
        if arguments.command == "run-once":
            print(json.dumps(transport.run_once().as_dict(), separators=(",", ":")))
            return 0
        if arguments.command == "status":
            print(json.dumps(transport.status(), separators=(",", ":"), sort_keys=True))
            return 0
        if arguments.command == "quarantine-list":
            print(json.dumps(transport.list_quarantine(), separators=(",", ":"), sort_keys=True))
            return 0
        if arguments.command == "quarantine-purge":
            purged = transport.purge_quarantine(arguments.batch_id)
            print(json.dumps(
                {"batchId": arguments.batch_id, "purged": purged},
                separators=(",", ":"),
                sort_keys=True,
            ))
            return 0 if purged else 1
        raise AssertionError("unreachable command")
    except (ConfigError, StorageError, AgentTransportError) as error:
        # Error messages never include tokens, request/response bodies, certificate data, or telemetry.
        print(f"monitor-agent-transport: {error}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
