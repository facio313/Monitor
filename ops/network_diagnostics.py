"""Bounded network evidence; no endpoint, address, request or response content.

Called by the host collector. TCP deltas use outbound segments as denominator;
unavailable/first/reset samples are null, never a fabricated healthy zero.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Mapping

MAX_DAY_BYTES = 8 * 1024 * 1024
MAX_DAY_ROWS = 10_000
MAX_ROW_BYTES = 32 * 1024
RETENTION_DAYS = 30
PROBE_STALE_SECONDS = 900
STATUS = {"ok", "dns", "permission", "timeout", "tls", "http", "invalid", "unsupported"}
PHASES = {"validation", "dns", "tcp", "tls", "request", "ttfb", "headers", "certificate", "redirect", "http"}
TIMINGS = ("dnsMs", "tcpMs", "tlsMs", "ttfbMs", "totalMs")


def number(value: Any, maximum: float = 1e18) -> float | int | None:
    return value if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and 0 <= value <= maximum else None


def timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z", value) is None:
        return None
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def safe_probe_id(value: Any) -> bool:
    return (isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value) is not None
            and "wgang" not in value.lower()
            and re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:gh[opsu]_|github_pat_|eyJ)", value) is None)


def validate_probe(value: Any) -> dict[str, Any]:
    fields = {"id", "checkedAt", "status", "httpStatus", "redirectCount", "errorPhase", "timings"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid diagnostic probe")
    timings = value["timings"]
    if (not safe_probe_id(value["id"]) or timestamp(value["checkedAt"]) is None
            or value["status"] not in STATUS or value["errorPhase"] not in PHASES | {None}
            or (value["status"] == "ok" and value["errorPhase"] is not None)
            or (value["status"] != "ok" and value["errorPhase"] is None)
            or number(value["redirectCount"], 5) is None or not isinstance(value["redirectCount"], int)
            or (value["httpStatus"] is not None and (number(value["httpStatus"], 599) is None or not isinstance(value["httpStatus"], int) or value["httpStatus"] < 100))
            or (value["status"] == "ok" and value["httpStatus"] is None)
            or not isinstance(timings, dict) or set(timings) != set(TIMINGS)
            or any(item is not None and number(item, 600_000) is None for item in timings.values())
            or timings["totalMs"] is None):
        raise ValueError("invalid diagnostic probe")
    return {key: value[key] for key in fields}


def read_safe(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > maximum:
            raise ValueError("unsafe diagnostic file")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise ValueError("oversize diagnostic file")
        return data
    finally:
        os.close(descriptor)


def load_probe_diagnostics(path: Path | None, now: dt.datetime) -> tuple[str, str | None, list[dict[str, Any]]]:
    if path is None:
        return "no_data", None, []
    try:
        document = json.loads(read_safe(path, 256 * 1024))
        if not isinstance(document, dict) or set(document) != {"schemaVersion", "generatedAt", "probes"} or document["schemaVersion"] != 1:
            raise ValueError("invalid diagnostic document")
        generated = timestamp(document["generatedAt"])
        if generated is None or generated > now + dt.timedelta(seconds=60):
            raise ValueError("invalid diagnostic time")
        values = document["probes"]
        if not isinstance(values, list) or len(values) > 32:
            raise ValueError("invalid diagnostic probes")
        probes = [validate_probe(value) for value in values
                  if not (isinstance(value, dict) and "wgang" in str(value.get("id", "")).lower())]
        if len({probe["id"] for probe in probes}) != len(probes):
            raise ValueError("duplicate diagnostic probes")
        if any(timestamp(probe["checkedAt"]) > generated + dt.timedelta(seconds=60) or
               timestamp(probe["checkedAt"]) < generated - dt.timedelta(seconds=600) for probe in probes):
            raise ValueError("inconsistent diagnostic time")
        state = "stale" if (now - generated).total_seconds() > PROBE_STALE_SECONDS else "fresh" if probes else "no_data"
        return state, document["generatedAt"], probes
    except FileNotFoundError:
        return "no_data", None, []
    except (OSError, ValueError, TypeError):
        return "error", None, []


def tcp_counters(proc_root: Path) -> tuple[int, int] | None:
    try:
        lines = read_safe(proc_root / "net" / "snmp", 64 * 1024).decode("ascii").splitlines()
        for index, line in enumerate(lines[:-1]):
            if line.startswith("Tcp:") and "OutSegs" in line:
                values = dict(zip(line.split()[1:], lines[index + 1].split()[1:]))
                result = int(values["RetransSegs"]), int(values["OutSegs"])
                return result if all(number(value) is not None for value in result) else None
    except (OSError, ValueError, KeyError):
        pass
    return None


def atomic_write(path: Path, content: bytes, mode: int = 0o640) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def record_network_diagnostics(data_dir: Path, *, metrics: Mapping[str, Any], pressure: Mapping[str, Any],
                               proc_root: Path, diagnostic_input: Path | None, now: dt.datetime) -> None:
    """Persist one sample, retaining at most 30 UTC days, 10k rows/8MiB per day.

    Call once per collection tick. OSError/ValueError propagates so the caller
    can mark collection failure in its operational log. No network requests.
    """
    now = now.astimezone(dt.timezone.utc)
    root = data_dir / "network-diagnostics"
    root.mkdir(mode=0o750, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("unsafe diagnostic directory")
    state_parent = data_dir / ".state"
    state_parent.mkdir(mode=0o700, exist_ok=True)
    state_info = state_parent.lstat()
    if not stat.S_ISDIR(state_info.st_mode) or state_info.st_mode & 0o022 or state_info.st_uid != os.geteuid():
        raise ValueError("unsafe diagnostic state parent")
    state_root = state_parent / "network-diagnostics"
    state_root.mkdir(mode=0o700, exist_ok=True)
    private_info = state_root.lstat()
    if not stat.S_ISDIR(private_info.st_mode) or stat.S_IMODE(private_info.st_mode) != 0o700 or private_info.st_uid != os.geteuid():
        raise ValueError("unsafe diagnostic private state")
    state_path = state_root / "tcp.json"
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        previous = {}
        try:
            previous = json.loads(read_safe(state_path, 4096))
        except (OSError, ValueError):
            pass
        if not isinstance(previous, dict):
            previous = {}
        counters = tcp_counters(proc_root)
        try:
            raw_boot = read_safe(proc_root / "sys" / "kernel" / "random" / "boot_id", 128).strip()
            boot = hashlib.sha256(raw_boot).hexdigest() if raw_boot else None
        except (OSError, ValueError):
            boot = None
        previous_time = number(previous.get("time"))
        elapsed = now.timestamp() - previous_time if previous_time is not None else None
        before = previous.get("counters")
        deltas = None
        if (counters is not None and boot and previous.get("boot") == boot and elapsed is not None and 0 < elapsed <= 600
                and isinstance(before, list) and len(before) == 2 and all(number(value) is not None for value in before)):
            computed = (counters[0] - before[0], counters[1] - before[1])
            if min(computed) >= 0:
                deltas = computed
        retransmitted, outbound = deltas if deltas is not None else (None, None)
        tcp = {"status": "fresh" if deltas is not None else "no_data" if counters is not None else "error",
               "elapsedSeconds": round(elapsed, 3) if deltas is not None else None,
               "retransmittedSegments": retransmitted, "outboundSegments": outbound,
               "retransmitPercent": round(100 * retransmitted / outbound, 6) if outbound else None,
               "retransmittedPerSecond": round(retransmitted / elapsed, 6) if deltas is not None else None,
               "outboundPerSecond": round(outbound / elapsed, 6) if deltas is not None else None}
        probe_state, probe_observed, probes = load_probe_diagnostics(diagnostic_input, now)
        interfaces = {key: number(metrics.get(field), 1e12) for key, field in (
            ("rxErrorsPerSecond", "networkRxErrorsPerSecond"), ("txErrorsPerSecond", "networkTxErrorsPerSecond"),
            ("rxDroppedPerSecond", "networkRxDroppedPerSecond"), ("txDroppedPerSecond", "networkTxDroppedPerSecond"))}
        context = {"cpuPercent": number(metrics.get("cpuPercent"), 100), "memoryPercent": number(metrics.get("memoryPercent"), 100)}
        for kind in ("cpu", "memory", "io"):
            source = pressure.get(kind)
            for dimension in ("someAvg10", "fullAvg10"):
                context[kind + "Pressure" + dimension[0].upper() + dimension[1:]] = number(source.get(dimension), 100) if isinstance(source, Mapping) else None
        problems = []
        if probe_state != "fresh" or any(probe["status"] != "ok" or probe["timings"]["totalMs"] >= 1000 for probe in probes):
            problems.append("http")
        if tcp["retransmitPercent"] is not None and tcp["retransmitPercent"] >= 1:
            problems.append("tcp")
        if any(value is not None and value > 0 for value in interfaces.values()):
            problems.append("interface")
        row = {"schemaVersion": 1, "observedAt": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
               "probeStatus": probe_state, "probeObservedAt": probe_observed, "probes": probes,
               "tcp": tcp, "interfaces": interfaces, "context": context, "problems": problems}
        encoded = (json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(encoded) > MAX_ROW_BYTES:
            raise ValueError("diagnostic sample exceeds row bound")
        day_path = root / f"{now.date().isoformat()}.jsonl"
        try:
            old = read_safe(day_path, MAX_DAY_BYTES)
        except FileNotFoundError:
            old = b""
        if len(encoded) > MAX_DAY_BYTES:
            raise ValueError("diagnostic sample exceeds day bound")
        # Recover an incomplete final write before appending the next sample.
        incomplete = bool(old and not old.endswith(b"\n"))
        if incomplete:
            old = old[:old.rfind(b"\n") + 1]
        if incomplete or len(old) + len(encoded) > MAX_DAY_BYTES or old.count(b"\n") >= MAX_DAY_ROWS:
            # Drop a small batch when full, avoiding a complete 8-MiB rewrite
            # on every collection tick once the day's storage limit is reached.
            lines = (old + encoded).splitlines(keepends=True)[-math.ceil(MAX_DAY_ROWS * .9):]
            size = sum(map(len, lines))
            dropped = 0
            target_size = max(len(encoded), int(MAX_DAY_BYTES * .9))
            while size > target_size:
                size -= len(lines[dropped])
                dropped += 1
            atomic_write(day_path, b"".join(lines[dropped:]))
        else:
            descriptor = os.open(day_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o022:
                    raise ValueError("unsafe diagnostic history")
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
        atomic_write(root / "latest.json", encoded)
        atomic_write(state_path, json.dumps({"time": now.timestamp(), "boot": boot, "counters": counters}).encode(), 0o600)
        state_fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(state_fd)
        finally:
            os.close(state_fd)
        cutoff = (now - dt.timedelta(days=RETENTION_DAYS - 1)).date().isoformat()
        for candidate in root.iterdir():
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", candidate.name) and candidate.name[:10] < cutoff:
                candidate.unlink()
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
