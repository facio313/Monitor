"""Reduced, bounded host inventory for the central enrollment contract."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
from pathlib import Path


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _bounded(value: object, maximum: int, fallback: str) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or _CONTROL.search(text):
        return fallback
    return text


def _read_bounded(path: Path, maximum: int) -> str:
    try:
        with path.open("rb") as source:
            encoded = source.read(maximum + 1)
    except OSError:
        return ""
    if len(encoded) > maximum:
        return ""
    return encoded.decode("utf-8", "replace")


def _ubuntu_version() -> str | None:
    values: dict[str, str] = {}
    for line in _read_bounded(Path("/etc/os-release"), 32 * 1024).splitlines():
        if "=" not in line:
            continue
        key, raw = line.split("=", 1)
        if key not in {"ID", "VERSION_ID"}:
            continue
        values[key] = raw.strip().strip('"\'')
    if values.get("ID", "").lower() != "ubuntu":
        return None
    version = values.get("VERSION_ID", "")
    return _bounded(version, 64, "unknown")


def _cpu_model() -> str:
    for line in _read_bounded(Path("/proc/cpuinfo"), 1024 * 1024).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in {"model name", "hardware", "processor"}:
            return _bounded(value, 256, "unknown")
    return "unknown"


def _memory_bytes() -> int:
    for line in _read_bounded(Path("/proc/meminfo"), 128 * 1024).splitlines():
        match = re.fullmatch(r"MemTotal:\s+([1-9][0-9]*)\s+kB", line)
        if match:
            value = int(match.group(1)) * 1024
            if 1 <= value <= (2**53 - 1):
                return value
    # The server requires a positive safe integer. sysconf is a bounded fallback.
    try:
        value = int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError):
        value = 1
    return max(1, min(value, 2**53 - 1))


def _ip_addresses(hostname: str) -> list[str]:
    addresses: set[str] = set()
    try:
        entries = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        entries = []
    for entry in entries:
        raw = entry[4][0].split("%", 1)[0]
        try:
            addresses.add(ipaddress.ip_address(raw).compressed)
        except ValueError:
            continue
    return sorted(addresses)[:16]


def collect_inventory(agent_version: str) -> dict[str, object]:
    """Return only the nine bounded fields accepted by parseInventory()."""

    hostname = _bounded(socket.gethostname(), 253, "unknown-host")
    return {
        "agentVersion": _bounded(agent_version, 64, "unknown"),
        "hostname": hostname,
        "ipAddresses": _ip_addresses(hostname),
        "operatingSystem": _bounded(platform.system(), 128, "unknown"),
        "ubuntuVersion": _ubuntu_version(),
        "kernelVersion": _bounded(platform.release(), 128, "unknown"),
        "architecture": _bounded(platform.machine(), 32, "unknown"),
        "cpuModel": _cpu_model(),
        "memoryBytes": _memory_bytes(),
    }


__all__ = ["collect_inventory"]
