"""Render a fixed SSH-only nftables table from a validated local country DB.

Pure read-only generator: no network, subprocess, apply, or output-file writes.
The caller owns atomic replacement of this table and management-lockout safety.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

try:
    from .ip_country import CountryLookup, DEFAULT_PATH, MAX_DB_BYTES, MAX_RECORDS
except ImportError:  # Direct CLI invocation beside ip_country.py.
    from ip_country import CountryLookup, DEFAULT_PATH, MAX_DB_BYTES, MAX_RECORDS

MAX_KR_RANGES = 100_000
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
# Conservatively reject special-purpose space, even across a range whose two
# endpoints are public. IPv6 is additionally limited to global unicast 2000::/3.
SPECIAL = {
    4: ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"),
    6: ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"),
}
BLOCKED = {version: [(int(net.network_address), int(net.broadcast_address))
                     for net in map(ipaddress.ip_network, values)]
           for version, values in SPECIAL.items()}
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
COUNTERS = ("loopback", "lan", "kr4", "kr6", "denied")
PORTS = "tcp dport { 22, 22022 }"


def _public_range(first: ipaddress.IPv4Address | ipaddress.IPv6Address,
                  last: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if any(not ip.is_global or ip.is_multicast or ip.is_reserved for ip in (first, last)):
        return False
    if first.version == 6 and (first not in GLOBAL_V6 or last not in GLOBAL_V6):
        return False
    low, high = int(first), int(last)
    return not any(low <= end and high >= start for start, end in BLOCKED[first.version])


def render_rules(database: Path | str = DEFAULT_PATH, *, today: dt.date | None = None) -> str:
    """Return a complete table, or raise ValueError without partial output."""
    try:
        with CountryLookup(database, today=today) as lookup:
            if lookup.connection is None or lookup.descriptor is None or not lookup.database_date or lookup.stale:
                raise ValueError("country database is unavailable or stale")
            before = os.fstat(lookup.descriptor)
            metadata = dict(lookup.connection.execute("SELECT key,value FROM metadata LIMIT 7"))
            ranges: dict[int, list[str]] = {4: [], 6: []}
            previous: dict[int, int] = {}
            count = kr_count = 0
            # Validate every row, including foreign neighbours: a corrupt KR row
            # must not silently overlap a foreign allocation or escape row caps.
            rows = lookup.connection.execute(
                "SELECT version,start,end,country FROM ranges ORDER BY version,start LIMIT ?",
                (MAX_RECORDS + 1,),
            )
            for version, start, end, country in rows:
                count += 1
                if (count > MAX_RECORDS or version not in (4, 6) or type(start) is not bytes
                        or type(end) is not bytes or len(start) != (4 if version == 4 else 16)
                        or len(end) != len(start) or start > end or not isinstance(country, str)
                        or re.fullmatch(r"[A-Z]{2}", country) is None):
                    raise ValueError("invalid country range")
                first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
                if int(first) <= previous.get(version, -1):
                    raise ValueError("overlapping country ranges")
                previous[version] = int(last)
                if country != "KR":
                    continue
                kr_count += 1
                if kr_count > MAX_KR_RANGES or not _public_range(first, last):
                    raise ValueError("unsafe or excessive Korean ranges")
                ranges[version].append(str(first) if first == last else f"{first}-{last}")
            if count != int(metadata["recordCount"]) or not all(ranges.values()):
                raise ValueError("missing Korean ranges or invalid record count")
            digest = hashlib.sha256()
            offset = 0
            while chunk := os.pread(lookup.descriptor, 65536, offset):
                offset += len(chunk)
                if offset > MAX_DB_BYTES:
                    raise ValueError("country database exceeds bounds")
                digest.update(chunk)
            after = os.fstat(lookup.descriptor)
            if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("country database changed while reading")
            lines = [
                "# Monitor SSH Korea source guard; generated locally; country is an estimate.",
                f"# database_date: {lookup.database_date}; source: DB-IP IP to Country Lite; license: CC BY 4.0",
                f"# source_sha256: {metadata['checksumSha256']}",
                f"# database_sha256: {digest.hexdigest()}",
                f"# KR source ranges: IPv4={len(ranges[4])}; IPv6={len(ranges[6])}",
                "# Exceptions: loopback interface; eth0 source 192.168.75.190/32 only.",
                "# Update the single management source if its DHCP address changes; no destination pin.",
                "# Return delegates to other filters. All non-SSH traffic keeps the accept policy.",
                "table inet monitor_ssh_geo {",
            ]
            for version in (4, 6):
                lines.extend([f"    set kr{version} {{", f"        type ipv{version}_addr",
                              "        flags interval", "        auto-merge", "        elements = {"])
                lines.extend(f"            {value}{',' if index + 1 < len(ranges[version]) else ''}"
                             for index, value in enumerate(ranges[version]))
                lines.extend(["        }", "    }"])
            lines.extend(f"    counter ssh_geo_{name} {{ }}" for name in COUNTERS)
            lines.extend([
                "    chain input {",
                "        type filter hook input priority -10; policy accept;",
                f'        iifname "lo" {PORTS} counter name ssh_geo_loopback return',
                f'        iifname "eth0" ip saddr 192.168.75.190 {PORTS} counter name ssh_geo_lan return',
                f"        ip saddr @kr4 {PORTS} counter name ssh_geo_kr4 return",
                f"        ip6 saddr @kr6 {PORTS} counter name ssh_geo_kr6 return",
                f'        {PORTS} limit rate 3/minute burst 5 packets log prefix "SSH_GEO_DROP " level info',
                f"        {PORTS} counter name ssh_geo_denied drop",
                "    }", "}", "",
            ])
            output = "\n".join(lines)
            if len(output.encode("ascii")) > MAX_OUTPUT_BYTES:
                raise ValueError("generated rules exceed bounds")
            return output
    except (OSError, sqlite3.Error, TypeError, KeyError, ValueError) as error:
        raise ValueError("SSH geo guard generation failed: invalid, unsafe, or stale country database") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--github-policy", type=Path,
                        help="preserve GitHub SSH exceptions from the currently pinned policy")
    args = parser.parse_args(argv)
    try:
        output = render_rules(args.database)
        if args.github_policy:
            try:
                from .github_ssh_ranges import extract_ranges, render_policy
            except ImportError:
                from github_ssh_ranges import extract_ranges, render_policy
            with args.github_policy.open("rb") as stream:
                pinned = stream.read(2 * 1024 * 1024 + 1)
            if len(pinned) > 2 * 1024 * 1024:
                raise ValueError("pinned policy exceeds bounds")
            output = render_policy(output, extract_ranges(pinned.decode("ascii")))
    except (OSError, UnicodeError, ValueError):
        print("SSH geo guard generation failed: invalid, unsafe, or stale country database", file=sys.stderr)
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
