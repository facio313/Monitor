"""Pure, bounded GitHub Meta CIDR validation and SSH policy rendering.

Every published IP array is included, including newly introduced categories.
Only the documented non-IP key arrays are excluded. No network or file writes.
"""
from __future__ import annotations

import ipaddress
import json
import re

MAX_META_BYTES = 2 * 1024 * 1024
MAX_META_RANGES = 100_000
MAX_POLICY_BYTES = 2 * 1024 * 1024
IP_CATEGORIES = frozenset({
    "actions", "actions_macos", "api", "codespaces", "copilot", "dependabot",
    "git", "github_enterprise_importer", "hooks", "importer", "packages",
    "pages", "web",
})
NON_IP_ARRAYS = frozenset({"ssh_keys", "commit_signing_keys"})
# Endpoint checks alone miss special-purpose holes within a larger allocation.
SPECIAL = {
    4: ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"),
    6: ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"),
}
BLOCKED = {version: tuple(map(ipaddress.ip_network, values))
           for version, values in SPECIAL.items()}
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
TABLE = "table inet monitor_ssh_geo {\n"
PORTS = "tcp dport { 22, 22022 }"
LOG_RULE = (f'        {PORTS} limit rate 3/minute burst 5 packets '
            'log prefix "SSH_GEO_DROP " level info\n')
DROP_RULE = f"        {PORTS} counter name ssh_geo_denied drop\n"
SETS_BEGIN = "    # BEGIN GITHUB SSH SETS\n"
SETS_END = "    # END GITHUB SSH SETS\n"
RULES_BEGIN = "        # BEGIN GITHUB SSH RULES\n"
RULES_END = "        # END GITHUB SSH RULES\n"


def _network(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if (not isinstance(value, str) or len(value) > 49
            or re.fullmatch(r"[0-9a-fA-F:.]+/[0-9]{1,3}", value) is None):
        raise ValueError("GitHub range is not a CIDR string")
    network = ipaddress.ip_network(value, strict=True)
    if (network.prefixlen == 0
            or any(not address.is_global or address.is_multicast or address.is_reserved
                   for address in (network.network_address, network.broadcast_address))
            or network.version == 6 and not network.subnet_of(GLOBAL_V6)
            or any(network.overlaps(blocked) for blocked in BLOCKED[network.version])):
        raise ValueError("GitHub range includes nonpublic addresses")
    return network


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate GitHub metadata field")
        result[key] = value
    return result


def _collapse(ranges: dict[int, list]) -> dict[int, list[str]]:
    return {version: [str(network) for network in ipaddress.collapse_addresses(ranges[version])]
            for version in (4, 6)}


def parse_meta(payload: bytes) -> dict[int, list[str]]:
    """Validate all official top-level IP arrays and collapse their exact union.

    An invalid response raises ValueError; callers must keep the last policy.
    Overlaps and adjacent networks may merge, but no address gaps are filled.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_META_BYTES:
        raise ValueError("GitHub metadata exceeds byte bounds")
    try:
        metadata = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid GitHub metadata JSON") from error
    if (not isinstance(metadata, dict) or not isinstance(metadata.get("actions"), list)
            or not metadata["actions"]):
        raise ValueError("GitHub metadata has no Actions ranges")
    ranges: dict[int, list] = {4: [], 6: []}
    count = 0
    for category, values in metadata.items():
        if category in NON_IP_ARRAYS:
            continue
        if category in IP_CATEGORIES and not isinstance(values, list):
            raise ValueError("GitHub IP category is not an array")
        if not isinstance(values, list):
            continue
        count += len(values)
        if count > MAX_META_RANGES:
            raise ValueError("too many GitHub ranges")
        for value in values:
            network = _network(value)
            ranges[network.version].append(network)
    if not all(ranges.values()):
        raise ValueError("GitHub metadata must include IPv4 and IPv6 ranges")
    return _collapse(ranges)


def _validated_ranges(ranges: dict[int, list[str]]) -> dict[int, list[str]]:
    if not isinstance(ranges, dict) or set(ranges) != {4, 6}:
        raise ValueError("GitHub ranges must have exactly two IP families")
    if any(not isinstance(ranges[version], list) for version in (4, 6)):
        raise ValueError("GitHub ranges must be arrays")
    if sum(map(len, ranges.values())) > MAX_META_RANGES:
        raise ValueError("too many GitHub ranges")
    networks: dict[int, list] = {4: [], 6: []}
    for version in (4, 6):
        for value in ranges[version]:
            network = _network(value)
            if network.version != version:
                raise ValueError("GitHub range has the wrong IP family")
            networks[version].append(network)
    if bool(networks[4]) != bool(networks[6]):
        raise ValueError("GitHub policy must include both IP families")
    return _collapse(networks)


def _render_sets(ranges: dict[int, list[str]]) -> str:
    lines = [SETS_BEGIN.rstrip("\n")]
    for version in (4, 6):
        lines.extend([f"    set github{version} {{", f"        type ipv{version}_addr",
                      "        flags interval", "        auto-merge", "        elements = {"])
        lines.extend(f"            {value}{',' if index + 1 < len(ranges[version]) else ''}"
                     for index, value in enumerate(ranges[version]))
        lines.extend(["        }", "    }"])
    lines.extend(f"    counter ssh_geo_github{version} {{ }}" for version in (4, 6))
    lines.append(SETS_END.rstrip("\n"))
    return "\n".join(lines) + "\n"


def _render_rules() -> str:
    return (RULES_BEGIN
            + f"        ip saddr @github4 {PORTS} counter name ssh_geo_github4 return\n"
            + f"        ip6 saddr @github6 {PORTS} counter name ssh_geo_github6 return\n"
            + RULES_END)


def _validate_base(policy: str) -> None:
    """Reject ambiguous placement and policy outside the dedicated table."""
    if not isinstance(policy, str):
        raise ValueError("SSH policy must be text")
    try:
        size = len(policy.encode("ascii"))
    except UnicodeError as error:
        raise ValueError("SSH policy must be ASCII") from error
    if not 0 < size <= MAX_POLICY_BYTES:
        raise ValueError("SSH policy exceeds byte bounds")
    body = "\n".join(line for line in policy.splitlines() if not line.lstrip().startswith("#"))
    if (policy.count(TABLE) != 1 or not body.lstrip().startswith(TABLE)
            or len(re.findall(r"\btable\b", body)) != 1
            or re.search(r"\b(include|flush|delete|destroy|add|create|define|import|export)\b", body)
            or len(re.findall(r"\bchain\b", body)) != 1
            or policy.count("    chain input {\n") != 1
            or policy.count(LOG_RULE) != 1 or policy.count(DROP_RULE) != 1
            or not policy.endswith(LOG_RULE + DROP_RULE + "    }\n}\n")
            or re.search(r"\b(?:github[46]|ssh_geo_github[46])\b", body)):
        raise ValueError("SSH policy is not the expected dedicated country guard")
    lexical = re.sub(r'"(?:[^"\\]|\\.)*"', '""', body).strip()
    depth = 0
    for index, character in enumerate(lexical):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0 or depth == 0 and index != len(lexical) - 1:
                raise ValueError("commands outside the dedicated SSH table")
    if depth:
        raise ValueError("unbalanced SSH policy")


def _read_policy(policy: str) -> tuple[str, dict[int, list[str]]]:
    if not isinstance(policy, str) or len(policy) > MAX_POLICY_BYTES:
        raise ValueError("SSH policy exceeds byte bounds")
    markers = (SETS_BEGIN, SETS_END, RULES_BEGIN, RULES_END)
    # Count the text without indentation too, so misplaced or orphaned markers
    # are rejected rather than silently retained during a refresh.
    counts = [policy.count(marker.strip()) for marker in markers]
    if not any(counts):
        _validate_base(policy)
        return policy, {4: [], 6: []}
    if counts != [1, 1, 1, 1]:
        raise ValueError("incomplete or duplicate GitHub managed sections")
    sections = []
    for begin, end in ((SETS_BEGIN, SETS_END), (RULES_BEGIN, RULES_END)):
        match = re.search(r"^" + re.escape(begin) + r".*?^" + re.escape(end), policy, re.M | re.S)
        if match is None:
            raise ValueError("misplaced GitHub managed section")
        sections.append(match.group())
    sets, rules = sections
    ranges: dict[int, list[str]] = {4: [], 6: []}
    for version in (4, 6):
        match = re.search(rf"    set github{version} \{{\n.*?        elements = \{{\n"
                          r"(.*?)        }\n    }\n", sets, re.S)
        if match is None:
            raise ValueError("invalid managed GitHub set")
        ranges[version] = [line.strip().removesuffix(",") for line in match[1].splitlines()]
    ranges = _validated_ranges(ranges)
    if not all(ranges.values()) or sets != _render_sets(ranges) or rules != _render_rules():
        raise ValueError("modified or noncanonical GitHub managed sections")
    if TABLE + sets not in policy or rules + LOG_RULE not in policy:
        raise ValueError("GitHub managed sections are outside their expected positions")
    base = policy.replace(sets, "", 1).replace(rules, "", 1)
    _validate_base(base)
    return base, ranges


def extract_ranges(policy: str) -> dict[int, list[str]]:
    """Read validated pinned GitHub ranges for an offline country DB refresh."""
    return _read_policy(policy)[1]


def render_policy(policy: str, ranges: dict[int, list[str]]) -> str:
    """Replace only managed GitHub sections, preserving every baseline byte.

    Both empty families explicitly remove the managed exception. All nonempty
    inputs are independently validated so callers cannot interpolate nft code.
    """
    base, _ = _read_policy(policy)
    canonical = _validated_ranges(ranges)
    if not any(canonical.values()):
        return base
    result = base.replace(TABLE, TABLE + _render_sets(canonical), 1)
    result = result.replace(LOG_RULE, _render_rules() + LOG_RULE, 1)
    if len(result.encode("ascii")) > MAX_POLICY_BYTES:
        raise ValueError("SSH policy exceeds byte bounds")
    return result
