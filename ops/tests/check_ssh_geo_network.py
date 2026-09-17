#!/usr/bin/env python3
"""Exercise a rendered SSH policy with real TCP in disposable network namespaces.

Run as root: python3 ops/tests/check_ssh_geo_network.py --policy /path/to/policy.nft
Only the supplied policy is read. All links, addresses, routes, and nft rules are
created after entering a new unnamed network namespace; none belong to the host.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ssh_geo_apply import make_transaction  # noqa: E402

DESTINATIONS = {4: "198.18.0.1", 6: "fd78:6e65:7474::1"}
GATEWAYS = {4: "198.18.0.2", 6: "fd78:6e65:7474::2"}
SSH_PORTS = (22, 22022)
CONTROL_PORT = 18080
HOLDER = "import sys; print('READY', flush=True); sys.stdin.read()"
PROBE = r"""
import errno, json, socket, sys
results = []
for case in json.load(sys.stdin):
    family = socket.AF_INET6 if ':' in case['source'] else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(case.get('timeout', 0.7))
            connection.bind((case['source'], 0))
            connection.connect((case['destination'], case['port']))
        result = 'allowed'
    except TimeoutError:
        result = 'dropped'
    except OSError as error:
        result = 'error: ' + str(error)
    results.append(dict(case, result=result))
print(json.dumps(results))
"""


def run(command: list[str], *, input_text: str | None = None,
        timeout: float = 30) -> str:
    result = subprocess.run(command, input=input_text, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command[:8])} failed: "
                           f"{result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def ranges_for(policy: str, name: str) -> list[tuple[int, int]]:
    match = re.search(r"\bset\s+" + re.escape(name)
                      + r"\s*\{[^{}]*\belements\s*=\s*\{([^}]*)\}", policy, re.S)
    if not match:
        raise ValueError(f"policy must define populated {name} address set")
    version = int(name[-1])
    ranges = []
    for element in match.group(1).split(","):
        element = element.strip()
        if not element:
            continue
        if "-" in element:
            low, high = map(ipaddress.ip_address, element.split("-", 1))
        else:
            network = ipaddress.ip_network(element, strict=False)
            low, high = network.network_address, network.broadcast_address
        if low.version != version or high.version != version or int(low) > int(high):
            raise ValueError(f"invalid address range in {name}: {element}")
        ranges.append((int(low), int(high)))
    if not ranges:
        raise ValueError(f"empty address set: {name}")
    return ranges


def contains(ranges: list[tuple[int, int]], address: str) -> bool:
    value = int(ipaddress.ip_address(address))
    return any(first <= value <= last for first, last in ranges)


def representative(ranges: list[tuple[int, int]], version: int) -> str:
    first, last = ranges[0]
    constructor = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return str(constructor(min(first + 1, last)))


def build_cases(policy: str) -> tuple[list[dict[str, Any]], list[str]]:
    sets = {name: ranges_for(policy, name)
            for name in ("kr4", "kr6", "github4", "github6")}
    sources = [
        ("Korean IPv4", representative(sets["kr4"], 4), True),
        ("Korean IPv6", representative(sets["kr6"], 6), True),
        ("failed GitHub runner 1", "20.118.29.96", True),
        ("failed GitHub runner 2", "20.168.119.81", True),
        ("GitHub IPv6", representative(sets["github6"], 6), True),
        ("foreign IPv4", "1.1.1.1", False),
        ("foreign IPv6", "2606:4700:4700::1111", False),
        ("management eth0", "192.168.75.190", True),
        ("other internal PC", "192.168.75.191", False),
    ]
    for address in ("20.118.29.96", "20.168.119.81"):
        if not contains(sets["github4"], address):
            raise ValueError(f"previously failing runner {address} is absent from github4")
        if contains(sets["kr4"], address):
            raise ValueError(f"runner {address} also matches KR; cannot isolate GitHub exception")
    for address in ("1.1.1.1", "2606:4700:4700::1111",
                    "192.168.75.190", "192.168.75.191"):
        version = ipaddress.ip_address(address).version
        if any(contains(sets[f"{prefix}{version}"], address)
               for prefix in ("kr", "github")):
            raise ValueError(f"negative/control source {address} belongs to an allow set; "
                             "choose another source before running this check")
    cases = []
    for label, source, allowed in sources:
        version = ipaddress.ip_address(source).version
        for port in SSH_PORTS:
            cases.append({"name": label, "source": source,
                          "destination": DESTINATIONS[version], "port": port,
                          "expected": "allowed" if allowed else "dropped"})
        # Every representative must retain access to unrelated TCP traffic.
        cases.append({"name": label + " non-SSH", "source": source,
                      "destination": DESTINATIONS[version], "port": CONTROL_PORT,
                      "expected": "allowed"})
    return cases, sorted({source for _, source, _ in sources})


def isolated_main(policy_path: Path, original_namespace: str) -> int:
    # Refuse hidden-mode invocation unless unshare really separated us from our
    # immediate parent. This guard executes before *any* network mutation.
    if (os.readlink("/proc/self/ns/net") == original_namespace
            or os.readlink(f"/proc/{os.getppid()}/ns/net") != original_namespace):
        raise RuntimeError("network isolation was not established; refusing to run")
    policy = policy_path.read_text(encoding="ascii")
    make_transaction(policy)  # Validate the single dedicated table restriction.
    cases, sources = build_cases(policy)
    holder: subprocess.Popen[str] | None = None
    listeners: list[socket.socket] = []
    try:
        holder = subprocess.Popen(["unshare", "--net", "--", sys.executable,
                                   "-c", HOLDER], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        assert holder.stdout is not None
        ready, _, _ = select.select([holder.stdout], [], [], 10)
        if not ready or holder.stdout.readline().strip() != "READY":
            detail = "client namespace did not become ready"
            if holder.poll() is not None and holder.stderr is not None:
                detail += ": " + holder.stderr.read().strip()
            raise RuntimeError(detail)
        if os.readlink(f"/proc/{holder.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("client namespace is not isolated")
        client = ["nsenter", "--target", str(holder.pid), "--net", "--"]
        run(["ip", "link", "set", "lo", "up"])
        run(["ip", "link", "add", "eth0", "type", "veth", "peer", "name", "client0"])
        run(["ip", "link", "set", "client0", "netns", str(holder.pid)])
        run(client + ["ip", "link", "set", "client0", "name", "eth0"])
        run(client + ["ip", "link", "set", "lo", "up"])
        run(["ip", "link", "set", "eth0", "up"])
        run(client + ["ip", "link", "set", "eth0", "up"])
        run(["ip", "address", "add", DESTINATIONS[4] + "/30", "dev", "eth0"])
        run(client + ["ip", "address", "add", GATEWAYS[4] + "/30", "dev", "eth0"])
        run(["ip", "-6", "address", "add", DESTINATIONS[6] + "/64", "dev", "eth0", "nodad"])
        run(client + ["ip", "-6", "address", "add", GATEWAYS[6] + "/64", "dev", "eth0", "nodad"])
        for source in sources:
            version = ipaddress.ip_address(source).version
            family = ["-6"] if version == 6 else ["-4"]
            suffix = "/128" if version == 6 else "/32"
            arguments = ["ip"] + family + ["address", "add", source + suffix, "dev", "lo"]
            if version == 6:
                arguments.append("nodad")
            run(client + arguments)
            run(["ip"] + family + ["route", "add", source + suffix,
                                    "via", GATEWAYS[version], "dev", "eth0"])
        # sysctl writes here are network-namespace-local; no host state changes.
        for prefix in ([], client):
            run(prefix + ["sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0",
                          "net.ipv4.conf.eth0.rp_filter=0"])
        run(["nft", "--file", "-"], input_text=policy)
        for family in (socket.AF_INET, socket.AF_INET6):
            for port in (*SSH_PORTS, CONTROL_PORT):
                listener = socket.socket(family, socket.SOCK_STREAM)
                listeners.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
                listener.listen(128)
        # The first IPv6 neighbour discovery may overlap link-local DAD. Wait
        # for an unrelated-port handshake before short policy drop timeouts.
        readiness = [{"source": GATEWAYS[version], "destination": DESTINATIONS[version],
                      "port": CONTROL_PORT, "timeout": 4} for version in (4, 6)]
        ready_results = json.loads(run(client + [sys.executable, "-c", PROBE],
                                       input_text=json.dumps(readiness)))
        if any(result["result"] != "allowed" for result in ready_results):
            raise RuntimeError("isolated TCP topology did not become ready: "
                               + json.dumps(ready_results))
        results = json.loads(run(client + [sys.executable, "-c", PROBE],
                                 input_text=json.dumps(cases)))
        loopback_cases = [{"name": "loopback", "source": source,
                           "destination": source, "port": port, "expected": "allowed"}
                          for source in ("127.0.0.1", "::1") for port in SSH_PORTS]
        results.extend(json.loads(run([sys.executable, "-c", PROBE],
                                      input_text=json.dumps(loopback_cases))))
        failed = []
        for result in results:
            passed = result["result"] == result["expected"]
            print(f"{'PASS' if passed else 'FAIL'} {result['name']}: "
                  f"{result['source']} -> TCP {result['port']}: {result['result']}")
            if not passed:
                failed.append(result)
        print(f"Isolated real TCP checks: {len(results) - len(failed)}/{len(results)} passed")
        if failed:
            print("Expected decisions for failures: " + json.dumps(failed), file=sys.stderr)
            return 1
        return 0
    finally:
        for listener in listeners:
            listener.close()
        if holder is not None:
            if holder.stdin is not None:
                holder.stdin.close()
            try:
                holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                holder.terminate()
                holder.wait(timeout=5)
        # Unnamed namespaces and their veth pair disappear when their owning
        # processes exit. There are no host namespace names or files to delete.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--isolated-from", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("root is required for disposable network namespaces")
        for command in ("unshare", "nsenter", "ip", "nft", "sysctl"):
            if not shutil.which(command):
                raise RuntimeError(f"required command not installed: {command}")
        if args.isolated_from is not None:
            return isolated_main(args.policy, args.isolated_from)
        # The outer process is intentionally read-only toward network state.
        result = subprocess.run(["unshare", "--net", "--", sys.executable,
                                 str(Path(__file__).resolve()), "--policy",
                                 str(args.policy.resolve(strict=True)), "--isolated-from",
                                 os.readlink("/proc/self/ns/net")], check=False)
        return result.returncode
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"SSH network verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
