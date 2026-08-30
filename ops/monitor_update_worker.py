#!/usr/bin/python3
"""Root worker for the narrowly allow-listed Monitor host update queue.

Only two operations exist: refresh/simulate a safe APT upgrade, and apply the
same still-current plan.  Request data can never select a command, package,
path, option, repository, environment variable, or firmware image.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import monitor_update_gateway as protocol


MAX_QUEUE_RECORD_BYTES = protocol.MAX_REQUEST_BYTES
MAX_PLAN_PACKAGES = 2048
MAX_PUBLIC_PACKAGES = 512
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_AUDIT_BYTES = 4096
MAX_EXACT_ARGV_BYTES = 256 * 1024
MAX_EXPECTED_TRANSACTION_BYTES = 4 * 1024 * 1024
MAX_HOOK_INPUT_BYTES = 4 * 1024 * 1024
REQUEST_MAX_AGE = timedelta(minutes=10)
PLAN_MAX_AGE = timedelta(minutes=15)
PRECOMMIT_TIMEOUT_SECONDS = 90 * 60
PRECOMMIT_INTERRUPT_GRACE_SECONDS = 5 * 60
PRECOMMIT_TERMINATE_GRACE_SECONDS = 60
EXPECTED_TRANSACTION_MAX_AGE = timedelta(minutes=95)
CHECK_MIN_ROOT_FREE_BYTES = 256 * 1024 * 1024
APPLY_MIN_ROOT_FREE_BYTES = 2 * 1024 * 1024 * 1024
APPLY_MIN_BOOT_FREE_BYTES = 128 * 1024 * 1024

PUBLIC_STATES = frozenset({
    "idle", "checking", "available", "up-to-date", "applying",
    "succeeded", "failed", "interrupted",
})
PUBLIC_CODES = frozenset({
    "READY", "CHECKING", "UPDATES_AVAILABLE", "UP_TO_DATE", "UPDATES_KEPT_BACK", "APPLYING",
    "APPLY_SUCCEEDED", "REBOOT_REQUIRED", "PACKAGE_MANAGER_BUSY",
    "DPKG_AUDIT_FAILED", "PLAN_NOT_FOUND", "PLAN_STALE", "PLAN_CHANGED",
    "ROOT_READ_ONLY", "DISK_SPACE_LOW", "PLAN_TOO_LARGE", "COMMAND_FAILED",
    "INTERRUPTED", "INTERNAL_ERROR",
})
PACKAGE_ACTIONS = frozenset({"upgrade", "install"})
PACKAGE_CATEGORIES = frozenset({
    "kernel", "firmware", "container-runtime", "network", "core-system", "other",
})
PUBLIC_PACKAGE_FIELDS = (
    "name", "installedVersion", "candidateVersion", "action", "category",
)
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$", re.ASCII)
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9.+:~_-]{1,256}$", re.ASCII)
ARCHITECTURE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$", re.ASCII)
APT_INSTALL_PATTERN = re.compile(
    r"^Inst (?P<name>\S+?)(?: \[(?P<installed>[^\]\r\n]{1,256})\])? "
    r"\((?P<candidate>\S{1,256})(?: [^\r\n()]*)? "
    r"\[(?P<architecture>[a-z0-9][a-z0-9-]{0,31})\]\)"
    r"(?: \[[^\]\r\n]{0,1024}\])*$",
    re.ASCII,
)
APT_SUMMARY_PATTERN = re.compile(
    r"^(?P<upgrade>\d+) upgraded, (?P<install>\d+) newly installed, "
    r"(?P<remove>\d+) to remove and (?P<kept>\d+) not upgraded\.$",
    re.MULTILINE | re.ASCII,
)
APT_LOCK_PATTERN = re.compile(
    r"could not get lock|unable to acquire.*lock|another process.*package manager|is another process using it",
    re.IGNORECASE,
)
ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", re.ASCII)

DPKG_AUDIT_COMMAND = ("/usr/bin/dpkg", "--audit")
DPKG_ARCHITECTURE_COMMAND = ("/usr/bin/dpkg", "--print-architecture")
APT_EXACT_CONFIG_PATH = "/usr/local/lib/monitor-updater/apt-exact.conf"
APPLY_TRANSACTION_PATH = Path("/var/lib/monitor-update/apply-transaction.json")
APPLY_PHASE_LOCK_PATH = Path("/var/lib/monitor-update/apply-phase.lock")
APPLY_PHASE_MARKER_PATH = Path("/var/lib/monitor-update/apply-validator-started")
APT_UPDATE_COMMAND = (
    "/usr/bin/apt-get", "-q", "-o", "DPkg::Lock::Timeout=300", "update",
)
APT_SIMULATE_COMMAND = (
    "/usr/bin/apt-get", "-s", "-o", "Debug::NoLocking=1",
    "--with-new-pkgs", "--no-remove", "upgrade",
)
APT_EXACT_SIMULATE_PREFIX = (
    "/usr/bin/apt-get", "-s", "-c", APT_EXACT_CONFIG_PATH,
    "-o", "Debug::NoLocking=1",
    "--mark-auto", "--no-remove", "install",
)
APT_APPLY_PREFIX = (
    "/usr/bin/systemd-inhibit",
    "--what=shutdown:sleep",
    "--who=Monitor host updater",
    "--why=Applying a confirmed safe host package plan",
    "--mode=block",
    "/usr/bin/apt-get",
    "-c", APT_EXACT_CONFIG_PATH,
    "-y",
    "-o", "DPkg::Lock::Timeout=0",
    "-o", "Dpkg::Options::=--force-confold",
    "--mark-auto",
    "--no-remove",
    "install",
)
SAFE_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "DEBIAN_FRONTEND": "noninteractive",
    "APT_LISTCHANGES_FRONTEND": "none",
    "HOME": "/root",
}


class WorkerError(Exception):
    def __init__(self, code: str):
        if code not in PUBLIC_CODES:
            raise ValueError("unknown worker status code")
        super().__init__(code)
        self.code = code


class InfrastructureError(RuntimeError):
    """Persistence, process-control, or local invariant failure.

    These errors must escape the queue worker. Treating them as an ordinary
    package result could unlink the only recovery token after APT had started.
    """


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str = ""
    timed_out: bool = False


class ApplyPhaseGuard:
    """Race-free boundary between a bounded pre-dpkg phase and dpkg commit."""

    MARKER_BYTES = b"validator-started\n"

    def __init__(
        self,
        *,
        lock_path: Path = APPLY_PHASE_LOCK_PATH,
        marker_path: Path = APPLY_PHASE_MARKER_PATH,
        expected_uid: int = 0,
    ) -> None:
        self.lock_path = lock_path
        self.marker_path = marker_path
        self.expected_uid = expected_uid

    @contextmanager
    def exclusive_descriptor(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise InfrastructureError("unsafe apply phase lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield descriptor
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _marker_metadata(self) -> os.stat_result | None:
        try:
            metadata = os.lstat(self.marker_path)
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(self.MARKER_BYTES)
        ):
            raise InfrastructureError("unsafe apply phase marker")
        return metadata

    def validator_started_locked(self) -> bool:
        metadata = self._marker_metadata()
        if metadata is None:
            return False
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.marker_path, flags)
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise InfrastructureError("apply phase marker changed during validation")
            return os.read(descriptor, len(self.MARKER_BYTES) + 1) == self.MARKER_BYTES
        finally:
            os.close(descriptor)

    def validator_started(self) -> bool:
        return self.validator_started_locked()

    def prepare(self) -> None:
        with self.exclusive_descriptor():
            metadata = self._marker_metadata()
            if metadata is not None:
                os.unlink(self.marker_path)
                fsync_directory(self.marker_path.parent)

    def mark_validator_started(self) -> None:
        with self.exclusive_descriptor():
            if self.validator_started_locked():
                return
            temporary = self.marker_path.parent / f".{self.marker_path.name}.{os.getpid()}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                written = 0
                while written < len(self.MARKER_BYTES):
                    written += os.write(descriptor, self.MARKER_BYTES[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, self.marker_path)
                fsync_directory(self.marker_path.parent)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise

    def clear(self) -> None:
        self.prepare()


class SubprocessRunner:
    """Fixed-argv runner with bounded capture for non-mutating/check commands."""

    def run_capture(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: int,
        maximum_bytes: int = MAX_CAPTURE_BYTES,
    ) -> CommandResult:
        process = subprocess.Popen(
            tuple(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=SAFE_ENVIRONMENT,
            close_fds=True,
            start_new_session=True,
        )
        assert process.stdout is not None
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()

        def stop_bounded_command() -> None:
            for action, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                if process.poll() is not None:
                    return
                try:
                    os.killpg(process.pid, action)
                except ProcessLookupError:
                    return
                try:
                    process.wait(timeout=grace)
                    return
                except subprocess.TimeoutExpired:
                    continue
            if process.poll() is None:
                raise InfrastructureError("bounded check process did not stop")

        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stop_bounded_command()
                    raise WorkerError("COMMAND_FAILED")
                events = selector.select(min(remaining, 1.0))
                if not events:
                    if process.poll() is not None:
                        chunk = os.read(descriptor, 65_536)
                        if chunk:
                            output.extend(chunk)
                        break
                    continue
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > maximum_bytes:
                    stop_bounded_command()
                    raise WorkerError("COMMAND_FAILED")
            returncode = process.wait(timeout=max(1, int(deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            stop_bounded_command()
            raise WorkerError("COMMAND_FAILED") from None
        finally:
            selector.close()
            process.stdout.close()
        return CommandResult(returncode, output.decode("utf-8", errors="replace"))

    def run_passthrough(
        self,
        arguments: Sequence[str],
        *,
        phase_guard: "ApplyPhaseGuard",
        timeout_seconds: int = PRECOMMIT_TIMEOUT_SECONDS,
        interrupt_grace_seconds: int = PRECOMMIT_INTERRUPT_GRACE_SECONDS,
        terminate_grace_seconds: int = PRECOMMIT_TERMINATE_GRACE_SECONDS,
    ) -> CommandResult:
        phase_guard.prepare()
        process = subprocess.Popen(
            tuple(arguments),
            stdin=subprocess.DEVNULL,
            env=SAFE_ENVIRONMENT,
            close_fds=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        while True:
            returncode = process.poll()
            if returncode is not None:
                return CommandResult(returncode)
            if phase_guard.validator_started():
                # The fixed validator is APT's first pre-dpkg hook. Once it
                # starts, APT can enter dpkg immediately after it returns.
                # There is deliberately no kill deadline from this point: a
                # forced stop can corrupt an otherwise recoverable package DB.
                return CommandResult(process.wait())
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    return CommandResult(process.wait(timeout=min(remaining, 1.0)))
                except subprocess.TimeoutExpired:
                    continue
            break

        # Serialize the timeout decision with the validator's first action.
        # Whichever obtains the phase lock first determines whether it is still
        # safe to stop before dpkg can be invoked.
        with phase_guard.exclusive_descriptor() as descriptor:
            if phase_guard.validator_started_locked():
                return CommandResult(process.wait())
            stages = (
                (signal.SIGINT, interrupt_grace_seconds),
                (signal.SIGTERM, terminate_grace_seconds),
                (signal.SIGKILL, 30),
            )
            for action, grace in stages:
                if process.poll() is not None:
                    break
                try:
                    os.killpg(process.pid, action)
                except ProcessLookupError:
                    break
                try:
                    process.wait(timeout=grace)
                    break
                except subprocess.TimeoutExpired:
                    continue
            try:
                returncode = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                raise InfrastructureError("pre-dpkg APT process did not stop") from None
            finally:
                # Keep the descriptor live, and therefore the validator
                # excluded, until the whole process group has exited.
                _ = descriptor
        return CommandResult(returncode, timed_out=True)


def iso_timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not ISO_PATTERN.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def package_category(name: str) -> str:
    base = name.split(":", 1)[0]
    if base == "rpi-eeprom" or base.startswith(("linux-firmware", "firmware-", "fwupd", "libfwupd")):
        return "firmware"
    if base.startswith(("linux-image", "linux-modules", "linux-headers", "linux-raspi", "initramfs-tools")) \
            or base in {"flash-kernel", "linux-base"}:
        return "kernel"
    if base.startswith(("docker", "containerd", "moby")) or base in {"runc", "buildah", "podman"}:
        return "container-runtime"
    if base.startswith(("netplan", "network-manager", "openssh", "nginx", "nftables", "iproute2", "dhcpcd", "wpasupplicant")) \
            or base in {"ufw", "iptables"}:
        return "network"
    if base.startswith(("systemd", "libc6", "apt", "dpkg", "apparmor", "cryptsetup", "lvm2")) \
            or base in {"base-files", "coreutils", "sudo", "needrestart"}:
        return "core-system"
    return "other"


def _summary(upgrade: int, install: int, remove: int, kept: int, package_count: int) -> dict[str, Any]:
    return {
        "upgradeCount": upgrade,
        "installCount": install,
        "removeCount": remove,
        "keptBackCount": kept,
        "packageCount": package_count,
        "packagesTruncated": package_count > MAX_PUBLIC_PACKAGES,
    }


def parse_apt_plan(output: str, generated_at: datetime) -> dict[str, Any]:
    if len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
        raise WorkerError("PLAN_TOO_LARGE")
    summary_match = APT_SUMMARY_PATTERN.search(output)
    if not summary_match:
        raise WorkerError("COMMAND_FAILED")
    counts = {key: int(summary_match.group(key)) for key in ("upgrade", "install", "remove", "kept")}
    packages: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in output.splitlines():
        if not line.startswith("Inst "):
            continue
        match = APT_INSTALL_PATTERN.fullmatch(line)
        if not match:
            raise WorkerError("COMMAND_FAILED")
        name = match.group("name")
        installed = match.group("installed")
        candidate = match.group("candidate")
        architecture = match.group("architecture")
        identity = (name, architecture)
        if (
            not PACKAGE_NAME_PATTERN.fullmatch(name)
            or installed is not None and not VERSION_PATTERN.fullmatch(installed)
            or not VERSION_PATTERN.fullmatch(candidate)
            or not ARCHITECTURE_PATTERN.fullmatch(architecture)
            or identity in seen
        ):
            raise WorkerError("COMMAND_FAILED")
        seen.add(identity)
        packages.append({
            "name": name,
            "architecture": architecture,
            "installedVersion": installed,
            "candidateVersion": candidate,
            "action": "upgrade" if installed is not None else "install",
            "category": package_category(name),
        })
    if len(packages) > MAX_PLAN_PACKAGES:
        raise WorkerError("PLAN_TOO_LARGE")
    if counts["remove"] != 0:
        raise WorkerError("COMMAND_FAILED")
    if len(packages) != counts["upgrade"] + counts["install"]:
        raise WorkerError("COMMAND_FAILED")
    packages.sort(key=lambda item: (item["name"], item["architecture"], item["action"]))
    summary = _summary(
        counts["upgrade"], counts["install"], counts["remove"], counts["kept"], len(packages),
    )
    canonical = {
        "schemaVersion": protocol.SCHEMA_VERSION,
        "summary": {key: summary[key] for key in (
            "upgradeCount", "installCount", "removeCount", "keptBackCount", "packageCount",
        )},
        "packages": packages,
    }
    plan_id = hashlib.sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()
    return {
        "schemaVersion": protocol.SCHEMA_VERSION,
        "generatedAt": iso_timestamp(generated_at),
        "expiresAt": iso_timestamp(generated_at + PLAN_MAX_AGE),
        "planId": plan_id,
        "summary": summary,
        "packages": packages,
    }


def exact_plan_targets(plan: Mapping[str, Any]) -> tuple[str, ...]:
    packages = plan.get("packages")
    if not isinstance(packages, list) or len(packages) > MAX_PLAN_PACKAGES:
        raise WorkerError("PLAN_TOO_LARGE")
    targets: list[str] = []
    seen: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "name", "architecture", "installedVersion", "candidateVersion", "action", "category",
        }:
            raise WorkerError("INTERNAL_ERROR")
        name = package["name"]
        architecture = package["architecture"]
        installed = package["installedVersion"]
        candidate = package["candidateVersion"]
        action = package["action"]
        category = package["category"]
        if (
            not isinstance(name, str)
            or len(name) > 128
            or not PACKAGE_NAME_PATTERN.fullmatch(name)
            or not isinstance(architecture, str)
            or not ARCHITECTURE_PATTERN.fullmatch(architecture)
            or installed is not None and (
                not isinstance(installed, str) or not VERSION_PATTERN.fullmatch(installed)
            )
            or not isinstance(candidate, str)
            or not VERSION_PATTERN.fullmatch(candidate)
            or action not in PACKAGE_ACTIONS
            or category not in PACKAGE_CATEGORIES
            or action == "upgrade" and installed is None
            or action == "install" and installed is not None
        ):
            raise WorkerError("INTERNAL_ERROR")
        base_name, separator, qualified_architecture = name.rpartition(":")
        if separator:
            if qualified_architecture != architecture:
                raise WorkerError("INTERNAL_ERROR")
        else:
            base_name = name
        identity = (base_name, architecture)
        if identity in seen:
            raise WorkerError("INTERNAL_ERROR")
        seen.add(identity)
        targets.append(f"{base_name}:{architecture}={candidate}")
    arguments = APT_APPLY_PREFIX + tuple(targets)
    if sum(len(argument.encode("utf-8")) + 1 for argument in arguments) > MAX_EXACT_ARGV_BYTES:
        raise WorkerError("PLAN_TOO_LARGE")
    return tuple(targets)


def transaction_rows(plan: Mapping[str, Any]) -> tuple[tuple[Any, ...], ...]:
    packages = plan.get("packages")
    if not isinstance(packages, list):
        raise WorkerError("INTERNAL_ERROR")
    return tuple(sorted(
        (
            package.get("name"),
            package.get("architecture"),
            package.get("installedVersion"),
            package.get("candidateVersion"),
            package.get("action"),
        )
        for package in packages
        if isinstance(package, dict)
    ))


def require_exact_transaction(confirmed: Mapping[str, Any], simulated: Mapping[str, Any]) -> None:
    confirmed_summary = confirmed.get("summary")
    simulated_summary = simulated.get("summary")
    if not isinstance(confirmed_summary, dict) or not isinstance(simulated_summary, dict):
        raise WorkerError("PLAN_CHANGED")
    # Explicit install reports a different "not upgraded" count from broad
    # upgrade. It is intentionally excluded; every mutating package, version,
    # action, and removal count remains bound exactly.
    for key in ("upgradeCount", "installCount", "removeCount", "packageCount"):
        if confirmed_summary.get(key) != simulated_summary.get(key):
            raise WorkerError("PLAN_CHANGED")
    if confirmed_summary.get("removeCount") != 0 or transaction_rows(confirmed) != transaction_rows(simulated):
        raise WorkerError("PLAN_CHANGED")


def apt_state_fingerprint(
    status_path: Path = Path("/var/lib/dpkg/status"),
    extended_states_path: Path = Path("/var/lib/apt/extended_states"),
    lists_path: Path = Path("/var/lib/apt/lists"),
) -> str:
    """Detect package/list state changes between exact simulation and exec.

    Exact versions already prevent candidate drift. This additional snapshot
    closes the ordinary external-APT race to a tiny stat-to-exec window and
    makes a completed concurrent dpkg/list transaction fail closed.
    """

    digest = hashlib.sha256()
    for path, maximum in ((status_path, 32 * 1024 * 1024), (extended_states_path, 8 * 1024 * 1024)):
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            digest.update(f"missing:{path}\n".encode("utf-8"))
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
            raise WorkerError("INTERNAL_ERROR")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise WorkerError("PLAN_CHANGED")
            digest.update(str(path).encode("utf-8"))
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
    try:
        entries = sorted(os.scandir(lists_path), key=lambda entry: entry.name)
    except OSError:
        raise WorkerError("INTERNAL_ERROR") from None
    if len(entries) > 4096:
        raise WorkerError("PLAN_TOO_LARGE")
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        kind = "f" if stat.S_ISREG(metadata.st_mode) else "d" if stat.S_ISDIR(metadata.st_mode) else "x"
        digest.update(
            f"{entry.name}\0{kind}\0{metadata.st_dev}\0{metadata.st_ino}\0{metadata.st_size}\0{metadata.st_mtime_ns}\n".encode("utf-8")
        )
    return digest.hexdigest()


def _transaction_digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def build_expected_transaction(
    plan: Mapping[str, Any], native_architecture: str, created_at: datetime,
) -> dict[str, Any]:
    exact_plan_targets(plan)
    plan_id = plan.get("planId")
    if not isinstance(plan_id, str) or not protocol.PLAN_ID_PATTERN.fullmatch(plan_id):
        raise WorkerError("INTERNAL_ERROR")
    if not ARCHITECTURE_PATTERN.fullmatch(native_architecture):
        raise WorkerError("INTERNAL_ERROR")
    packages = [{
        "name": package["name"],
        "architecture": package["architecture"],
        "installedVersion": package["installedVersion"],
        "candidateVersion": package["candidateVersion"],
        "action": package["action"],
    } for package in plan["packages"]]
    packages.sort(key=lambda package: (package["name"], package["architecture"]))
    body = {
        "schemaVersion": protocol.SCHEMA_VERSION,
        "planId": plan_id,
        "createdAt": iso_timestamp(created_at),
        "expiresAt": iso_timestamp(created_at + EXPECTED_TRANSACTION_MAX_AGE),
        "nativeArchitecture": native_architecture,
        "packages": packages,
    }
    return {**body, "transactionDigest": _transaction_digest(body)}


def validate_expected_transaction(value: Any, at: datetime) -> dict[str, Any]:
    required = {
        "schemaVersion", "planId", "createdAt", "expiresAt",
        "nativeArchitecture", "packages", "transactionDigest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise InfrastructureError("invalid expected transaction schema")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != protocol.SCHEMA_VERSION:
        raise InfrastructureError("invalid expected transaction version")
    if not isinstance(value["planId"], str) or not protocol.PLAN_ID_PATTERN.fullmatch(value["planId"]):
        raise InfrastructureError("invalid expected transaction plan")
    created_at = parse_timestamp(value["createdAt"])
    expires_at = parse_timestamp(value["expiresAt"])
    if (
        created_at is None
        or expires_at is None
        or expires_at < created_at
        or expires_at - created_at > EXPECTED_TRANSACTION_MAX_AGE
        or created_at - at > timedelta(minutes=1)
        or at > expires_at
    ):
        raise InfrastructureError("stale expected transaction")
    native_architecture = value["nativeArchitecture"]
    if not isinstance(native_architecture, str) or not ARCHITECTURE_PATTERN.fullmatch(native_architecture):
        raise InfrastructureError("invalid expected transaction architecture")
    packages = value["packages"]
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PLAN_PACKAGES:
        raise InfrastructureError("invalid expected transaction package count")
    seen: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "name", "architecture", "installedVersion", "candidateVersion", "action",
        }:
            raise InfrastructureError("invalid expected transaction package schema")
        name = package["name"]
        architecture = package["architecture"]
        installed = package["installedVersion"]
        candidate = package["candidateVersion"]
        action = package["action"]
        if (
            not isinstance(name, str)
            or len(name) > 128
            or not PACKAGE_NAME_PATTERN.fullmatch(name)
            or not isinstance(architecture, str)
            or not ARCHITECTURE_PATTERN.fullmatch(architecture)
            or installed is not None and (
                not isinstance(installed, str) or not VERSION_PATTERN.fullmatch(installed)
            )
            or not isinstance(candidate, str)
            or not VERSION_PATTERN.fullmatch(candidate)
            or action not in PACKAGE_ACTIONS
            or action == "upgrade" and installed is None
            or action == "install" and installed is not None
        ):
            raise InfrastructureError("invalid expected transaction package")
        base_name, separator, qualified_architecture = name.rpartition(":")
        if separator:
            if qualified_architecture != architecture:
                raise InfrastructureError("expected transaction architecture mismatch")
        else:
            base_name = name
        identity = (base_name, architecture)
        if identity in seen:
            raise InfrastructureError("duplicate expected transaction package")
        seen.add(identity)
    if packages != sorted(packages, key=lambda package: (package["name"], package["architecture"])):
        raise InfrastructureError("unsorted expected transaction packages")
    digest = value["transactionDigest"]
    body = {key: value[key] for key in required if key != "transactionDigest"}
    if (
        not isinstance(digest, str)
        or not protocol.PLAN_ID_PATTERN.fullmatch(digest)
        or not hmac.compare_digest(digest, _transaction_digest(body))
    ):
        raise InfrastructureError("expected transaction digest mismatch")
    return value


def read_expected_transaction(
    path: Path, *, at: datetime, expected_uid: int = 0,
) -> dict[str, Any]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size < 2
        or metadata.st_size > MAX_EXPECTED_TRANSACTION_BYTES
    ):
        raise InfrastructureError("unsafe expected transaction file")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise InfrastructureError("expected transaction changed while opening")
        encoded = bytearray()
        while len(encoded) <= MAX_EXPECTED_TRANSACTION_BYTES:
            chunk = os.read(descriptor, min(65_536, MAX_EXPECTED_TRANSACTION_BYTES + 1 - len(encoded)))
            if not chunk:
                break
            encoded.extend(chunk)
    finally:
        os.close(descriptor)
    if (
        len(encoded) > MAX_EXPECTED_TRANSACTION_BYTES
        or not encoded.endswith(b"\n")
        or b"\n" in encoded[:-1]
    ):
        raise InfrastructureError("invalid expected transaction encoding")
    try:
        value = json.loads(encoded[:-1].decode("ascii"), object_pairs_hook=protocol._unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise InfrastructureError("invalid expected transaction JSON") from None
    return validate_expected_transaction(value, at)


def _hook_package_identity(
    package_name: str,
    architecture: str,
    expected: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[str, str]:
    identity = (package_name, architecture)
    if identity not in expected:
        raise InfrastructureError("APT hook package identity mismatch")
    return identity


def validate_apt_hook_payload(payload: bytes, expected_value: Mapping[str, Any]) -> None:
    if len(payload) > MAX_HOOK_INPUT_BYTES:
        raise InfrastructureError("APT hook input is too large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise InfrastructureError("APT hook input is not UTF-8") from None
    lines = text.splitlines()
    if not lines or lines[0] != "VERSION 3" or any(len(line) > 8192 for line in lines):
        raise InfrastructureError("APT hook protocol mismatch")
    try:
        action_start = lines.index("", 1) + 1
    except ValueError:
        raise InfrastructureError("APT hook configuration delimiter missing") from None
    action_lines = lines[action_start:]
    if (
        not action_lines
        or len(action_lines) != len(expected_value["packages"]) * 2
        or any(not line for line in action_lines)
    ):
        raise InfrastructureError("APT hook action list missing")

    expected: dict[tuple[str, str], Mapping[str, Any]] = {}
    for package in expected_value["packages"]:
        base_name, separator, _qualified_architecture = package["name"].rpartition(":")
        if not separator:
            base_name = package["name"]
        expected[(base_name, package["architecture"])] = package
    unpacked: dict[tuple[str, str], tuple[str, ...]] = {}
    configured: dict[tuple[str, str], tuple[str, ...]] = {}
    multiarch_values = {"same", "foreign", "allowed", "none", "no"}
    base_name_pattern = re.compile(r"^[a-z0-9][a-z0-9+.-]*$", re.ASCII)

    for line in action_lines:
        fields = line.split(maxsplit=8)
        if len(fields) != 9:
            raise InfrastructureError("APT hook action field mismatch")
        (
            package_name, old_version, old_architecture, old_multiarch,
            direction, new_version, new_architecture, new_multiarch, action,
        ) = fields
        if (
            not base_name_pattern.fullmatch(package_name)
            or direction not in {"<", "=", ">"}
            or old_multiarch not in multiarch_values
            or new_multiarch not in multiarch_values
            or old_version != "-" and not VERSION_PATTERN.fullmatch(old_version)
            or new_version != "-" and not VERSION_PATTERN.fullmatch(new_version)
            or old_architecture != "-" and not ARCHITECTURE_PATTERN.fullmatch(old_architecture)
            or new_architecture != "-" and not ARCHITECTURE_PATTERN.fullmatch(new_architecture)
            or old_version == "-" and old_architecture != "-"
            or new_version == "-" and new_architecture != "-"
        ):
            raise InfrastructureError("APT hook action value mismatch")
        if action in {"**REMOVE**", "**ERROR**"} or direction == ">":
            raise InfrastructureError("APT hook contains a forbidden action")
        if new_version == "-" or new_architecture == "-":
            raise InfrastructureError("APT hook action has no candidate")
        identity = _hook_package_identity(package_name, new_architecture, expected)
        package = expected[identity]
        transaction_tuple = tuple(fields[:8])
        if new_version != package["candidateVersion"] or new_architecture != package["architecture"]:
            raise InfrastructureError("APT hook candidate version mismatch")

        if action == "**CONFIGURE**":
            if identity in configured:
                raise InfrastructureError("APT hook configure action mismatch")
            configured[identity] = transaction_tuple
            continue
        if action.startswith("**") or not os.path.isabs(action) or len(action) > 4096 or not action.endswith(".deb"):
            raise InfrastructureError("APT hook unpack action mismatch")
        expected_old = package["installedVersion"] or "-"
        if (
            identity in unpacked
            or direction != "<"
            or old_version != expected_old
            or package["installedVersion"] is None and old_architecture != "-"
            or package["installedVersion"] is not None and old_architecture != new_architecture
        ):
            raise InfrastructureError("APT hook installed version mismatch")
        unpacked[identity] = transaction_tuple

    expected_names = set(expected)
    if set(unpacked) != expected_names or set(configured) != expected_names:
        raise InfrastructureError("APT hook transaction set mismatch")
    if any(configured[name] != unpacked[name] for name in expected_names):
        raise InfrastructureError("APT hook configure tuple mismatch")


def run_apt_transaction_hook(
    *,
    input_stream: Any,
    environment: Mapping[str, str],
    expected_path: Path = APPLY_TRANSACTION_PATH,
    phase_guard: ApplyPhaseGuard | None = None,
    at: datetime | None = None,
    expected_uid: int = 0,
) -> None:
    if environment.get("APT_HOOK_INFO_FD") != "0" or environment.get("DPKG_FRONTEND_LOCKED") != "true":
        raise InfrastructureError("APT hook environment mismatch")
    guard = phase_guard or ApplyPhaseGuard(expected_uid=expected_uid)
    # This is the first fixed pre-dpkg hook. Mark entry before parsing so the
    # supervising worker will never signal a process which can immediately
    # transition into dpkg after the validator returns.
    guard.mark_validator_started()
    expected_value = read_expected_transaction(
        expected_path, at=at or datetime.now(UTC), expected_uid=expected_uid,
    )
    payload = input_stream.read(MAX_HOOK_INPUT_BYTES + 1)
    if not isinstance(payload, bytes):
        raise InfrastructureError("APT hook input stream must be binary")
    validate_apt_hook_payload(payload, expected_value)


def public_status(
    *,
    now: datetime,
    state: str,
    code: str,
    request_id: str | None = None,
    action: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    checked_at: str | None = None,
    plan: Mapping[str, Any] | None = None,
    reboot_required: bool = False,
) -> dict[str, Any]:
    if state not in PUBLIC_STATES or code not in PUBLIC_CODES:
        raise ValueError("invalid public update status")
    packages = [
        {key: package[key] for key in PUBLIC_PACKAGE_FIELDS}
        for package in list(plan.get("packages", []))[:MAX_PUBLIC_PACKAGES]
    ] if plan else []
    summary = dict(plan["summary"]) if plan else None
    return {
        "schemaVersion": protocol.SCHEMA_VERSION,
        "generatedAt": iso_timestamp(now),
        "state": state,
        "requestId": request_id,
        "action": action,
        "startedAt": started_at,
        "completedAt": completed_at,
        "checkedAt": checked_at,
        "planId": plan.get("planId") if plan else None,
        "planExpiresAt": plan.get("expiresAt") if plan else None,
        "summary": summary,
        "packages": packages,
        "rebootRequired": bool(reboot_required),
        "code": code,
    }


def validate_public_status(value: Any) -> dict[str, Any] | None:
    required = {
        "schemaVersion", "generatedAt", "state", "requestId", "action", "startedAt",
        "completedAt", "checkedAt", "planId", "planExpiresAt", "summary", "packages",
        "rebootRequired", "code",
    }
    if not isinstance(value, dict) or set(value) != required:
        return None
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != protocol.SCHEMA_VERSION:
        return None
    if parse_timestamp(value["generatedAt"]) is None:
        return None
    if value["state"] not in PUBLIC_STATES or value["code"] not in PUBLIC_CODES:
        return None
    if value["requestId"] is not None and not (
        isinstance(value["requestId"], str) and protocol.REQUEST_ID_PATTERN.fullmatch(value["requestId"])
    ):
        return None
    if value["action"] is not None and value["action"] not in protocol.ALLOWED_ACTIONS:
        return None
    for key in ("startedAt", "completedAt", "checkedAt", "planExpiresAt"):
        if value[key] is not None and parse_timestamp(value[key]) is None:
            return None
    if value["planId"] is not None and not (
        isinstance(value["planId"], str) and protocol.PLAN_ID_PATTERN.fullmatch(value["planId"])
    ):
        return None
    if type(value["rebootRequired"]) is not bool or not isinstance(value["packages"], list):
        return None
    return value


class StateStore:
    def __init__(
        self,
        *,
        public_path: Path,
        private_plan_path: Path,
        audit_path: Path,
        apply_transaction_path: Path = APPLY_TRANSACTION_PATH,
        public_gid: int | None = None,
        expected_uid: int | None = None,
    ) -> None:
        self.public_path = public_path
        self.private_plan_path = private_plan_path
        self.audit_path = audit_path
        self.apply_transaction_path = apply_transaction_path
        self.public_gid = public_gid
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def _atomic_write(self, path: Path, payload: Mapping[str, Any], mode: int, gid: int | None) -> None:
        parent_metadata = os.lstat(path.parent)
        if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != self.expected_uid:
            raise InfrastructureError("unsafe state directory")
        if path.exists() or path.is_symlink():
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise InfrastructureError("unsafe state file")
        encoded = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, mode)
        try:
            try:
                if gid is not None:
                    os.fchown(descriptor, self.expected_uid, gid)
                os.fchmod(descriptor, mode)
                written = 0
                while written < len(encoded):
                    written += os.write(descriptor, encoded[written:])
                os.fsync(descriptor)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def write_public(self, status_value: Mapping[str, Any]) -> None:
        if validate_public_status(dict(status_value)) is None:
            raise InfrastructureError("invalid public status")
        self._atomic_write(self.public_path, status_value, 0o640, self.public_gid)

    def read_public(self) -> dict[str, Any] | None:
        try:
            metadata = os.lstat(self.public_path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or self.public_gid is not None and metadata.st_gid != self.public_gid
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or metadata.st_nlink != 1
                or metadata.st_size > 1024 * 1024
            ):
                return None
            value = json.loads(self.public_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return validate_public_status(value)

    def write_plan(self, plan: Mapping[str, Any]) -> None:
        self._atomic_write(self.private_plan_path, plan, 0o600, None)

    def read_plan(self) -> dict[str, Any] | None:
        try:
            metadata = os.lstat(self.private_plan_path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_CAPTURE_BYTES
            ):
                return None
            value = json.loads(self.private_plan_path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict) or not protocol.PLAN_ID_PATTERN.fullmatch(str(value.get("planId", ""))):
            return None
        if parse_timestamp(value.get("generatedAt")) is None or parse_timestamp(value.get("expiresAt")) is None:
            return None
        if not isinstance(value.get("packages"), list) or not isinstance(value.get("summary"), dict):
            return None
        return value

    def clear_plan(self) -> None:
        try:
            metadata = os.lstat(self.private_plan_path)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_uid or metadata.st_nlink != 1:
            raise InfrastructureError("unsafe private plan")
        os.unlink(self.private_plan_path)
        directory_descriptor = os.open(
            self.private_plan_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def write_expected_transaction(self, expected_value: Mapping[str, Any]) -> None:
        created_at = parse_timestamp(expected_value.get("createdAt"))
        if created_at is None:
            raise InfrastructureError("invalid expected transaction creation time")
        validate_expected_transaction(dict(expected_value), created_at)
        self._atomic_write(self.apply_transaction_path, expected_value, 0o600, None)

    def clear_expected_transaction(self) -> None:
        try:
            metadata = os.lstat(self.apply_transaction_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise InfrastructureError("unsafe expected transaction file")
        os.unlink(self.apply_transaction_path)
        fsync_directory(self.apply_transaction_path.parent)

    def audit(
        self,
        *,
        now: datetime,
        request: Mapping[str, Any],
        result: str,
        code: str,
        plan_id: str | None,
        package_count: int,
        reboot_required: bool,
    ) -> None:
        if result not in {"started", "succeeded", "failed", "interrupted", "rejected"}:
            raise ValueError("invalid audit result")
        record = {
            "timestamp": iso_timestamp(now),
            "requestId": request["requestId"],
            "actor": request["actor"],
            "peerUid": request["peerUid"],
            "action": request["action"],
            "result": result,
            "code": code,
            "planId": plan_id,
            "packageCount": package_count,
            "rebootRequired": bool(reboot_required),
        }
        encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if len(encoded) > MAX_AUDIT_BYTES:
            raise WorkerError("INTERNAL_ERROR")
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.audit_path, flags, 0o640)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or metadata.st_nlink != 1
            ):
                raise InfrastructureError("unsafe audit log")
            os.fchmod(descriptor, 0o640)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            metadata = os.fstat(descriptor)
            semantic = {key: record[key] for key in (
                "requestId", "actor", "peerUid", "action", "result", "code",
                "planId", "packageCount", "rebootRequired",
            )}
            tail_bytes = min(metadata.st_size, 1024 * 1024)
            os.lseek(descriptor, metadata.st_size - tail_bytes, os.SEEK_SET)
            tail = bytearray()
            while len(tail) < tail_bytes:
                chunk = os.read(descriptor, tail_bytes - len(tail))
                if not chunk:
                    break
                tail.extend(chunk)
            if metadata.st_size > tail_bytes:
                separator = tail.find(b"\n")
                tail = tail[separator + 1:] if separator >= 0 else bytearray()
            for line in tail.splitlines():
                if not line:
                    continue
                try:
                    prior = json.loads(line.decode("ascii"), object_pairs_hook=protocol._unique_object)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    raise InfrastructureError("malformed audit log tail") from None
                if isinstance(prior, dict) and all(prior.get(key) == value for key, value in semantic.items()):
                    return
            written = 0
            while written < len(encoded):
                written += os.write(descriptor, encoded[written:])
            os.fsync(descriptor)
            # O_CREAT can add the audit inode to the directory. Durability of
            # the file alone is insufficient before the queue token is
            # durably unlinked.
            fsync_directory(self.audit_path.parent)
        finally:
            os.close(descriptor)


def validate_queue_request(value: Any, expected_peer_uid: int) -> dict[str, Any]:
    required = {
        "schemaVersion", "requestId", "action", "actor", "planId", "peerUid", "requestedAt",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise WorkerError("INTERNAL_ERROR")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != protocol.SCHEMA_VERSION:
        raise WorkerError("INTERNAL_ERROR")
    if not isinstance(value["requestId"], str) or not protocol.REQUEST_ID_PATTERN.fullmatch(value["requestId"]):
        raise WorkerError("INTERNAL_ERROR")
    if value["action"] not in protocol.ALLOWED_ACTIONS:
        raise WorkerError("INTERNAL_ERROR")
    if not isinstance(value["actor"], str) or not protocol.ACTOR_PATTERN.fullmatch(value["actor"]):
        raise WorkerError("INTERNAL_ERROR")
    if type(value["peerUid"]) is not int or value["peerUid"] != expected_peer_uid:
        raise WorkerError("INTERNAL_ERROR")
    if parse_timestamp(value["requestedAt"]) is None:
        raise WorkerError("INTERNAL_ERROR")
    if value["action"] == "check":
        if value["planId"] is not None:
            raise WorkerError("INTERNAL_ERROR")
    elif not isinstance(value["planId"], str) or not protocol.PLAN_ID_PATTERN.fullmatch(value["planId"]):
        raise WorkerError("INTERNAL_ERROR")
    return value


def read_claimed_request(path: Path, expected_uid: int, expected_peer_uid: int) -> dict[str, Any]:
    metadata = os.lstat(path)
    if (
        not protocol.QUEUE_NAME_PATTERN.fullmatch(path.name)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size < 2
        or metadata.st_size > MAX_QUEUE_RECORD_BYTES
    ):
        raise WorkerError("INTERNAL_ERROR")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise WorkerError("INTERNAL_ERROR")
        encoded = os.read(descriptor, MAX_QUEUE_RECORD_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(encoded) > MAX_QUEUE_RECORD_BYTES or not encoded.endswith(b"\n") or b"\n" in encoded[:-1]:
        raise WorkerError("INTERNAL_ERROR")
    try:
        value = json.loads(encoded[:-1].decode("ascii"), object_pairs_hook=protocol._unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise WorkerError("INTERNAL_ERROR") from None
    return validate_queue_request(value, expected_peer_uid)


class Preflight:
    def __init__(self, root_path: Path = Path("/"), boot_path: Path = Path("/boot/firmware")) -> None:
        self.root_path = root_path
        self.boot_path = boot_path

    @staticmethod
    def _read_only(path: Path) -> bool:
        return bool(os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1))

    def verify_filesystems(self, *, applying: bool) -> None:
        if self._read_only(self.root_path) or self.boot_path.exists() and self._read_only(self.boot_path):
            raise WorkerError("ROOT_READ_ONLY")
        root_minimum = APPLY_MIN_ROOT_FREE_BYTES if applying else CHECK_MIN_ROOT_FREE_BYTES
        if shutil.disk_usage(self.root_path).free < root_minimum:
            raise WorkerError("DISK_SPACE_LOW")
        if applying and self.boot_path.exists() and shutil.disk_usage(self.boot_path).free < APPLY_MIN_BOOT_FREE_BYTES:
            raise WorkerError("DISK_SPACE_LOW")


class UpdateWorker:
    def __init__(
        self,
        *,
        runner: Any,
        store: StateStore,
        preflight: Preflight,
        now: Callable[[], datetime] | None = None,
        reboot_required_path: Path = Path("/var/run/reboot-required"),
        state_fingerprint: Callable[[], str] = apt_state_fingerprint,
        phase_guard: ApplyPhaseGuard | None = None,
    ) -> None:
        self.runner = runner
        self.store = store
        self.preflight = preflight
        self.now = now or (lambda: datetime.now(UTC))
        self.reboot_required_path = reboot_required_path
        self.state_fingerprint = state_fingerprint
        self.phase_guard = phase_guard or ApplyPhaseGuard()

    def _dpkg_audit(self) -> None:
        result = self.runner.run_capture(DPKG_AUDIT_COMMAND, timeout_seconds=60, maximum_bytes=64 * 1024)
        if result.returncode != 0 or result.output.strip():
            raise WorkerError("DPKG_AUDIT_FAILED")

    def _apt_update(self) -> None:
        result = self.runner.run_capture(APT_UPDATE_COMMAND, timeout_seconds=10 * 60)
        if result.returncode != 0:
            if APT_LOCK_PATTERN.search(result.output):
                raise WorkerError("PACKAGE_MANAGER_BUSY")
            raise WorkerError("COMMAND_FAILED")

    def _simulate(self, at: datetime) -> dict[str, Any]:
        result = self.runner.run_capture(APT_SIMULATE_COMMAND, timeout_seconds=5 * 60)
        if result.returncode != 0:
            if APT_LOCK_PATTERN.search(result.output):
                raise WorkerError("PACKAGE_MANAGER_BUSY")
            raise WorkerError("COMMAND_FAILED")
        return parse_apt_plan(result.output, at)

    def _simulate_exact(self, targets: Sequence[str], at: datetime) -> dict[str, Any]:
        arguments = APT_EXACT_SIMULATE_PREFIX + tuple(targets)
        if sum(len(argument.encode("utf-8")) + 1 for argument in arguments) > MAX_EXACT_ARGV_BYTES:
            raise WorkerError("PLAN_TOO_LARGE")
        result = self.runner.run_capture(arguments, timeout_seconds=5 * 60)
        if result.returncode != 0:
            if APT_LOCK_PATTERN.search(result.output):
                raise WorkerError("PACKAGE_MANAGER_BUSY")
            raise WorkerError("COMMAND_FAILED")
        return parse_apt_plan(result.output, at)

    def _native_architecture(self) -> str:
        result = self.runner.run_capture(
            DPKG_ARCHITECTURE_COMMAND, timeout_seconds=30, maximum_bytes=1024,
        )
        architecture = result.output.strip()
        if result.returncode != 0 or not ARCHITECTURE_PATTERN.fullmatch(architecture):
            raise WorkerError("COMMAND_FAILED")
        return architecture

    def _started_status(self, request: Mapping[str, Any], state: str, code: str, plan: Mapping[str, Any] | None) -> str:
        started_at = iso_timestamp(self.now())
        self.store.write_public(public_status(
            now=self.now(), state=state, code=code, request_id=request["requestId"],
            action=request["action"], started_at=started_at,
            checked_at=plan.get("generatedAt") if plan else None, plan=plan,
            reboot_required=self.reboot_required_path.exists(),
        ))
        self.store.audit(
            now=self.now(), request=request, result="started", code=code,
            plan_id=plan.get("planId") if plan else request.get("planId"),
            package_count=len(plan.get("packages", [])) if plan else 0,
            reboot_required=self.reboot_required_path.exists(),
        )
        return started_at

    def _failure(
        self,
        request: Mapping[str, Any],
        started_at: str,
        error: WorkerError,
        plan: Mapping[str, Any] | None,
    ) -> None:
        completed_at = iso_timestamp(self.now())
        self.store.write_public(public_status(
            now=self.now(), state="failed", code=error.code, request_id=request["requestId"],
            action=request["action"], started_at=started_at, completed_at=completed_at,
            checked_at=plan.get("generatedAt") if plan else None, plan=plan,
            reboot_required=self.reboot_required_path.exists(),
        ))
        self.store.audit(
            now=self.now(), request=request, result="failed", code=error.code,
            plan_id=plan.get("planId") if plan else request.get("planId"),
            package_count=len(plan.get("packages", [])) if plan else 0,
            reboot_required=self.reboot_required_path.exists(),
        )

    def check(self, request: Mapping[str, Any]) -> None:
        started_at = self._started_status(request, "checking", "CHECKING", None)
        plan: dict[str, Any] | None = None
        try:
            self.preflight.verify_filesystems(applying=False)
            self._dpkg_audit()
            self._apt_update()
            checked = self.now()
            plan = self._simulate(checked)
            completed_at = iso_timestamp(self.now())
            reboot_required = self.reboot_required_path.exists()
            if plan["summary"]["packageCount"] == 0:
                self.store.clear_plan()
                code = "UPDATES_KEPT_BACK" if plan["summary"]["keptBackCount"] else "UP_TO_DATE"
                public_plan = {
                    **plan,
                    "planId": None,
                    "expiresAt": None,
                }
                state = "up-to-date"
            else:
                exact_plan_targets(plan)
                self.store.write_plan(plan)
                state, code, public_plan = "available", "UPDATES_AVAILABLE", plan
            self.store.write_public(public_status(
                now=self.now(), state=state, code=code, request_id=request["requestId"],
                action=request["action"], started_at=started_at, completed_at=completed_at,
                checked_at=plan["generatedAt"], plan=public_plan, reboot_required=reboot_required,
            ))
            self.store.audit(
                now=self.now(), request=request, result="succeeded", code=code,
                plan_id=plan["planId"] if plan["summary"]["packageCount"] else None,
                package_count=plan["summary"]["packageCount"], reboot_required=reboot_required,
            )
        except WorkerError as error:
            self._failure(request, started_at, error, plan)

    def apply_safe(self, request: Mapping[str, Any]) -> None:
        stored_plan = self.store.read_plan()
        if stored_plan is None or stored_plan.get("planId") != request["planId"]:
            started_at = iso_timestamp(self.now())
            self._failure(request, started_at, WorkerError("PLAN_NOT_FOUND"), None)
            return
        expiry = parse_timestamp(stored_plan.get("expiresAt"))
        if expiry is None or self.now() > expiry:
            started_at = iso_timestamp(self.now())
            self._failure(request, started_at, WorkerError("PLAN_STALE"), stored_plan)
            return
        # Stale hook state is never reused across requests. If a previous APT
        # child were still alive, systemd would keep this oneshot unit active
        # and prevent a second worker invocation.
        self.store.clear_expected_transaction()
        self.phase_guard.clear()
        started_at = self._started_status(request, "applying", "APPLYING", stored_plan)
        current_plan: dict[str, Any] | None = stored_plan
        apply_invoked = False
        expected_written = False
        operation_error: WorkerError | None = None
        try:
            self.preflight.verify_filesystems(applying=True)
            self._dpkg_audit()
            self._apt_update()
            current_plan = self._simulate(self.now())
            if current_plan["planId"] != request["planId"]:
                if current_plan["summary"]["packageCount"]:
                    self.store.write_plan(current_plan)
                else:
                    self.store.clear_plan()
                raise WorkerError("PLAN_CHANGED")
            targets = exact_plan_targets(current_plan)
            fingerprint = self.state_fingerprint()
            exact_simulation = self._simulate_exact(targets, self.now())
            require_exact_transaction(current_plan, exact_simulation)
            if self.state_fingerprint() != fingerprint:
                raise WorkerError("PLAN_CHANGED")
            native_architecture = self._native_architecture()
            expected_value = build_expected_transaction(
                current_plan, native_architecture, self.now(),
            )
            self.store.write_expected_transaction(expected_value)
            expected_written = True
            # The confirmation token becomes single-use before Popen. A spawn
            # error is intentionally not retryable because process creation can
            # race with observing whether APT actually began.
            self.store.clear_plan()
            apply_invoked = True
            result = self.runner.run_passthrough(
                APT_APPLY_PREFIX + targets,
                phase_guard=self.phase_guard,
                timeout_seconds=PRECOMMIT_TIMEOUT_SECONDS,
                interrupt_grace_seconds=PRECOMMIT_INTERRUPT_GRACE_SECONDS,
                terminate_grace_seconds=PRECOMMIT_TERMINATE_GRACE_SECONDS,
            )
            audit_error: WorkerError | None = None
            try:
                self._dpkg_audit()
            except WorkerError as error:
                audit_error = error
            if audit_error is not None:
                raise audit_error
            if result.returncode != 0 or result.timed_out:
                raise WorkerError("COMMAND_FAILED")
        except WorkerError as error:
            operation_error = error
        finally:
            if expected_written:
                self.store.clear_expected_transaction()
            self.phase_guard.clear()

        if operation_error is not None:
            if apply_invoked:
                # Already cleared before Popen; retain this explicit invariant
                # if the implementation order is changed later.
                self.store.clear_plan()
            self._failure(request, started_at, operation_error, current_plan)
            return

        completed_at = iso_timestamp(self.now())
        reboot_required = self.reboot_required_path.exists()
        code = "REBOOT_REQUIRED" if reboot_required else "APPLY_SUCCEEDED"
        self.store.write_public(public_status(
            now=self.now(), state="succeeded", code=code, request_id=request["requestId"],
            action=request["action"], started_at=started_at, completed_at=completed_at,
            checked_at=current_plan["generatedAt"], plan=current_plan,
            reboot_required=reboot_required,
        ))
        self.store.audit(
            now=self.now(), request=request, result="succeeded", code=code,
            plan_id=current_plan["planId"],
            package_count=current_plan["summary"]["packageCount"],
            reboot_required=reboot_required,
        )

    def process(self, request: Mapping[str, Any]) -> None:
        requested_at = parse_timestamp(request["requestedAt"])
        if requested_at is None or self.now() - requested_at > REQUEST_MAX_AGE or requested_at - self.now() > timedelta(minutes=1):
            started_at = iso_timestamp(self.now())
            status = public_status(
                now=self.now(), state="interrupted", code="INTERRUPTED",
                request_id=request["requestId"], action=request["action"],
                started_at=started_at, completed_at=started_at,
                reboot_required=self.reboot_required_path.exists(),
            )
            self.store.write_public(status)
            self.store.audit(
                now=self.now(), request=request, result="interrupted", code="INTERRUPTED",
                plan_id=request.get("planId"), package_count=0,
                reboot_required=self.reboot_required_path.exists(),
            )
            return
        if request["action"] == "check":
            self.check(request)
        else:
            self.apply_safe(request)


def safe_directory(path: Path, uid: int, mode: int) -> None:
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != mode:
        raise WorkerError("INTERNAL_ERROR")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def claim_requests(incoming: Path, processing: Path) -> list[Path]:
    claimed = sorted(
        path for path in processing.iterdir()
        if protocol.QUEUE_NAME_PATTERN.fullmatch(path.name)
    )
    for source in sorted(incoming.iterdir()):
        if not protocol.QUEUE_NAME_PATTERN.fullmatch(source.name):
            continue
        destination = processing / source.name
        if destination.exists() or destination.is_symlink():
            continue
        try:
            os.rename(source, destination)
        except FileNotFoundError:
            continue
        fsync_directory(incoming)
        fsync_directory(processing)
        claimed.append(destination)
    return claimed


def initialize_status(store: StateStore, now: datetime) -> None:
    if store.read_public() is None:
        store.write_public(public_status(now=now, state="idle", code="READY"))


def _public_plan(previous: Mapping[str, Any]) -> dict[str, Any] | None:
    if previous.get("summary") is None:
        return None
    return {
        "planId": previous.get("planId"),
        "expiresAt": previous.get("planExpiresAt"),
        "summary": previous["summary"],
        "packages": previous.get("packages", []),
    }


def _audit_terminal_status(
    *, store: StateStore, worker: UpdateWorker, request: Mapping[str, Any], status_value: Mapping[str, Any],
) -> None:
    state = status_value.get("state")
    if state in {"available", "up-to-date", "succeeded"}:
        result = "succeeded"
    elif state == "failed":
        result = "failed"
    elif state == "interrupted":
        result = "interrupted"
    else:
        raise InfrastructureError("request has no terminal public status")
    summary = status_value.get("summary")
    package_count = summary.get("packageCount", 0) if isinstance(summary, dict) else 0
    plan_id = status_value.get("planId") or request.get("planId")
    store.audit(
        now=worker.now(), request=request, result=result, code=status_value["code"],
        plan_id=plan_id, package_count=package_count,
        reboot_required=bool(status_value.get("rebootRequired")),
    )


def _interrupt_recovered_request(
    *,
    store: StateStore,
    worker: UpdateWorker,
    request: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
) -> None:
    if request["action"] == "apply-safe":
        # An applying status means process creation or package mutation may
        # already have happened. Invalidate every one-shot capability before
        # publishing the conservative interrupted result.
        store.clear_plan()
        store.clear_expected_transaction()
        worker.phase_guard.clear()
    now = worker.now()
    prior_matches = previous is not None and previous.get("requestId") == request["requestId"]
    plan = _public_plan(previous) if prior_matches else None
    status_value = public_status(
        now=now, state="interrupted", code="INTERRUPTED",
        request_id=request["requestId"], action=request["action"],
        started_at=previous.get("startedAt") if prior_matches else iso_timestamp(now),
        completed_at=iso_timestamp(now),
        checked_at=previous.get("checkedAt") if prior_matches else None,
        plan=plan, reboot_required=worker.reboot_required_path.exists(),
    )
    store.write_public(status_value)
    _audit_terminal_status(store=store, worker=worker, request=request, status_value=status_value)


def _unlink_claimed_request(path: Path, processing: Path, expected_uid: int) -> None:
    metadata = os.lstat(path)
    if (
        not protocol.QUEUE_NAME_PATTERN.fullmatch(path.name)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise InfrastructureError("claimed request changed before unlink")
    os.unlink(path)
    fsync_directory(processing)


def process_queue(
    *,
    worker: UpdateWorker,
    store: StateStore,
    incoming: Path,
    processing: Path,
    expected_request_uid: int,
    expected_processing_uid: int,
    expected_peer_uid: int,
) -> None:
    safe_directory(incoming, expected_request_uid, 0o700)
    safe_directory(processing, expected_processing_uid, 0o700)
    initialize_status(store, worker.now())
    recovering_names = {
        path.name for path in processing.iterdir()
        if protocol.QUEUE_NAME_PATTERN.fullmatch(path.name)
    }
    # The gateway caps incoming at eight. A crash can leave those eight in the
    # root-only processing directory while another eight arrive. Process the
    # full claimed set so an empty incoming directory cannot strand work where
    # the path unit would no longer retrigger.
    for path in claim_requests(incoming, processing):
        request = read_claimed_request(path, expected_request_uid, expected_peer_uid)
        previous = store.read_public()
        if path.name in recovering_names:
            if previous and previous.get("requestId") == request["requestId"] and previous.get("state") not in {
                "checking", "applying",
            }:
                # A durable terminal state may have been committed just before
                # a crash. Re-append its semantic audit idempotently, never APT.
                _audit_terminal_status(
                    store=store, worker=worker, request=request, status_value=previous,
                )
            else:
                _interrupt_recovered_request(
                    store=store, worker=worker, request=request, previous=previous,
                )
        else:
            worker.process(request)
            terminal = store.read_public()
            if (
                terminal is None
                or terminal.get("requestId") != request["requestId"]
                or terminal.get("state") in {"idle", "checking", "applying"}
            ):
                raise InfrastructureError("request did not commit a terminal status")
        _unlink_claimed_request(path, processing, expected_request_uid)


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor fixed-policy host update worker")
    parser.add_argument("--incoming", type=Path, default=Path("/var/lib/monitor-update/incoming"))
    parser.add_argument("--processing", type=Path, default=Path("/var/lib/monitor-update/processing"))
    parser.add_argument("--plan", type=Path, default=Path("/var/lib/monitor-update/plan.json"))
    parser.add_argument("--public-status", type=Path, default=Path("/var/lib/monitor-export/system-update.json"))
    parser.add_argument("--audit-log", type=Path, default=Path("/var/log/monitor-update-audit.jsonl"))
    parser.add_argument("--lock", type=Path, default=Path("/run/monitor-update-worker.lock"))
    parser.add_argument("--request-user", default="monitor-updater")
    parser.add_argument("--peer-uid", type=int, default=1001)
    parser.add_argument("--public-group", default="cks")
    parser.add_argument("--initialize-only", action="store_true")
    parser.add_argument("--verify-apt-transaction", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    values = parse_arguments(arguments)
    if os.geteuid() != 0:
        raise PermissionError("monitor update worker must run as root")
    if values.verify_apt_transaction:
        run_apt_transaction_hook(
            input_stream=sys.stdin.buffer,
            environment=os.environ,
            expected_path=APPLY_TRANSACTION_PATH,
            phase_guard=ApplyPhaseGuard(),
            expected_uid=0,
        )
        return 0
    request_uid = pwd.getpwnam(values.request_user).pw_uid
    public_gid = grp.getgrnam(values.public_group).gr_gid
    store = StateStore(
        public_path=values.public_status,
        private_plan_path=values.plan,
        audit_path=values.audit_log,
        public_gid=public_gid,
        expected_uid=0,
    )
    initialize_status(store, datetime.now(UTC))
    if values.initialize_only:
        return 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(values.lock, flags, 0o600)
    try:
        lock_metadata = os.fstat(lock_descriptor)
        if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != 0 or lock_metadata.st_nlink != 1:
            raise WorkerError("INTERNAL_ERROR")
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        worker = UpdateWorker(runner=SubprocessRunner(), store=store, preflight=Preflight())
        process_queue(
            worker=worker, store=store, incoming=values.incoming, processing=values.processing,
            expected_request_uid=request_uid, expected_processing_uid=0,
            expected_peer_uid=values.peer_uid,
        )
    finally:
        os.close(lock_descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, PermissionError, WorkerError, InfrastructureError, OSError) as error:
        print(f"monitor update worker: {error}", file=sys.stderr)
        raise SystemExit(1) from None
