import io
import json
import os
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitor_update_gateway as gateway  # noqa: E402
import monitor_update_worker as worker_module  # noqa: E402


NOW = datetime(2026, 8, 27, 7, 30, tzinfo=UTC)
REQUEST_ID = "update-12345678-1234-4234-9234-123456789abc"
SIMULATION = """Reading package lists...
Building dependency tree...
Calculating upgrade...
The following NEW packages will be installed:
  libfwupd3
The following packages will be upgraded:
  apt docker-ce rpi-eeprom linux-image-raspi
4 upgraded, 1 newly installed, 0 to remove and 2 not upgraded.
Inst apt [2.7.14build2] (2.8.3 Ubuntu:24.04/noble-updates [arm64])
Inst docker-ce [5:28.2.2] (5:29.7.2 Docker CE:noble [arm64])
Inst libfwupd3 (2.0.20-1ubuntu2~24.04.2 Ubuntu:24.04/noble-updates [arm64])
Inst linux-image-raspi [6.8.0-1062.66] (6.8.0-1063.67 Ubuntu:24.04/noble-updates [arm64])
Inst rpi-eeprom [28.14-0ubuntu0.24.04.1] (28.15-0ubuntu0.24.04.1 Ubuntu:24.04/noble-updates [arm64])
"""
EXACT_SIMULATION = SIMULATION.replace("2 not upgraded", "37 not upgraded")
KEPT_BACK_SIMULATION = """Reading package lists...
Building dependency tree...
0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
"""


class FakeRunner:
    def __init__(self, captures=None, passthrough=None) -> None:
        self.captures = list(captures or [])
        self.passthrough = list(passthrough or [])
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def run_capture(self, arguments, **_kwargs):
        self.calls.append(("capture", tuple(arguments)))
        if not self.captures:
            raise AssertionError("unexpected capture command")
        return self.captures.pop(0)

    def run_passthrough(self, arguments, **_kwargs):
        self.calls.append(("passthrough", tuple(arguments)))
        if not self.passthrough:
            raise AssertionError("unexpected apply command")
        return self.passthrough.pop(0)


class NoopPreflight:
    def __init__(self) -> None:
        self.calls: list[bool] = []

    def verify_filesystems(self, *, applying: bool) -> None:
        self.calls.append(applying)


class WorkerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.public_dir = self.root / "export"
        self.private_dir = self.root / "private"
        self.public_dir.mkdir(mode=0o750)
        self.private_dir.mkdir(mode=0o700)
        self.runtime_dir = self.root / "run"
        self.runtime_dir.mkdir(mode=0o700)
        self.store = worker_module.StateStore(
            public_path=self.public_dir / "system-update.json",
            private_plan_path=self.private_dir / "plan.json",
            audit_path=self.root / "audit.jsonl",
            apply_transaction_path=self.private_dir / "apply-transaction.json",
            expected_uid=os.geteuid(),
        )
        self.preflight = NoopPreflight()
        self.reboot_required = self.root / "reboot-required"
        self.phase_guard = worker_module.ApplyPhaseGuard(
            lock_path=self.runtime_dir / "apply-phase.lock",
            marker_path=self.runtime_dir / "apply-validator-started",
            expected_uid=os.geteuid(),
        )

    @staticmethod
    def request(action: str, plan_id: str | None = None) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "requestId": REQUEST_ID,
            "action": action,
            "actor": "operator@example.com",
            "planId": plan_id,
            "peerUid": 1001,
            "requestedAt": worker_module.iso_timestamp(NOW),
        }

    def make_worker(self, runner: FakeRunner) -> worker_module.UpdateWorker:
        return worker_module.UpdateWorker(
            runner=runner,
            store=self.store,
            preflight=self.preflight,
            now=lambda: NOW,
            reboot_required_path=self.reboot_required,
            state_fingerprint=lambda: "stable-package-state",
            phase_guard=self.phase_guard,
        )


class PlanTests(unittest.TestCase):
    def test_plan_is_bounded_canonical_and_classified(self) -> None:
        first = worker_module.parse_apt_plan(SIMULATION, NOW)
        second = worker_module.parse_apt_plan(SIMULATION, NOW + timedelta(seconds=5))
        self.assertEqual(first["planId"], second["planId"])
        self.assertEqual(first["summary"], {
            "upgradeCount": 4,
            "installCount": 1,
            "removeCount": 0,
            "keptBackCount": 2,
            "packageCount": 5,
            "packagesTruncated": False,
        })
        categories = {item["name"]: item["category"] for item in first["packages"]}
        self.assertEqual(categories["apt"], "core-system")
        self.assertEqual(categories["docker-ce"], "container-runtime")
        self.assertEqual(categories["rpi-eeprom"], "firmware")
        self.assertEqual(categories["linux-image-raspi"], "kernel")
        self.assertEqual(next(item for item in first["packages"] if item["name"] == "apt")["architecture"], "arm64")
        self.assertIsNone(next(item for item in first["packages"] if item["name"] == "libfwupd3")["installedVersion"])

    def test_plan_accepts_apt_dependency_annotations_after_candidate(self) -> None:
        annotated = SIMULATION.replace(
            "Inst apt [2.7.14build2] (2.8.3 Ubuntu:24.04/noble-updates [arm64])",
            "Inst apt [2.7.14build2] (2.8.3 Ubuntu:24.04/noble-updates [arm64]) [apt-utils:arm64 ]",
        )
        self.assertEqual(worker_module.parse_apt_plan(annotated, NOW)["summary"]["packageCount"], 5)

    def test_plan_refuses_removals_malformed_versions_and_count_mismatch(self) -> None:
        cases = (
            SIMULATION.replace("0 to remove", "1 to remove"),
            SIMULATION.replace("2.8.3", "bad/version"),
            SIMULATION.replace("4 upgraded", "5 upgraded"),
        )
        for output in cases:
            with self.subTest(), self.assertRaises(worker_module.WorkerError):
                worker_module.parse_apt_plan(output, NOW)

    def test_exact_targets_are_pinned_and_exact_simulation_ignores_only_kept_back(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        exact = worker_module.parse_apt_plan(EXACT_SIMULATION, NOW)
        targets = worker_module.exact_plan_targets(plan)
        self.assertIn("apt:arm64=2.8.3", targets)
        self.assertIn("libfwupd3:arm64=2.0.20-1ubuntu2~24.04.2", targets)
        worker_module.require_exact_transaction(plan, exact)
        changed = worker_module.parse_apt_plan(SIMULATION.replace("2.8.3", "2.8.4"), NOW)
        with self.assertRaisesRegex(worker_module.WorkerError, "PLAN_CHANGED"):
            worker_module.require_exact_transaction(plan, changed)

    def test_architecture_is_part_of_plan_digest_targets_and_exact_match(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        changed_output = SIMULATION.replace(
            "(2.8.3 Ubuntu:24.04/noble-updates [arm64])",
            "(2.8.3 Ubuntu:24.04/noble-updates [all])",
        )
        changed = worker_module.parse_apt_plan(changed_output, NOW)
        self.assertNotEqual(plan["planId"], changed["planId"])
        with self.assertRaisesRegex(worker_module.WorkerError, "PLAN_CHANGED"):
            worker_module.require_exact_transaction(plan, changed)
        self.assertIn("apt:arm64=2.8.3", worker_module.exact_plan_targets(plan))


class AptHookTests(WorkerFixture):
    @staticmethod
    def hook_payload(expected: dict[str, object]) -> bytes:
        unpack_rows: list[str] = []
        configure_rows: list[str] = []
        for package in expected["packages"]:
            qualified_name = package["name"]
            if ":" in qualified_name:
                package_name, _qualified_architecture = qualified_name.rsplit(":", 1)
            else:
                package_name = qualified_name
            architecture = package["architecture"]
            old_version = package["installedVersion"] or "-"
            old_architecture = architecture if package["installedVersion"] else "-"
            new_version = package["candidateVersion"]
            archive = f"/var/cache/apt/archives/{package_name}_{new_version}_{architecture}.deb"
            prefix = (
                f"{package_name} {old_version} {old_architecture} none < "
                f"{new_version} {architecture} none"
            )
            unpack_rows.append(f"{prefix} {archive}")
            configure_rows.append(f"{prefix} **CONFIGURE**")
        return ("VERSION 3\nAPT::Architecture=arm64\n\n" + "\n".join(
            unpack_rows + configure_rows,
        ) + "\n").encode("utf-8")

    def test_v3_hook_accepts_only_the_root_confirmed_full_transaction(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        expected = worker_module.build_expected_transaction(plan, "arm64", NOW)
        self.store.write_expected_transaction(expected)
        payload = self.hook_payload(expected)

        worker_module.run_apt_transaction_hook(
            input_stream=io.BytesIO(payload),
            environment={"APT_HOOK_INFO_FD": "0", "DPKG_FRONTEND_LOCKED": "true"},
            expected_path=self.store.apply_transaction_path,
            phase_guard=self.phase_guard,
            at=NOW,
            expected_uid=os.geteuid(),
        )
        self.assertTrue(self.phase_guard.validator_started())

        for changed in (
            payload.replace(b"2.8.3", b"2.8.4", 1),
            payload.replace(b"2.8.3 arm64 none", b"2.8.3 all none", 1),
            payload.replace(b"/var/cache/apt/archives/apt_", b"**REMOVE** #", 1),
            payload + b"unknown 1 arm64 none < 2 arm64 none **CONFIGURE**\n",
        ):
            with self.subTest(), self.assertRaises(worker_module.InfrastructureError):
                worker_module.validate_apt_hook_payload(changed, expected)

        configure_mismatch = payload.decode("utf-8").splitlines()
        for index, line in enumerate(configure_mismatch):
            if line.startswith("apt ") and line.endswith(" **CONFIGURE**"):
                configure_mismatch[index] = line.replace("2.7.14build2", "2.7.14build1", 1)
                break
        with self.assertRaisesRegex(worker_module.InfrastructureError, "configure tuple"):
            worker_module.validate_apt_hook_payload(
                ("\n".join(configure_mismatch) + "\n").encode("utf-8"), expected,
            )

    def test_expected_transaction_rejects_tampered_digest_mode_and_stale_data(self) -> None:
        expected = worker_module.build_expected_transaction(
            worker_module.parse_apt_plan(SIMULATION, NOW), "arm64", NOW,
        )
        self.store.write_expected_transaction(expected)
        loaded = worker_module.read_expected_transaction(
            self.store.apply_transaction_path, at=NOW, expected_uid=os.geteuid(),
        )
        self.assertEqual(loaded["transactionDigest"], expected["transactionDigest"])

        tampered = {**expected, "transactionDigest": "0" * 64}
        self.store.apply_transaction_path.write_text(json.dumps(tampered) + "\n", encoding="ascii")
        self.store.apply_transaction_path.chmod(0o600)
        with self.assertRaisesRegex(worker_module.InfrastructureError, "digest"):
            worker_module.read_expected_transaction(
                self.store.apply_transaction_path, at=NOW, expected_uid=os.geteuid(),
            )

        self.store.write_expected_transaction(expected)
        self.store.apply_transaction_path.chmod(0o640)
        with self.assertRaisesRegex(worker_module.InfrastructureError, "unsafe"):
            worker_module.read_expected_transaction(
                self.store.apply_transaction_path, at=NOW, expected_uid=os.geteuid(),
            )

        self.store.apply_transaction_path.chmod(0o600)
        with self.assertRaisesRegex(worker_module.InfrastructureError, "stale"):
            worker_module.read_expected_transaction(
                self.store.apply_transaction_path,
                at=NOW + worker_module.EXPECTED_TRANSACTION_MAX_AGE + timedelta(seconds=1),
                expected_uid=os.geteuid(),
            )

    def test_hook_requires_locked_fixed_info_fd_environment(self) -> None:
        expected = worker_module.build_expected_transaction(
            worker_module.parse_apt_plan(SIMULATION, NOW), "arm64", NOW,
        )
        self.store.write_expected_transaction(expected)
        with self.assertRaisesRegex(worker_module.InfrastructureError, "environment"):
            worker_module.run_apt_transaction_hook(
                input_stream=io.BytesIO(self.hook_payload(expected)),
                environment={}, expected_path=self.store.apply_transaction_path,
                phase_guard=self.phase_guard, at=NOW, expected_uid=os.geteuid(),
            )


class ProcessRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.guard = worker_module.ApplyPhaseGuard(
            lock_path=root / "phase.lock", marker_path=root / "marker",
            expected_uid=os.geteuid(),
        )

    def test_validator_entry_disables_all_apply_kill_deadlines(self) -> None:
        guard = self.guard

        class Process:
            pid = 43210

            def __init__(self) -> None:
                self.waits = 0

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.waits += 1
                if timeout is not None:
                    guard.mark_validator_started()
                    raise worker_module.subprocess.TimeoutExpired("apt", timeout)
                return 0

        process = Process()
        with mock.patch.object(worker_module.subprocess, "Popen", return_value=process), \
                mock.patch.object(worker_module.os, "killpg") as killpg:
            result = worker_module.SubprocessRunner().run_passthrough(
                worker_module.APT_APPLY_PREFIX + ("apt=2.8.3",),
                phase_guard=guard, timeout_seconds=5,
            )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        killpg.assert_not_called()

    def test_precommit_timeout_can_stop_before_validator_starts(self) -> None:
        class Process:
            pid = 43211

            def __init__(self) -> None:
                self.returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if timeout == worker_module.PRECOMMIT_INTERRUPT_GRACE_SECONDS:
                    self.returncode = -2
                    return self.returncode
                if self.returncode is not None:
                    return self.returncode
                raise worker_module.subprocess.TimeoutExpired("apt", timeout)

        process = Process()
        with mock.patch.object(worker_module.subprocess, "Popen", return_value=process), \
                mock.patch.object(worker_module.os, "killpg") as killpg:
            result = worker_module.SubprocessRunner().run_passthrough(
                worker_module.APT_APPLY_PREFIX + ("apt=2.8.3",),
                phase_guard=self.guard, timeout_seconds=0,
            )
        self.assertTrue(result.timed_out)
        killpg.assert_called_once_with(process.pid, worker_module.signal.SIGINT)


class UpdateActionTests(WorkerFixture):
    def test_check_runs_only_fixed_commands_and_publishes_plan(self) -> None:
        runner = FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(0, "updated\n"),
            worker_module.CommandResult(0, SIMULATION),
        ])
        updater = self.make_worker(runner)
        updater.process(self.request("check"))

        self.assertEqual(runner.calls, [
            ("capture", worker_module.DPKG_AUDIT_COMMAND),
            ("capture", worker_module.APT_UPDATE_COMMAND),
            ("capture", worker_module.APT_SIMULATE_COMMAND),
        ])
        status = json.loads(self.store.public_path.read_text(encoding="ascii"))
        self.assertEqual(set(status), {
            "schemaVersion", "generatedAt", "state", "requestId", "action", "startedAt",
            "completedAt", "checkedAt", "planId", "planExpiresAt", "summary", "packages",
            "rebootRequired", "code",
        })
        self.assertEqual(status["state"], "available")
        self.assertEqual(status["code"], "UPDATES_AVAILABLE")
        self.assertEqual(status["summary"]["packageCount"], 5)
        self.assertNotIn("architecture", status["packages"][0])
        self.assertTrue(self.store.private_plan_path.exists())
        audit = [json.loads(line) for line in (self.root / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["result"] for row in audit], ["started", "succeeded"])
        self.assertNotIn("updated", json.dumps(audit))

    def test_apply_rechecks_matching_plan_then_uses_exact_inhibited_argv(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        self.store.write_plan(plan)
        runner = FakeRunner(
            captures=[
                worker_module.CommandResult(0, ""),
                worker_module.CommandResult(0, "updated\n"),
                worker_module.CommandResult(0, SIMULATION),
                worker_module.CommandResult(0, EXACT_SIMULATION),
                worker_module.CommandResult(0, "arm64\n"),
                worker_module.CommandResult(0, ""),
            ],
            passthrough=[worker_module.CommandResult(0)],
        )
        updater = self.make_worker(runner)
        updater.process(self.request("apply-safe", plan["planId"]))

        targets = worker_module.exact_plan_targets(plan)
        self.assertIn(("capture", worker_module.APT_EXACT_SIMULATE_PREFIX + targets), runner.calls)
        self.assertIn(("passthrough", worker_module.APT_APPLY_PREFIX + targets), runner.calls)
        self.assertNotIn("operator@example.com", " ".join(
            argument for _kind, command in runner.calls for argument in command
        ))
        status = json.loads(self.store.public_path.read_text(encoding="ascii"))
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(status["code"], "APPLY_SUCCEEDED")
        self.assertFalse(self.store.private_plan_path.exists())
        self.assertFalse(self.store.apply_transaction_path.exists())
        self.assertEqual(self.preflight.calls, [True])


class QueueRecoveryTests(WorkerFixture):
    def queue_directories(self) -> tuple[Path, Path]:
        incoming = self.root / "incoming"
        processing = self.root / "processing"
        incoming.mkdir(mode=0o700)
        processing.mkdir(mode=0o700)
        return incoming, processing

    def write_request(self, incoming: Path, request: dict[str, object]) -> Path:
        path = incoming / f"request-{request['requestId']}.json"
        path.write_text(json.dumps(request, separators=(",", ":")) + "\n", encoding="ascii")
        path.chmod(0o600)
        return path

    def run_queue(self, updater: worker_module.UpdateWorker, incoming: Path, processing: Path) -> None:
        worker_module.process_queue(
            worker=updater, store=self.store, incoming=incoming, processing=processing,
            expected_request_uid=os.geteuid(), expected_peer_uid=1001,
        )

    def test_started_status_audit_failure_surfaces_and_recovers_without_apt(self) -> None:
        incoming, processing = self.queue_directories()
        request = self.request("check")
        self.write_request(incoming, request)
        updater = self.make_worker(FakeRunner())
        original_audit = self.store.audit

        def fail_started(**kwargs):
            if kwargs["result"] == "started":
                raise OSError("simulated audit storage failure")
            return original_audit(**kwargs)

        with mock.patch.object(self.store, "audit", side_effect=fail_started):
            with self.assertRaises(OSError):
                self.run_queue(updater, incoming, processing)
        self.assertEqual(json.loads(self.store.public_path.read_text())["state"], "checking")
        self.assertEqual(len(list(processing.iterdir())), 1)

        self.run_queue(updater, incoming, processing)
        status = json.loads(self.store.public_path.read_text())
        self.assertEqual(status["state"], "interrupted")
        self.assertEqual(list(processing.iterdir()), [])
        self.assertEqual(updater.runner.calls, [])

    def test_missing_incoming_directory_surfaces_even_with_recovery_work(self) -> None:
        processing = self.root / "processing"
        processing.mkdir(mode=0o700)
        request = self.request("check")
        path = processing / f"request-{request['requestId']}.json"
        path.write_text(json.dumps(request) + "\n", encoding="ascii")
        path.chmod(0o600)
        missing_incoming = self.root / "missing-incoming"
        with self.assertRaises(FileNotFoundError):
            self.run_queue(self.make_worker(FakeRunner()), missing_incoming, processing)
        self.assertTrue(path.exists())

    def test_terminal_status_audit_failure_is_retried_without_replaying_apt(self) -> None:
        incoming, processing = self.queue_directories()
        self.write_request(incoming, self.request("check"))
        runner = FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(0, "updated\n"),
            worker_module.CommandResult(0, SIMULATION),
        ])
        updater = self.make_worker(runner)
        original_audit = self.store.audit
        failed = False

        def fail_terminal_once(**kwargs):
            nonlocal failed
            if kwargs["result"] == "succeeded" and not failed:
                failed = True
                raise OSError("simulated terminal audit failure")
            return original_audit(**kwargs)

        with mock.patch.object(self.store, "audit", side_effect=fail_terminal_once):
            with self.assertRaises(OSError):
                self.run_queue(updater, incoming, processing)
        self.assertEqual(json.loads(self.store.public_path.read_text())["state"], "available")
        calls_after_first_run = list(runner.calls)

        self.run_queue(updater, incoming, processing)
        self.assertEqual(runner.calls, calls_after_first_run)
        self.assertEqual(list(processing.iterdir()), [])
        audit = [json.loads(line) for line in (self.root / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["result"] for row in audit], ["started", "succeeded"])

    def test_crash_remainder_plus_new_queue_is_fully_terminalized(self) -> None:
        incoming, processing = self.queue_directories()
        old_request = self.request("check")
        old_path = self.write_request(incoming, old_request)
        old_path.rename(processing / old_path.name)
        new_request = {**self.request("check"), "requestId": "update-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        self.write_request(incoming, new_request)
        updater = self.make_worker(FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(0, "updated\n"),
            worker_module.CommandResult(0, SIMULATION),
        ]))
        self.run_queue(updater, incoming, processing)
        self.assertEqual(list(incoming.iterdir()), [])
        self.assertEqual(list(processing.iterdir()), [])
        audit = [json.loads(line) for line in (self.root / "audit.jsonl").read_text().splitlines()]
        by_request = {row["requestId"]: row["result"] for row in audit if row["result"] != "started"}
        self.assertEqual(by_request[old_request["requestId"]], "interrupted")
        self.assertEqual(by_request[new_request["requestId"]], "succeeded")


class AdditionalUpdateActionTests(WorkerFixture):
    def test_apply_refuses_changed_plan_without_running_apt_apply(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        changed_output = SIMULATION.replace("2.8.3", "2.8.4")
        self.store.write_plan(plan)
        runner = FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(0, "updated\n"),
            worker_module.CommandResult(0, changed_output),
        ])
        updater = self.make_worker(runner)
        updater.process(self.request("apply-safe", plan["planId"]))

        self.assertFalse(any(kind == "passthrough" for kind, _command in runner.calls))
        status = json.loads(self.store.public_path.read_text(encoding="ascii"))
        self.assertEqual(status["code"], "PLAN_CHANGED")
        self.assertNotEqual(status["planId"], plan["planId"])

    def test_stale_or_missing_plan_never_executes_a_command(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW - timedelta(hours=1))
        self.store.write_plan(plan)
        runner = FakeRunner()
        updater = self.make_worker(runner)
        updater.process(self.request("apply-safe", plan["planId"]))
        self.assertEqual(runner.calls, [])
        self.assertEqual(json.loads(self.store.public_path.read_text())["code"], "PLAN_STALE")

    def test_package_lock_is_reported_without_raw_output(self) -> None:
        runner = FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(100, "Could not get lock /var/lib/apt/lists/lock secret"),
        ])
        updater = self.make_worker(runner)
        updater.process(self.request("check"))
        status_text = self.store.public_path.read_text(encoding="ascii")
        self.assertEqual(json.loads(status_text)["code"], "PACKAGE_MANAGER_BUSY")
        self.assertNotIn("/var/lib/apt", status_text)
        self.assertNotIn("secret", (self.root / "audit.jsonl").read_text())

    def test_failed_real_apply_invalidates_confirmation_token(self) -> None:
        plan = worker_module.parse_apt_plan(SIMULATION, NOW)
        self.store.write_plan(plan)
        runner = FakeRunner(
            captures=[
                worker_module.CommandResult(0, ""),
                worker_module.CommandResult(0, "updated\n"),
                worker_module.CommandResult(0, SIMULATION),
                worker_module.CommandResult(0, EXACT_SIMULATION),
                worker_module.CommandResult(0, "arm64\n"),
                worker_module.CommandResult(0, ""),
            ],
            passthrough=[worker_module.CommandResult(100)],
        )
        self.make_worker(runner).process(self.request("apply-safe", plan["planId"]))
        self.assertFalse(self.store.private_plan_path.exists())
        self.assertEqual(json.loads(self.store.public_path.read_text())["code"], "COMMAND_FAILED")

    def test_check_exposes_kept_back_summary_without_an_apply_token(self) -> None:
        runner = FakeRunner(captures=[
            worker_module.CommandResult(0, ""),
            worker_module.CommandResult(0, "updated\n"),
            worker_module.CommandResult(0, KEPT_BACK_SIMULATION),
        ])
        self.make_worker(runner).process(self.request("check"))
        status = json.loads(self.store.public_path.read_text())
        self.assertEqual(status["state"], "up-to-date")
        self.assertEqual(status["code"], "UPDATES_KEPT_BACK")
        self.assertEqual(status["summary"]["keptBackCount"], 3)
        self.assertEqual(status["summary"]["packageCount"], 0)
        self.assertIsNone(status["planId"])
        self.assertFalse(self.store.private_plan_path.exists())


class FilesystemSafetyTests(WorkerFixture):
    def test_queue_reader_rejects_link_or_wrong_mode(self) -> None:
        path = self.root / f"request-{REQUEST_ID}.json"
        path.write_text(json.dumps(self.request("check")) + "\n", encoding="ascii")
        path.chmod(0o640)
        with self.assertRaises(worker_module.WorkerError):
            worker_module.read_claimed_request(path, os.geteuid(), 1001)

    def test_public_status_is_private_group_readable_atomic_file(self) -> None:
        worker_module.initialize_status(self.store, NOW)
        metadata = self.store.public_path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o640)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(json.loads(self.store.public_path.read_text())["code"], "READY")

    def test_valid_json_with_unsafe_mode_is_replaced_on_initialize(self) -> None:
        unsafe = worker_module.public_status(now=NOW, state="idle", code="READY")
        self.store.public_path.write_text(json.dumps(unsafe), encoding="ascii")
        self.store.public_path.chmod(0o666)
        self.assertIsNone(self.store.read_public())
        worker_module.initialize_status(self.store, NOW)
        self.assertEqual(stat.S_IMODE(self.store.public_path.stat().st_mode), 0o640)

    def test_new_audit_entry_fsyncs_its_parent_before_queue_commit(self) -> None:
        request = self.request("check")
        with mock.patch.object(
            worker_module, "fsync_directory", wraps=worker_module.fsync_directory,
        ) as fsync:
            self.store.audit(
                now=NOW, request=request, result="started", code="CHECKING",
                plan_id=None, package_count=0, reboot_required=False,
            )
        fsync.assert_called_with(self.store.audit_path.parent)

    def test_claims_processing_remainder_and_full_bounded_incoming_set(self) -> None:
        incoming = self.root / "incoming"
        processing = self.root / "processing"
        incoming.mkdir(mode=0o700)
        processing.mkdir(mode=0o700)
        for index in range(gateway.MAX_QUEUE_DEPTH):
            name = f"request-update-00000000-0000-4000-8000-{index:012d}.json"
            (incoming / name).write_text("{}\n", encoding="ascii")
            old_name = f"request-update-00000000-0000-4000-9000-{index:012d}.json"
            (processing / old_name).write_text("{}\n", encoding="ascii")
        claimed = worker_module.claim_requests(incoming, processing)
        self.assertEqual(len(claimed), gateway.MAX_QUEUE_DEPTH * 2)
        self.assertEqual(list(incoming.iterdir()), [])
        self.assertEqual(len(list(processing.iterdir())), gateway.MAX_QUEUE_DEPTH * 2)

    def test_preflight_checks_readonly_and_space_without_mutation(self) -> None:
        preflight = worker_module.Preflight(self.root, self.root)
        with mock.patch.object(preflight, "_read_only", return_value=True):
            with self.assertRaisesRegex(worker_module.WorkerError, "ROOT_READ_ONLY"):
                preflight.verify_filesystems(applying=True)
        with mock.patch.object(worker_module.shutil, "disk_usage", return_value=mock.Mock(free=1)):
            with self.assertRaisesRegex(worker_module.WorkerError, "DISK_SPACE_LOW"):
                preflight.verify_filesystems(applying=False)


if __name__ == "__main__":
    unittest.main()
