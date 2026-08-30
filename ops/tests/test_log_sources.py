import datetime as dt
import errno
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import log_sources
from ops.log_pipeline import SourceBatch, process_batches
from ops.log_sources import (
    CommandResult,
    SourceConfigError,
    load_source_config,
    read_file_source,
    read_journal_source,
    run_bounded_command,
)


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


class LogSourceTests(unittest.TestCase):
    def _write_config(self, path: Path, sources: list[dict]) -> None:
        path.write_text(json.dumps({"schemaVersion": 1, "sources": sources}))
        path.chmod(0o600)

    def test_source_config_is_exact_owner_controlled_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log_root = root / "logs"
            log_root.mkdir()
            config = root / "sources.json"
            self._write_config(config, [
                {
                    "id": "file:application",
                    "kind": "file",
                    "path": str(log_root / "application.log"),
                    "priority": "incident",
                    "fieldAllowlist": ["status"],
                    "maxLines": 250,
                },
                {
                    "id": "journal:sshd",
                    "kind": "journald",
                    "unit": "sshd.service",
                    "priority": "security",
                },
            ])
            loaded = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(log_root,)
            )
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[0].path, log_root / "application.log")
            self.assertEqual(loaded[0].max_lines, 250)
            self.assertEqual(loaded[1].unit, "sshd.service")
            self.assertEqual(loaded[1].source.systemd_unit, "sshd.service")
            self.assertEqual(loaded[1].source.priority, "security")

            config.chmod(0o622)
            with self.assertRaises(SourceConfigError):
                load_source_config(config, expected_uid=os.getuid(), allowed_file_roots=(log_root,))
            config.chmod(0o600)
            config.write_text('{"schemaVersion":1,"schemaVersion":1,"sources":[]}')
            with self.assertRaises(SourceConfigError):
                load_source_config(config, expected_uid=os.getuid(), allowed_file_roots=(log_root,))

    def test_config_rejects_symlink_unknown_fields_paths_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            config = root / "sources.json"
            target = root / "target.json"
            self._write_config(target, [])
            config.symlink_to(target)
            with self.assertRaises(SourceConfigError):
                load_source_config(config, expected_uid=os.getuid(), allowed_file_roots=(logs,))
            config.unlink()

            invalid_sets = [
                [{"id": "file:a", "kind": "file", "path": "/etc/passwd"}],
                [{"id": "file:a", "kind": "file", "path": str(logs / "a"), "unknown": True}],
                [
                    {"id": "file:a", "kind": "file", "path": str(logs / "a")},
                    {"id": "file:a", "kind": "file", "path": str(logs / "b")},
                ],
                [{"id": "journal:a", "kind": "journald", "unit": "../../escape"}],
                [{"id": "docker:a", "kind": "docker", "path": str(logs / "a")}],
            ]
            for sources in invalid_sets:
                with self.subTest(sources=sources):
                    self._write_config(config, sources)
                    with self.assertRaises(SourceConfigError):
                        load_source_config(
                            config, expected_uid=os.getuid(), allowed_file_roots=(logs,)
                        )

    def test_optional_missing_config_is_empty_but_required_config_fails(self):
        missing = Path("/definitely/not/present/monitor-log-sources.json")
        self.assertEqual(load_source_config(missing), ())
        with self.assertRaises(SourceConfigError):
            load_source_config(missing, required=True)

    def test_file_tail_preserves_partial_append_and_rotation_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "application.log"
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(log),
            }])
            definition = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(root,)
            )[0]
            log.write_text("first\npartial")
            log.chmod(0o640)
            first = read_file_source(definition, None, maximum_bytes=1024, maximum_line_bytes=128)
            self.assertEqual(first["status"], "fresh")
            self.assertEqual(first["lines"], ["first"])

            with log.open("a") as handle:
                handle.write("-complete\nrotated-tail\n")
            second = read_file_source(
                definition, first["cursor"], maximum_bytes=1024, maximum_line_bytes=128
            )
            self.assertEqual(second["lines"], ["partial-complete", "rotated-tail"])
            self.assertFalse(second["rotationGap"])

            with log.open("a") as handle:
                handle.write("after-cursor\n")
            log.rename(root / "application.log.1")
            log.write_text("new-file\n")
            log.chmod(0o640)
            third = read_file_source(
                definition, second["cursor"], maximum_bytes=1024, maximum_line_bytes=128
            )
            self.assertEqual(third["lines"], ["after-cursor", "new-file"])
            self.assertFalse(third["rotationGap"])
            fourth = read_file_source(
                definition, third["cursor"], maximum_bytes=1024, maximum_line_bytes=128
            )
            self.assertEqual(fourth["lines"], [])

    def test_file_tail_reports_unsafe_source_and_bounded_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "application.log"
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(log),
                "maxLines": 2,
            }])
            definition = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(root,)
            )[0]
            log.write_text("one\n" + "x" * 129 + "\ntwo\nthree\n")
            log.chmod(0o640)
            result = read_file_source(
                definition, None, maximum_bytes=1024, maximum_line_bytes=128
            )
            self.assertEqual(result["lines"], ["two", "three"])
            self.assertEqual(result["droppedLines"], 2)
            self.assertEqual(result["status"], "truncated")
            self.assertEqual(result["errorClass"], "output_limit")

            log.chmod(0o666)
            denied = read_file_source(definition, result["cursor"])
            self.assertEqual(denied["status"], "permission_denied")
            self.assertEqual(denied["lines"], [])
            with self.assertRaises(ValueError):
                read_file_source(definition, {"inode": -1, "offset": 0})

    def test_file_tail_reports_same_inode_backlog_byte_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "application.log"
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(log),
            }])
            definition = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(root,)
            )[0]
            log.write_text("baseline\n")
            log.chmod(0o640)
            first = read_file_source(
                definition, None, maximum_bytes=1024, maximum_line_bytes=128
            )
            with log.open("a") as handle:
                handle.write("lost-line\n" * 150)
                handle.write("retained-line\n")

            second = read_file_source(
                definition,
                first["cursor"],
                maximum_bytes=1024,
                maximum_line_bytes=128,
            )

            self.assertEqual(second["status"], "truncated")
            self.assertEqual(second["errorClass"], "output_limit")
            self.assertTrue(second["backlogGap"])
            self.assertGreaterEqual(second["droppedLines"], 1)
            self.assertIn("retained-line", second["lines"])

    def test_file_tail_detects_copytruncate_that_regrows_past_the_prior_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "application.log"
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(log),
            }])
            definition = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(root,)
            )[0]
            log.write_text("old-one\nold-two\n")
            log.chmod(0o640)
            first = read_file_source(
                definition, None, maximum_bytes=1024, maximum_line_bytes=128
            )
            inode = log.stat().st_ino
            self.assertIn("guardSha256", first["cursor"])

            log.write_text("new-one\nnew-two\nnew-three\nnew-four\n")
            self.assertEqual(log.stat().st_ino, inode)
            self.assertGreater(log.stat().st_size, first["cursor"]["offset"])
            second = read_file_source(
                definition,
                first["cursor"],
                maximum_bytes=1024,
                maximum_line_bytes=128,
            )

            self.assertEqual(
                second["lines"], ["new-one", "new-two", "new-three", "new-four"]
            )
            self.assertEqual(second["status"], "truncated")
            self.assertEqual(second["errorClass"], "output_limit")
            self.assertTrue(second["backlogGap"])
            self.assertGreaterEqual(second["droppedLines"], 1)

    def test_file_tail_never_follows_an_intermediate_symlink_outside_reviewed_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reviewed = root / "reviewed"
            outside = root / "outside"
            reviewed.mkdir()
            outside.mkdir()
            secret = outside / "application.log"
            secret.write_text("must-not-be-collected\n")
            secret.chmod(0o640)
            (reviewed / "linked").symlink_to(outside, target_is_directory=True)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application",
                "kind": "file",
                "path": str(reviewed / "linked" / "application.log"),
            }])
            definition = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(reviewed,)
            )[0]

            result = read_file_source(definition, None)

            self.assertEqual(result["status"], "permission_denied")
            self.assertEqual(result["lines"], [])
            self.assertNotIn("must-not-be-collected", json.dumps(result))

            (reviewed / "leaf.log").symlink_to(secret)
            self._write_config(config, [{
                "id": "file:leaf",
                "kind": "file",
                "path": str(reviewed / "leaf.log"),
            }])
            leaf = load_source_config(
                config, expected_uid=os.getuid(), allowed_file_roots=(reviewed,)
            )[0]
            leaf_result = read_file_source(leaf, None)
            self.assertEqual(leaf_result["status"], "permission_denied")
            self.assertEqual(leaf_result["lines"], [])

    def test_rotated_log_scan_lazily_stops_after_256_directory_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(300):
                (root / f"application.log.{index:03d}").write_text("old\n")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    log_sources.os, "stat", wraps=os.stat
                ) as inspected:
                    self.assertIsNone(log_sources._open_rotated_log(
                        descriptor, "application.log", -1
                    ))
                self.assertEqual(inspected.call_count, 256)
            finally:
                os.close(descriptor)

    def test_log_open_closes_descriptors_when_metadata_checks_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "application.log"
            log.write_text("safe\n")
            log.chmod(0o640)
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                baseline = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(
                    log_sources.os,
                    "fstat",
                    side_effect=OSError(errno.EIO, "metadata failed"),
                ):
                    with self.assertRaises(OSError):
                        log_sources._open_log_at(parent, log.name)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
            finally:
                os.close(parent)

            definition = log_sources.SourceDefinition(
                source=log_sources.LogSource(source_id="file:test", kind="file"),
                path=log,
                file_root=root,
            )
            baseline = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(
                log_sources.os,
                "fstat",
                side_effect=OSError(errno.EIO, "metadata failed"),
            ):
                with self.assertRaises(OSError):
                    log_sources._open_log_parent(definition)
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_journal_adapter_reduces_metadata_and_pipeline_redacts_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "priority": "security",
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            rows = [
                {
                    "__CURSOR": "s=abc;i=1",
                    "__REALTIME_TIMESTAMP": "1788091199000000",
                    "PRIORITY": "3",
                    "MESSAGE": "failed login token=must-not-escape from 10.1.2.3",
                    "_PID": "999",
                    "UNREVIEWED": "private-extra",
                },
                {
                    "__CURSOR": "s=abc;i=2",
                    "__REALTIME_TIMESTAMP": "1788091200000000",
                    "PRIORITY": "6",
                    "MESSAGE": "service recovered",
                },
            ]
            captured: list[str] = []

            def runner(command, timeout, maximum):
                captured.extend(command)
                self.assertEqual(timeout, 3.0)
                self.assertEqual(maximum, 2 * 1024 * 1024)
                return CommandResult(
                    "completed",
                    ("\n".join(json.dumps(row) for row in rows) + "\n").encode(),
                    b"",
                    0,
                )

            acquired = read_journal_source(definition, None, runner=runner)
            self.assertIn("--unit=sshd.service", captured)
            self.assertIn("--lines=1000", captured)
            self.assertNotIn("--lines=+1000", captured)
            self.assertEqual(acquired["status"], "fresh")
            self.assertEqual(acquired["cursor"], {"cursor": "s=abc;i=2"})
            self.assertEqual(len(acquired["lines"]), 2)
            self.assertNotIn("_PID", "".join(acquired["lines"]))
            self.assertNotIn("private-extra", "".join(acquired["lines"]))

            normalized = process_batches(
                [SourceBatch(definition.source, acquired["lines"])], NOW
            )
            serialized = json.dumps(normalized)
            self.assertNotIn("must-not-escape", serialized)
            self.assertNotIn("10.1.2.3", serialized)
            self.assertEqual(normalized["records"][0]["severity"], "error")
            self.assertEqual(normalized["records"][0]["systemdUnit"], "sshd.service")

    def test_journal_counted_poison_row_does_not_block_later_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "maxLines": 1,
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            poison = {"__CURSOR": "s=abc;i=2", "PRIORITY": "6"}
            lookahead = {
                "__CURSOR": "s=abc;i=3", "MESSAGE": "later-valid", "PRIORITY": "6",
            }
            first = read_journal_source(
                definition,
                {"cursor": "s=abc;i=1"},
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "completed",
                    (json.dumps(poison) + "\n" + json.dumps(lookahead) + "\n").encode(),
                    b"",
                    0,
                ),
            )
            self.assertEqual(first["status"], "truncated")
            self.assertEqual(first["droppedLines"], 1)
            self.assertEqual(first["cursor"], {"cursor": "s=abc;i=2"})

            resumed = read_journal_source(
                definition,
                first["cursor"],
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "completed", (json.dumps(lookahead) + "\n").encode(), b"", 0
                ),
            )
            self.assertEqual(resumed["status"], "fresh")
            self.assertEqual(resumed["cursor"], {"cursor": "s=abc;i=3"})
            self.assertIn("later-valid", resumed["lines"][0])

    def test_journal_oversized_valid_cursor_does_not_block_later_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "maxLines": 1,
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            oversized = {
                "__CURSOR": "s=abc;i=2", "MESSAGE": "x" * (128 * 1024),
                "PRIORITY": "6",
            }
            later = {
                "__CURSOR": "s=abc;i=3", "MESSAGE": "later-valid", "PRIORITY": "6",
            }
            first = read_journal_source(
                definition,
                {"cursor": "s=abc;i=1"},
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "completed",
                    (json.dumps(oversized) + "\n" + json.dumps(later) + "\n").encode(),
                    b"",
                    0,
                ),
            )
            self.assertEqual(first["status"], "truncated")
            self.assertEqual(first["droppedLines"], 1)
            self.assertEqual(first["cursor"], {"cursor": "s=abc;i=2"})

            resumed = read_journal_source(
                definition,
                first["cursor"],
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "completed", (json.dumps(later) + "\n").encode(), b"", 0
                ),
            )
            self.assertEqual(resumed["status"], "fresh")
            self.assertEqual(resumed["cursor"], {"cursor": "s=abc;i=3"})
            self.assertIn("later-valid", resumed["lines"][0])

    def test_journal_output_cut_after_valid_cursor_can_advance_counted_drop(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "maxLines": 1,
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            partial = (
                b'{"__CURSOR":"s=abc;i=2","MESSAGE":"'
                + b"x" * (128 * 1024)
            )
            acquired = read_journal_source(
                definition,
                {"cursor": "s=abc;i=1"},
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "limit_exceeded", partial, b"", -9
                ),
            )
            self.assertEqual(acquired["status"], "truncated")
            self.assertEqual(acquired["errorClass"], "output_limit")
            self.assertEqual(acquired["droppedLines"], 1)
            self.assertEqual(acquired["cursor"], {"cursor": "s=abc;i=2"})

    def test_journal_incremental_backlog_reads_oldest_without_advancing_past_lookahead(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "maxLines": 2,
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            rows = [
                {"__CURSOR": f"s=abc;i={index}", "MESSAGE": f"line-{index}", "PRIORITY": "6"}
                for index in (2, 3, 4)
            ]
            captured: list[str] = []

            def runner(command, _timeout, _maximum):
                captured.extend(command)
                return CommandResult(
                    "completed",
                    ("\n".join(json.dumps(row) for row in rows) + "\n").encode(),
                    b"",
                    0,
                )

            acquired = read_journal_source(
                definition, {"cursor": "s=abc;i=1"}, runner=runner
            )

            self.assertIn("--after-cursor=s=abc;i=1", captured)
            self.assertIn("--lines=+3", captured)
            self.assertEqual(acquired["status"], "truncated")
            self.assertEqual(acquired["errorClass"], "output_limit")
            self.assertEqual(acquired["droppedLines"], 0)
            self.assertEqual(len(acquired["lines"]), 2)
            self.assertIn("line-2", acquired["lines"][0])
            self.assertIn("line-3", acquired["lines"][1])
            self.assertNotIn("line-4", "".join(acquired["lines"]))
            self.assertEqual(acquired["cursor"], {"cursor": "s=abc;i=3"})

            resumed_commands: list[str] = []
            resumed = read_journal_source(
                definition,
                acquired["cursor"],
                runner=lambda command, _timeout, _maximum: (
                    resumed_commands.extend(command)
                    or CommandResult(
                        "completed", (json.dumps(rows[2]) + "\n").encode(), b"", 0
                    )
                ),
            )
            self.assertIn("--after-cursor=s=abc;i=3", resumed_commands)
            self.assertIn("--lines=+3", resumed_commands)
            self.assertEqual(resumed["status"], "fresh")
            self.assertEqual(resumed["droppedLines"], 0)
            self.assertEqual(resumed["cursor"], {"cursor": "s=abc;i=4"})
            self.assertIn("line-4", resumed["lines"][0])

    def test_journal_invalid_rows_are_dropped_with_counted_cursor_advance(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
                "maxLines": 3,
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            rows = [
                {"__CURSOR": "s=abc;i=2", "MESSAGE": "emitted", "PRIORITY": "6"},
                {"__CURSOR": "s=abc;i=3", "PRIORITY": "6"},
                {"MESSAGE": "missing cursor", "PRIORITY": "6"},
            ]

            acquired = read_journal_source(
                definition,
                {"cursor": "s=abc;i=1"},
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "completed",
                    ("\n".join(json.dumps(row) for row in rows) + "\n").encode(),
                    b"",
                    0,
                ),
            )

            self.assertEqual(acquired["status"], "truncated")
            self.assertEqual(acquired["errorClass"], "output_limit")
            self.assertEqual(acquired["droppedLines"], 2)
            self.assertEqual(len(acquired["lines"]), 1)
            self.assertIn("emitted", acquired["lines"][0])
            self.assertEqual(acquired["cursor"], {"cursor": "s=abc;i=3"})

    def test_journal_failure_states_do_not_expose_command_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            fixtures = [
                (CommandResult("unsupported"), "unsupported", "unsupported"),
                (CommandResult("timeout"), "failed", "timeout"),
                (CommandResult("failed"), "failed", "read_failed"),
                (CommandResult("completed", b"", b"Permission denied: /secret/path", 1), "permission_denied", "permission_denied"),
                (CommandResult("completed", b"", b"raw internal failure", 2), "failed", "command_failed"),
            ]
            for command_result, status, error_class in fixtures:
                with self.subTest(status=status):
                    result = read_journal_source(
                        definition, None,
                        runner=lambda _command, _timeout, _maximum, value=command_result: value,
                    )
                    self.assertEqual(result["status"], status)
                    self.assertEqual(result["errorClass"], error_class)
                    self.assertNotIn("secret", json.dumps(result).lower())
                    self.assertNotIn("internal", json.dumps(result).lower())

    def test_journal_output_limit_keeps_only_complete_valid_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "sources.json"
            self._write_config(config, [{
                "id": "journal:sshd", "kind": "journald", "unit": "sshd.service",
            }])
            definition = load_source_config(config, expected_uid=os.getuid())[0]
            valid = json.dumps({
                "__CURSOR": "s=abc;i=1", "MESSAGE": "one", "PRIORITY": "6",
            }).encode()
            result = read_journal_source(
                definition, None,
                runner=lambda _command, _timeout, _maximum: CommandResult(
                    "limit_exceeded", valid + b"\n{partial", b"", -9
                ),
            )
            self.assertEqual(result["status"], "truncated")
            self.assertEqual(result["errorClass"], "output_limit")
            self.assertEqual(len(result["lines"]), 1)
            self.assertEqual(result["droppedLines"], 1)
            self.assertEqual(result["cursor"], {"cursor": "s=abc;i=1"})

    def test_bounded_command_enforces_output_and_timeout(self):
        completed = run_bounded_command(
            [sys.executable, "-c", "print('ok')"], 1.0, 1024
        )
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"ok\n")

        limited = run_bounded_command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
            1.0,
            1024,
        )
        self.assertEqual(limited.status, "limit_exceeded")
        self.assertLessEqual(len(limited.stdout), 1024)

        timed_out = run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(2)"], 0.1, 1024
        )
        self.assertEqual(timed_out.status, "timeout")


if __name__ == "__main__":
    unittest.main()
