import datetime as dt
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.generic_log_collector import FAILURE_MARKER, collect_generic_logs
from ops.log_pipeline import PipelineLimits


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


class GenericLogCollectorTests(unittest.TestCase):
    def _write_config(self, path: Path, sources: list[dict]) -> None:
        path.write_text(json.dumps({"schemaVersion": 1, "sources": sources}))
        path.chmod(0o600)

    def test_file_source_is_redacted_persisted_and_resumed_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            application = logs / "application.log"
            application.write_text("started\ntoken=raw-secret from 10.1.2.3\n")
            application.chmod(0o640)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application",
                "kind": "file",
                "path": str(application),
                "priority": "incident",
            }])
            output = root / "export"
            first = collect_generic_logs(
                output,
                config,
                NOW,
                expected_uid=os.getuid(),
                allowed_file_roots=(logs,),
            )
            self.assertEqual(first["status"], "ok")
            self.assertEqual(first["accepted"], 2)
            public = (output / "generic-logs.jsonl").read_text()
            self.assertIn("started", public)
            self.assertNotIn("raw-secret", public)
            self.assertNotIn("10.1.2.3", public)
            self.assertIn("[structured log]", public)
            self.assertEqual(
                stat.S_IMODE((output / "generic-logs.jsonl").stat().st_mode), 0o640
            )

            with application.open("a") as handle:
                handle.write("recovered\n")
            second = collect_generic_logs(
                output,
                config,
                NOW + dt.timedelta(minutes=1),
                expected_uid=os.getuid(),
                allowed_file_roots=(logs,),
            )
            self.assertEqual(second["accepted"], 1)
            records = [
                json.loads(line)
                for line in (output / "generic-logs.jsonl").read_text().splitlines()
            ]
            self.assertEqual([item["message"] for item in records], [
                "started", "[structured log]", "recovered",
            ])

    def test_v1_cursor_inside_pem_is_migrated_without_persisting_followup_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            application = logs / "application.log"
            application.write_text("-----BEGIN RSA PRIVATE KEY-----\n")
            application.chmod(0o640)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(application),
            }])
            output = root / "export"
            first = collect_generic_logs(
                output, config, NOW, expected_uid=os.getuid(), allowed_file_roots=(logs,),
            )
            self.assertEqual(first["status"], "ok")

            # Model an on-disk v1 snapshot whose cursor already advanced past
            # BEGIN. The upgrade must clear it and enter recovery before reading
            # the next physical lines.
            records_path = output / "generic-logs.jsonl"
            rows = [json.loads(line) for line in records_path.read_text().splitlines()]
            for row in rows:
                row["redactionVersion"] = "monitor-log-redaction-v1"
            records_path.write_text("".join(
                json.dumps(row, separators=(",", ":")) + "\n" for row in rows
            ))
            records_path.chmod(0o640)
            state_path = output / ".state" / "generic-log-state.json"
            state = json.loads(state_path.read_text())
            quota = state["quotaState"]
            state["quotaState"] = {
                "schemaVersion": 1,
                "windowStartedAt": quota["windowStartedAt"],
                "admittedGlobal": quota["admittedGlobal"],
                "admittedBySource": quota["admittedBySource"],
            }
            state_path.write_text(json.dumps(state))
            state_path.chmod(0o600)
            with application.open("a") as handle:
                handle.write(
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
                    "-----END RSA PRIVATE KEY-----\n"
                    "service recovered\n"
                )

            second = collect_generic_logs(
                output,
                config,
                NOW + dt.timedelta(seconds=1),
                expected_uid=os.getuid(),
                allowed_file_roots=(logs,),
            )

            self.assertEqual(second["status"], "ok")
            public = records_path.read_text()
            self.assertNotIn("MIIEvQIB", public)
            self.assertNotIn("BEGIN RSA PRIVATE KEY", public)
            self.assertNotIn("END RSA PRIVATE KEY", public)
            self.assertEqual(
                [json.loads(line)["message"] for line in public.splitlines()],
                ["service recovered"],
            )

    def test_initial_tail_recovers_when_pem_begin_is_outside_the_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            application = logs / "application.log"
            application.write_text(
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
                "-----END RSA PRIVATE KEY-----\n"
                "service recovered\n"
            )
            application.chmod(0o640)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(application),
            }])
            output = root / "export"

            result = collect_generic_logs(
                output, config, NOW, expected_uid=os.getuid(), allowed_file_roots=(logs,),
            )

            self.assertEqual(result["status"], "ok")
            public = (output / "generic-logs.jsonl").read_text()
            self.assertNotIn("MIIEvQIB", public)
            self.assertNotIn("END RSA PRIVATE KEY", public)
            self.assertEqual(
                [json.loads(line)["message"] for line in public.splitlines()],
                ["service recovered"],
            )

    def test_rotation_gap_enters_recovery_before_gap_followup_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            application = logs / "application.log"
            application.write_text("initial ordinary event\n")
            application.chmod(0o640)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:application", "kind": "file", "path": str(application),
            }])
            output = root / "export"
            first = collect_generic_logs(
                output, config, NOW, expected_uid=os.getuid(), allowed_file_roots=(logs,),
            )
            self.assertEqual(first["status"], "ok")

            def gap_read(_definition, _cursor, **_kwargs):
                return {
                    "status": "truncated",
                    "errorClass": "output_limit",
                    "lines": [
                        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
                        "-----END EC PRIVATE KEY-----",
                        "after rotation",
                    ],
                    "cursor": {"inode": 12, "offset": 200},
                    "droppedLines": 1,
                    "rotationGap": True,
                    "backlogGap": False,
                }

            with patch("ops.generic_log_collector.read_file_source", side_effect=gap_read):
                second = collect_generic_logs(
                    output,
                    config,
                    NOW + dt.timedelta(seconds=1),
                    expected_uid=os.getuid(),
                    allowed_file_roots=(logs,),
                )

            self.assertEqual(second["status"], "ok")
            public = (output / "generic-logs.jsonl").read_text()
            self.assertNotIn("MIIEvQIB", public)
            self.assertNotIn("END EC PRIVATE KEY", public)
            self.assertEqual(
                [json.loads(line)["message"] for line in public.splitlines()],
                ["initial ordinary event", "after rotation"],
            )

    def test_optional_empty_config_publishes_explicit_no_data_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "export"
            result = collect_generic_logs(
                output,
                root / "missing.json",
                NOW,
                expected_uid=os.getuid(),
                allowed_file_roots=(root,),
            )
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["sources"], 0)
            self.assertEqual((output / "generic-logs.jsonl").read_text(), "")
            status = json.loads((output / "generic-log-sources.json").read_text())
            self.assertEqual(status["sources"], [])

    def test_unsafe_config_sets_a_strict_failure_marker_and_recovery_clears_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:escape", "kind": "file", "path": "/etc/passwd",
            }])
            output = root / "export"
            failed = collect_generic_logs(
                output,
                config,
                NOW,
                expected_uid=os.getuid(),
                allowed_file_roots=(root,),
            )
            self.assertEqual(failed["status"], "collection_error")
            self.assertEqual(failed["errorClass"], "unsafe_config")
            marker = output / FAILURE_MARKER
            self.assertTrue(marker.is_file())
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o640)
            self.assertEqual(json.loads(marker.read_text()), {
                "schemaVersion": 1,
                "observedAt": "2026-08-30T12:00:00.000Z",
                "errorClass": "unsafe_config",
            })

            self._write_config(config, [])
            recovered = collect_generic_logs(
                output,
                config,
                NOW + dt.timedelta(minutes=1),
                expected_uid=os.getuid(),
                allowed_file_roots=(root,),
            )
            self.assertEqual(recovered["status"], "ok")
            self.assertFalse(marker.exists())

    def test_source_read_failure_is_visible_without_failing_other_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            unsafe = logs / "unsafe.log"
            unsafe.write_text("must not be read\n")
            unsafe.chmod(0o666)
            config = root / "sources.json"
            self._write_config(config, [{
                "id": "file:unsafe", "kind": "file", "path": str(unsafe),
            }])
            output = root / "export"
            result = collect_generic_logs(
                output,
                config,
                NOW,
                expected_uid=os.getuid(),
                allowed_file_roots=(logs,),
            )
            self.assertEqual(result["status"], "ok")
            status = json.loads((output / "generic-log-sources.json").read_text())
            self.assertEqual(status["sources"][0]["status"], "permission_denied")
            self.assertEqual(status["sources"][0]["errorClass"], "permission_denied")
            self.assertEqual((output / "generic-logs.jsonl").read_text(), "")

    def test_sixty_four_sources_share_one_sixteen_mib_acquisition_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            config = root / "sources.json"
            self._write_config(config, [{
                "id": f"file:source-{index:02d}",
                "kind": "file",
                "path": str(logs / f"source-{index:02d}.log"),
            } for index in range(64)])
            limits = PipelineLimits()
            calls: list[tuple[int, int]] = []

            def fake_read(_definition, cursor, *, maximum_bytes, maximum_line_bytes):
                calls.append((maximum_bytes, maximum_line_bytes))
                exceeded = len(calls) == 1
                return {
                    "status": "truncated" if exceeded else "no_data",
                    "errorClass": "output_limit" if exceeded else None,
                    "lines": [],
                    "cursor": cursor,
                    "droppedLines": 3 if exceeded else 0,
                    "rotationGap": False,
                }

            with patch(
                "ops.generic_log_collector.read_file_source",
                side_effect=fake_read,
            ):
                result = collect_generic_logs(
                    root / "export",
                    config,
                    NOW,
                    expected_uid=os.getuid(),
                    allowed_file_roots=(logs,),
                    pipeline_limits=limits,
                )

            self.assertEqual(result["status"], "ok")
            self.assertEqual(len(calls), 64)
            fair_share = limits.max_input_bytes_global // 64
            self.assertEqual({maximum for maximum, _line in calls}, {fair_share})
            self.assertEqual(sum(maximum for maximum, _line in calls), 16 * 1024 * 1024)
            self.assertEqual(
                {line for _maximum, line in calls}, {limits.max_line_bytes}
            )
            status = json.loads(
                (root / "export" / "generic-log-sources.json").read_text()
            )
            self.assertEqual(status["sources"][0]["status"], "truncated")
            self.assertEqual(status["sources"][0]["errorClass"], "output_limit")
            self.assertEqual(status["sources"][0]["dropped"]["acquisition"], 3)


if __name__ == "__main__":
    unittest.main()
