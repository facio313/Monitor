import datetime as dt
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import log_store
from ops.log_pipeline import LogSource, PipelineLimits, SourceBatch, process_batches
from ops.log_sources import SourceDefinition
from ops.log_store import GenericLogStore, LogStoreError


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


def file_definition(source_id: str = "file:application") -> SourceDefinition:
    return SourceDefinition(
        source=LogSource(source_id=source_id, kind="file"),
        path=Path(f"/var/log/{source_id.replace(':', '-')}.log"),
        file_root=Path("/var/log"),
    )


def pipeline_for(definition: SourceDefinition, lines, observed=NOW, limits=None, prior=None):
    return process_batches(
        [SourceBatch(definition.source, lines)],
        observed,
        limits=limits,
        prior_state=prior,
    )


def acquisition(status="fresh", dropped=0, error=None):
    return {
        "status": status,
        "errorClass": error,
        "lines": [],
        "cursor": {"inode": 10, "offset": 20},
        "droppedLines": dropped,
        "rotationGap": False,
    }


class GenericLogStoreTests(unittest.TestCase):
    def test_pending_marker_is_fsynced_then_published_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pending.json"
            payload = b'{"complete":true}\n'
            events: list[str] = []
            original_fsync = log_store.os.fsync
            original_rename = log_store._rename_noreplace

            def observed_fsync(descriptor):
                kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                events.append(f"fsync:{kind}")
                if kind == "directory":
                    self.assertEqual(path.read_bytes(), payload)
                    self.assertEqual(list(root.glob(".pending.json.tmp-*")), [])
                return original_fsync(descriptor)

            def observed_rename(source, destination):
                self.assertIn("fsync:file", events)
                events.append("rename")
                return original_rename(source, destination)

            with (
                mock.patch.object(log_store.os, "fsync", side_effect=observed_fsync),
                mock.patch.object(log_store, "_rename_noreplace", side_effect=observed_rename),
            ):
                log_store._atomic_create_bytes(path, payload, 0o600, os.getuid())

            self.assertEqual(events, ["fsync:file", "rename", "fsync:directory"])
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

            with self.assertRaisesRegex(LogStoreError, "already exists"):
                log_store._atomic_create_bytes(
                    path, b'{"must":"not overwrite"}\n', 0o600, os.getuid()
                )
            self.assertEqual(path.read_bytes(), payload)

    def test_pending_marker_mid_write_and_file_fsync_failures_leave_no_partial_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b'{"complete":true,"padding":"abcdef"}\n'

            write_path = root / "write-failure.json"
            original_write = log_store.os.write
            write_calls = 0

            def fail_mid_write(descriptor, data):
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    return original_write(descriptor, data[:5])
                raise OSError("injected pending write failure")

            with mock.patch.object(
                log_store.os, "write", side_effect=fail_mid_write
            ):
                with self.assertRaisesRegex(OSError, "pending write failure"):
                    log_store._atomic_create_bytes(
                        write_path, payload, 0o600, os.getuid()
                    )
            self.assertFalse(write_path.exists())
            self.assertEqual(list(root.glob(".write-failure.json.tmp-*")), [])

            fsync_path = root / "fsync-failure.json"
            original_fsync = log_store.os.fsync

            def fail_file_fsync(descriptor):
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("injected pending file fsync failure")
                return original_fsync(descriptor)

            with mock.patch.object(
                log_store.os, "fsync", side_effect=fail_file_fsync
            ):
                with self.assertRaisesRegex(OSError, "file fsync failure"):
                    log_store._atomic_create_bytes(
                        fsync_path, payload, 0o600, os.getuid()
                    )
            self.assertFalse(fsync_path.exists())
            self.assertEqual(list(root.glob(".fsync-failure.json.tmp-*")), [])

    def test_pending_marker_publish_race_and_directory_fsync_failure_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            race_path = root / "race.json"
            winner = b'{"writer":"winner"}\n'
            original_rename = log_store._rename_noreplace

            def install_competing_marker(source, destination):
                Path(destination).write_bytes(winner)
                Path(destination).chmod(0o600)
                return original_rename(source, destination)

            with mock.patch.object(
                log_store, "_rename_noreplace", side_effect=install_competing_marker
            ):
                with self.assertRaisesRegex(LogStoreError, "already exists"):
                    log_store._atomic_create_bytes(
                        race_path, b'{"writer":"loser"}\n', 0o600, os.getuid()
                    )
            self.assertEqual(race_path.read_bytes(), winner)
            self.assertEqual(list(root.glob(".race.json.tmp-*")), [])

            crash_path = root / "crash-equivalent.json"
            complete = b'{"durable":"file-before-publish"}\n'
            with mock.patch.object(
                log_store,
                "_fsync_directory",
                side_effect=OSError("injected directory fsync failure"),
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failure"):
                    log_store._atomic_create_bytes(
                        crash_path, complete, 0o600, os.getuid()
                    )

            # Losing acknowledgement after the single-name atomic publication
            # leaves only a complete marker. A retry preserves it and fails closed.
            self.assertEqual(crash_path.read_bytes(), complete)
            self.assertEqual(crash_path.stat().st_nlink, 1)
            self.assertEqual(list(root.glob(".crash-equivalent.json.tmp-*")), [])
            with self.assertRaisesRegex(LogStoreError, "already exists"):
                log_store._atomic_create_bytes(
                    crash_path, b'{"overwrite":true}\n', 0o600, os.getuid()
                )
            self.assertEqual(crash_path.read_bytes(), complete)

    def test_store_rejects_limits_above_packaged_reader_and_memory_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            GenericLogStore(
                root,
                [],
                max_records=20_000,
                max_file_bytes=16 * 1024 * 1024,
            )
            with self.assertRaisesRegex(ValueError, "max_records"):
                GenericLogStore(root, [], max_records=20_001)
            with self.assertRaisesRegex(ValueError, "max_file_bytes"):
                GenericLogStore(root, [], max_file_bytes=16 * 1024 * 1024 + 1)

    def test_commit_publishes_logs_status_then_private_cursor_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(definition, [
                "safe first", "token=must-not-escape from 10.1.2.3",
            ])
            acquired = acquisition()
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            committed = store.commit(
                pipeline["records"], status,
                {definition.source.source_id: acquired["cursor"]},
                pipeline["quotaState"], NOW,
            )
            self.assertEqual(committed, {
                "stored": 2, "accepted": 2, "retentionDropped": 0,
            })
            self.assertFalse(store.pending_path.exists())
            self.assertEqual(stat.S_IMODE(store.records_path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(store.status_path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(store.private_state_path.stat().st_mode), 0o600)
            self.assertEqual(len(store.load_records()), 2)
            self.assertEqual(store.load_status_document(), status)
            state = store.load_private_state()
            self.assertEqual(state["cursors"], {
                definition.source.source_id: {"inode": 10, "offset": 20},
            })
            serialized = (
                store.records_path.read_text() + store.status_path.read_text()
                + store.private_state_path.read_text()
            )
            self.assertNotIn("must-not-escape", serialized)
            self.assertNotIn("10.1.2.3", serialized)

    def test_v1_history_and_pending_are_purged_with_durable_cursor_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            template = pipeline_for(definition, ["template"])["records"][0]
            legacy_body = {
                **template,
                "message": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
                "redactionVersion": "monitor-log-redaction-v1",
            }
            legacy_ordinary = {
                **template,
                "message": "ordinary v1 history is cleared as one unsafe snapshot",
                "redactionVersion": "monitor-log-redaction-v1",
            }
            store.records_path.write_bytes(b"".join(
                json.dumps(row, separators=(",", ":")).encode() + b"\n"
                for row in (legacy_body, legacy_ordinary)
            ))
            store.records_path.chmod(0o640)
            old_private_state = {
                "schemaVersion": 1,
                "cursors": {definition.source.source_id: {"inode": 10, "offset": 20}},
                "quotaState": {
                    "schemaVersion": 1,
                    "windowStartedAt": int(NOW.timestamp()),
                    "admittedGlobal": 0,
                    "admittedBySource": {},
                },
            }
            store.private_state_path.write_text(json.dumps(old_private_state))
            store.private_state_path.chmod(0o600)
            # Even an interrupted v1 transaction is discarded instead of being
            # replayed into a v2 snapshot.
            store.pending_path.write_text(json.dumps({"rows": [legacy_body]}))
            store.pending_path.chmod(0o600)

            self.assertTrue(store.replay())

            self.assertEqual(store.records_path.read_bytes(), b"")
            self.assertFalse(store.pending_path.exists())
            migrated = store.load_private_state()
            self.assertEqual(migrated["cursors"], {
                definition.source.source_id: {"inode": 10, "offset": 20},
            })
            self.assertTrue(migrated["quotaState"]["pemRecoveryRequired"])
            self.assertEqual(
                migrated["quotaState"]["redactionVersion"],
                "monitor-log-redaction-v2",
            )
            resumed = pipeline_for(
                definition,
                ["RkZHSA==", "-----END RSA PRIVATE KEY-----", "recovered"],
                prior=migrated["quotaState"],
            )
            self.assertEqual(
                [row["message"] for row in resumed["records"]], ["recovered"]
            )

    def test_record_count_retention_is_bounded_and_reports_drops(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            limits = PipelineLimits(
                max_events_per_source_per_window=200,
                max_events_global_per_window=200,
            )
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid(),
                max_records=100, pipeline_limits=limits,
            )
            pipeline = pipeline_for(
                definition, [f"event {index}" for index in range(105)], limits=limits
            )
            acquired = acquisition()
            acquired["cursor"] = {"inode": 11, "offset": 999}
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            result = store.commit(
                pipeline["records"], status,
                {definition.source.source_id: acquired["cursor"]},
                pipeline["quotaState"], NOW,
            )
            self.assertEqual(result["stored"], 100)
            self.assertEqual(result["retentionDropped"], 5)
            records = store.load_records()
            self.assertEqual(records[0]["message"], "event 5")
            self.assertEqual(records[-1]["message"], "event 104")

    def test_crash_after_public_log_write_replays_without_duplicate_and_then_advances_cursor(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(definition, ["one", "two"])
            acquired = acquisition()
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            original = log_store._atomic_write_bytes

            def fail_status(path, payload, mode, expected_uid):
                if path == store.status_path:
                    raise OSError("injected status publication failure")
                return original(path, payload, mode, expected_uid)

            with mock.patch.object(log_store, "_atomic_write_bytes", side_effect=fail_status):
                with self.assertRaises(OSError):
                    store.commit(
                        pipeline["records"], status,
                        {definition.source.source_id: acquired["cursor"]},
                        pipeline["quotaState"], NOW,
                    )
            self.assertTrue(store.pending_path.is_file())
            self.assertEqual(len(store.load_records()), 2)
            self.assertFalse(store.private_state_path.exists())

            self.assertTrue(store.replay())
            self.assertFalse(store.pending_path.exists())
            self.assertEqual(len(store.load_records()), 2)
            self.assertEqual(
                store.load_private_state()["cursors"][definition.source.source_id],
                acquired["cursor"],
            )
            self.assertFalse(store.replay())

    def test_crash_after_status_before_state_is_also_replayable(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(definition, ["one"])
            acquired = acquisition()
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            original = log_store._atomic_write_bytes

            def fail_state(path, payload, mode, expected_uid):
                if path == store.private_state_path:
                    raise OSError("injected private state failure")
                return original(path, payload, mode, expected_uid)

            with mock.patch.object(log_store, "_atomic_write_bytes", side_effect=fail_state):
                with self.assertRaises(OSError):
                    store.commit(
                        pipeline["records"], status,
                        {definition.source.source_id: acquired["cursor"]},
                        pipeline["quotaState"], NOW,
                    )
            self.assertTrue(store.pending_path.is_file())
            self.assertEqual(store.load_status_document(), status)
            self.assertFalse(store.private_state_path.exists())
            store.replay()
            self.assertEqual(store.load_private_state()["quotaState"], pipeline["quotaState"])

    def test_reviewed_source_changes_migrate_state_and_replay_old_pending_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "export"
            original_definition = file_definition("file:original")
            replacement_definition = file_definition("file:replacement")
            original_store = GenericLogStore(
                root, [original_definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(original_definition, ["before config change"])
            acquired = acquisition()
            status = original_store.build_status_document(
                NOW, {original_definition.source.source_id: acquired}, pipeline["sources"]
            )
            original_write = log_store._atomic_write_bytes

            def fail_status(path, payload, mode, expected_uid):
                if path == original_store.status_path:
                    raise OSError("leave an old-config pending transaction")
                return original_write(path, payload, mode, expected_uid)

            with mock.patch.object(log_store, "_atomic_write_bytes", side_effect=fail_status):
                with self.assertRaises(OSError):
                    original_store.commit(
                        pipeline["records"], status,
                        {original_definition.source.source_id: acquired["cursor"]},
                        pipeline["quotaState"], NOW,
                    )

            replacement_store = GenericLogStore(
                root, [replacement_definition], expected_uid=os.getuid()
            )
            self.assertTrue(replacement_store.replay())
            migrated = replacement_store.load_private_state()
            self.assertEqual(migrated["cursors"], {"file:replacement": {}})
            self.assertEqual(migrated["quotaState"]["admittedGlobal"], 1)

            next_pipeline = pipeline_for(
                replacement_definition,
                ["after config change"],
                prior=migrated["quotaState"],
            )
            next_acquired = acquisition()
            next_acquired["cursor"] = {"inode": 12, "offset": 30}
            next_status = replacement_store.build_status_document(
                NOW,
                {replacement_definition.source.source_id: next_acquired},
                next_pipeline["sources"],
            )
            replacement_store.commit(
                next_pipeline["records"], next_status,
                {replacement_definition.source.source_id: next_acquired["cursor"]},
                next_pipeline["quotaState"], NOW,
            )
            persisted = replacement_store.load_private_state()
            self.assertEqual(persisted["cursors"], {
                "file:replacement": {"inode": 12, "offset": 30},
            })
            self.assertEqual(len(replacement_store.load_records()), 2)

    def test_pending_divergence_and_malformed_state_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(definition, ["expected"])
            acquired = acquisition()
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            original = log_store._atomic_write_bytes

            def fail_status(path, payload, mode, expected_uid):
                if path == store.status_path:
                    raise OSError("stop after public records")
                return original(path, payload, mode, expected_uid)

            with mock.patch.object(log_store, "_atomic_write_bytes", side_effect=fail_status):
                with self.assertRaises(OSError):
                    store.commit(
                        pipeline["records"], status,
                        {definition.source.source_id: acquired["cursor"]},
                        pipeline["quotaState"], NOW,
                    )
            divergent = pipeline_for(definition, ["different"])["records"]
            store.records_path.write_bytes(b"".join(log_store._record_lines(divergent)))
            store.records_path.chmod(0o640)
            with self.assertRaises(LogStoreError):
                store.replay()
            self.assertTrue(store.pending_path.exists())

            store.pending_path.write_text('{"rawToken":"must-remain"}')
            store.pending_path.chmod(0o600)
            with self.assertRaises(LogStoreError):
                store.replay()
            self.assertIn("must-remain", store.pending_path.read_text())

    def test_source_failures_retain_last_success_and_account_all_drops(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            first_pipeline = pipeline_for(definition, ["ok"])
            first_acquisition = acquisition()
            first_status = store.build_status_document(
                NOW, {definition.source.source_id: first_acquisition},
                first_pipeline["sources"],
            )
            store.commit(
                first_pipeline["records"], first_status,
                {definition.source.source_id: first_acquisition["cursor"]},
                first_pipeline["quotaState"], NOW,
            )

            later = NOW + dt.timedelta(minutes=2)
            failed_pipeline = pipeline_for(definition, [], later)
            failed_acquisition = acquisition(
                status="permission_denied", dropped=3, error="permission_denied"
            )
            failed_acquisition["cursor"] = first_acquisition["cursor"]
            failed_status = store.build_status_document(
                later, {definition.source.source_id: failed_acquisition},
                failed_pipeline["sources"],
            )
            row = failed_status["sources"][0]
            self.assertEqual(row["status"], "permission_denied")
            self.assertEqual(row["lastSuccessAt"], first_status["generatedAt"])
            self.assertEqual(row["droppedLines"], 3)
            self.assertEqual(row["dropped"]["acquisition"], 3)

    def test_status_and_private_state_contracts_reject_mismatched_sources_and_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            definition = file_definition()
            store = GenericLogStore(
                Path(temporary) / "export", [definition], expected_uid=os.getuid()
            )
            pipeline = pipeline_for(definition, ["ok"])
            acquired = acquisition()
            status = store.build_status_document(
                NOW, {definition.source.source_id: acquired}, pipeline["sources"]
            )
            with self.assertRaises(ValueError):
                store.commit(
                    pipeline["records"], status,
                    {definition.source.source_id: acquired["cursor"]},
                    pipeline["quotaState"], NOW + dt.timedelta(seconds=1),
                )
            with self.assertRaises(ValueError):
                store.commit(
                    pipeline["records"], status, {}, pipeline["quotaState"], NOW,
                )


if __name__ == "__main__":
    unittest.main()
