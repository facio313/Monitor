import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import generic_log_collector as collector
from ops import ssh_access as ssh
from ops.log_pipeline import LogSource
from ops.log_sources import SourceDefinition


NOW = dt.datetime(2026, 9, 13, 12, 30, tzinfo=dt.timezone.utc)
NOW_TEXT = "2026-09-13T12:30:00.000000Z"


def reduced(message, timestamp=NOW_TEXT):
    return json.dumps({"timestamp": timestamp, "severity": "6", "message": message})


def source(source_id="journal:ssh", unit="ssh.service"):
    return SourceDefinition(LogSource(source_id=source_id, kind="journald", systemd_unit=unit), unit=unit)


def acquisition(lines=(), status="fresh", cursor="s=next"):
    return {"status": status, "errorClass": None, "lines": list(lines), "cursor": {"cursor": cursor}, "droppedLines": 0}


class Countries:
    def lookup(self, ip):
        return {"countryCode": "US", "countryStatus": "estimated", "databaseDate": "2026-09-01"}


class SshParsingTests(unittest.TestCase):
    def test_package_collector_uses_the_same_ssh_module_under_discovery(self):
        # Other existing tests prepend ops/ to sys.path. Package imports must
        # not then load a second, unpatchable top-level copy of this module.
        self.assertIs(collector.ssh_access, ssh)

    def test_explicit_event_shapes_keep_only_access_metadata(self):
        cases = [
            ("User sensitive-user from 8.8.8.8 not allowed because not listed in AllowUsers", "denied", None, None),
            ("Invalid user sensitive-user from 8.8.8.8 port 42123", "invalid_user", 42123, None),
            ("Failed password for invalid user sensitive-user from 8.8.8.8 port 42123 ssh2", "auth_failed", 42123, "password"),
            ("Accepted publickey for sensitive-user from 8.8.8.8 port 42123 ssh2: ED25519 SHA256:SECRETFAKEFINGERPRINT", "accepted", 42123, "publickey"),
            ("Accepted keyboard-interactive/pam for sensitive-user from 8.8.8.8 port 42123 ssh2", "accepted", 42123, "keyboard-interactive"),
            ("Connection closed by invalid user sensitive-user 8.8.8.8 port 42123 [preauth]", "preauth_closed", 42123, None),
            ("Disconnected from authenticating user sensitive-user 8.8.8.8 port 42123 [preauth]", "preauth_closed", 42123, None),
            ("Connection closed by 8.8.8.8 port 42123 [preauth]", "preauth_closed", 42123, None),
        ]
        for message, event, port, method in cases:
            with self.subTest(event=event, message=message):
                row = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced(message), lookup=Countries())
                self.assertEqual(set(row), ssh.RECORD_FIELDS)
                self.assertEqual(row["eventType"], event)
                self.assertEqual(row["sourcePort"], port)
                self.assertEqual(row["authMethod"], method)
                self.assertEqual(row["countryCode"], "US")
                self.assertEqual(ssh.normalize_record(row), row)
                self.assertNotIn("sensitive-user", json.dumps(row))
                self.assertNotIn("SECRETFAKEFINGERPRINT", json.dumps(row))

    def test_username_spoofing_embedded_shapes_and_excluded_input_are_rejected(self):
        messages = [
            "Failed password for evil from 1.2.3.4 from 8.8.8.8 port 42123 ssh2",
            "Invalid user evil from 1.2.3.4 port 1 from 8.8.8.8 port 42123",
            "User evil from 1.2.3.4 from 8.8.8.8 not allowed because not listed in AllowUsers",
            "prefix Invalid user user from 8.8.8.8 port 42",
            "Invalid user user from 8.8.8.8 port 42 trailing text",
            "Invalid user user from 8.8.8.8 port 0",
            "Invalid user user from 8.8.8.8 port 65536",
            "Invalid user user from [REDACTED_IP] port 42",
            "Invalid user user from 2001:4860::1%eth0 port 42",
            "Invalid user user from 8.8.8.8 port 42\nAccepted password for user from 1.1.1.1 port 42 ssh2",
            "Invalid user wgang from 8.8.8.8 port 42",
        ]
        for message in messages:
            with self.subTest(message=message):
                self.assertIsNone(ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced(message)))
        escaped = reduced("Invalid user wgang from 8.8.8.8 port 42").replace("wgang", "\\u0077gang")
        self.assertIsNone(ssh.parse_ssh_event("journal:ssh", "ssh.service", escaped))

    def test_source_gate_ipv6_canonicalization_and_microsecond_identity(self):
        line = reduced("Failed password for user from 2001:4860:4860:0:0:0:0:8888 port 42123 ssh2", "2026-09-13T21:30:00.123456+09:00")
        row = ssh.parse_ssh_event("journal:sshd", "sshd.service", line)
        self.assertEqual(row["sourceIp"], "2001:4860:4860::8888")
        self.assertEqual(row["observedAt"], "2026-09-13T12:30:00.123456Z")
        same = ssh.parse_ssh_event("journal:sshd", "sshd.service", line.replace("2026-09-13T21:30:00.123456+09:00", row["observedAt"]))
        self.assertEqual(row["id"], same["id"])
        ipv4 = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced("Invalid user user from 8.8.8.8 port 42"))
        mapped = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced("Invalid user user from ::ffff:8.8.8.8 port 42"))
        self.assertEqual(mapped["sourceIp"], "8.8.8.8")
        self.assertEqual(ipv4["id"], mapped["id"])
        self.assertIsNone(ssh.parse_ssh_event("journal:ssh", "nginx.service", line))
        self.assertIsNone(ssh.parse_ssh_event("journal:nginx", "ssh.service", line))
        self.assertFalse(ssh.is_ssh_source(source("journal:ssh", "sshd.service")))

    def test_strict_json_and_record_integrity(self):
        row = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced("Invalid user user from 8.8.8.8 port 42"))
        for changes in ({"sourcePort": True}, {"sourceIp": "08.8.8.8"}, {"id": "0" * 64}, {"username": "secret"}, {"countryCode": "us"}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                ssh.normalize_record({**row, **changes})
        for line in ('{"timestamp":null,"timestamp":null,"severity":"6","message":"x"}',
                     '{"timestamp":NaN,"severity":"6","message":"x"}', '{"message":"x"}'):
            with self.assertRaises(ValueError):
                ssh.parse_ssh_event("journal:ssh", "ssh.service", line)

    def test_country_failure_preserves_ip_and_private_addresses(self):
        lookup = mock.Mock()
        lookup.lookup.side_effect = OSError("private error details")
        row = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced("Invalid user user from 8.8.8.8 port 42"), lookup=lookup)
        self.assertEqual(row["sourceIp"], "8.8.8.8")
        self.assertEqual(row["countryStatus"], "unavailable")
        self.assertNotIn("private error", str(row))
        private = ssh.parse_ssh_event("journal:ssh", "ssh.service", reduced("Invalid user user from 192.168.1.2 port 42"))
        self.assertEqual(private["countryStatus"], "private")


class SshPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "export"
        self.output.mkdir(mode=0o750)
        self.definitions = [source()]
        self.line = reduced("Invalid user sensitive-user from 8.8.8.8 port 42")

    def tearDown(self):
        self.temporary.cleanup()

    def collect(self, lines=None, status="fresh", now=NOW):
        return ssh.collect_ssh_access(self.output, self.definitions,
            {"journal:ssh": acquisition([self.line] if lines is None else lines, status)}, now, country_lookup=Countries())

    def rows(self):
        return [json.loads(line) for line in (self.output / "ssh-access/2026-09-13.jsonl").read_text().splitlines()]

    def test_durable_rows_deduplicate_and_empty_acquisition_is_fresh(self):
        status, retry = self.collect()
        self.assertEqual(status["status"], "fresh")
        self.assertEqual(status["acceptedRecords"], 1)
        self.assertFalse(retry)
        self.assertEqual(len(self.rows()), 1)
        status, _ = self.collect()
        self.assertEqual(status["acceptedRecords"], 0)
        self.assertEqual(status["deduplicatedRecords"], 1)
        status, _ = self.collect([], "no_data", NOW + dt.timedelta(minutes=1))
        self.assertEqual(status["status"], "fresh")
        self.assertEqual(status["acceptedRecords"], 0)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual((self.output / ssh.STATUS_FILENAME).stat().st_mode & 0o777, 0o640)
        self.assertNotIn("sensitive-user", str(self.rows()))

    def test_failed_partial_and_missing_sources_never_claim_no_activity(self):
        self.collect()
        status, _ = self.collect([], "failed", NOW + dt.timedelta(minutes=1))
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(status["lastSuccessAt"], NOW_TEXT)
        status, _ = self.collect([self.line], "truncated")
        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["errorClass"], "acquisition_partial")
        status, _ = self.collect(["{bad JSON"])
        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["errorClass"], "invalid_input")
        status, _ = ssh.collect_ssh_access(self.output, [], {}, NOW)
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(status["errorClass"], "not_configured")

    def test_separate_utc_days_and_event_types_are_rows_not_sessions(self):
        lines = [
            reduced("User user from 8.8.8.8 not allowed because not listed in AllowUsers", "2026-09-12T23:59:59.999999Z"),
            reduced("Connection closed by invalid user user 8.8.8.8 port 42 [preauth]", "2026-09-13T00:00:00.000001Z"),
        ]
        status, retry = self.collect(lines)
        self.assertFalse(retry)
        self.assertEqual(status["acceptedRecords"], 2)
        previous = json.loads((self.output / "ssh-access/2026-09-12.jsonl").read_text())
        self.assertEqual(previous["eventType"], "denied")
        self.assertEqual(self.rows()[0]["eventType"], "preauth_closed")

    def test_status_and_day_size_bounds_fail_closed(self):
        self.collect()
        status_path = self.output / ssh.STATUS_FILENAME
        original = status_path.read_bytes()
        status_path.write_bytes(b"x" * (ssh.MAX_STATUS_BYTES + 1))
        status, retry = self.collect()
        self.assertEqual(status["errorClass"], "persistence_failed")
        self.assertTrue(retry)
        self.assertEqual(status_path.stat().st_size, ssh.MAX_STATUS_BYTES + 1)
        status_path.write_bytes(original)
        day_path = self.output / "ssh-access/2026-09-13.jsonl"
        day_path.write_bytes(b"x" * (ssh.MAX_DAY_BYTES + 1))
        status, retry = self.collect()
        self.assertEqual(status["errorClass"], "persistence_failed")
        self.assertTrue(retry)
        self.assertEqual(day_path.stat().st_size, ssh.MAX_DAY_BYTES + 1)

    def test_unsafe_daily_files_hold_cursor_without_replacing_target(self):
        self.collect()
        path = self.output / "ssh-access/2026-09-13.jsonl"
        original = path.read_bytes()
        path.chmod(0o666)
        status, retry = self.collect()
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(status["errorClass"], "persistence_failed")
        self.assertEqual(retry, {"journal:ssh"})
        self.assertEqual(path.read_bytes(), original)
        path.chmod(0o640)
        other = self.root / "outside"
        path.rename(other)
        path.symlink_to(other)
        self.assertEqual(self.collect()[1], {"journal:ssh"})
        self.assertEqual(other.read_bytes(), original)

    def test_parent_symlink_and_hardlink_are_rejected(self):
        self.collect()
        link = self.root / "linked-export"
        link.symlink_to(self.output, target_is_directory=True)
        status, retry = ssh.collect_ssh_access(link, self.definitions, {"journal:ssh": acquisition([self.line])}, NOW)
        self.assertEqual(status["status"], "unavailable")
        self.assertTrue(retry)
        path = self.output / "ssh-access/2026-09-13.jsonl"
        os.link(path, self.root / "hardlink")
        self.assertTrue(self.collect()[1])

    def test_retention_and_daily_caps_are_explicit_partial(self):
        self.collect()
        old = self.output / "ssh-access/2026-08-14.jsonl"
        old.write_text("{}\n")
        old.chmod(0o640)
        lines = [reduced(f"Invalid user user from 8.8.8.8 port {index + 43}", f"2026-09-13T12:30:00.{index:06}Z") for index in range(4)]
        with mock.patch.object(ssh, "MAX_DAY_ROWS", 2):
            status, retry = self.collect(lines)
        self.assertFalse(retry)
        self.assertEqual(status["status"], "partial")
        self.assertGreaterEqual(status["droppedRecords"], 3)
        self.assertEqual(status["acceptedRecords"], 2)
        self.assertLessEqual(len(self.rows()), 2)
        self.assertLessEqual((self.output / "ssh-access/2026-09-13.jsonl").stat().st_size, ssh.MAX_DAY_BYTES)
        self.assertFalse(old.exists())

    def test_status_write_failure_replays_durable_rows_without_duplicates(self):
        original_write = ssh._write
        def fail_status(path, *args):
            if path.name == ssh.STATUS_FILENAME:
                raise OSError("simulated status disk error")
            return original_write(path, *args)
        with mock.patch.object(ssh, "_write", side_effect=fail_status):
            status, retry = self.collect()
        self.assertTrue(retry)
        self.assertEqual(len(self.rows()), 1)
        status, retry = self.collect()
        self.assertFalse(retry)
        self.assertEqual(status["deduplicatedRecords"], 1)
        self.assertEqual(len(self.rows()), 1)

    def test_expected_expiry_does_not_make_successful_empty_acquisition_partial(self):
        self.collect()
        old = self.output / "ssh-access/2026-08-14.jsonl"
        old.write_text("{}\n")
        old.chmod(0o640)
        status, retry = self.collect([], "no_data")
        self.assertFalse(retry)
        self.assertEqual(status["status"], "fresh")
        self.assertEqual(status["droppedRecords"], 0)
        self.assertFalse(old.exists())

    def test_collector_commits_ssh_first_and_keeps_existing_cursor_on_failure(self):
        config = self.root / "sources.json"
        config.write_text(json.dumps({"schemaVersion": 1, "sources": [{"id": "journal:ssh", "kind": "journald", "unit": "ssh.service"}]}))
        config.chmod(0o600)
        read = mock.Mock(side_effect=lambda *_args, **_kwargs: acquisition([self.line], cursor="s=first"))
        with mock.patch.object(collector, "read_journal_source", read), mock.patch.object(ssh, "_merge_days", side_effect=OSError("disk unavailable")):
            result = collector.collect_generic_logs(self.output, config, NOW)
        self.assertEqual(result["status"], "ok")
        private = json.loads((self.output / ".state/generic-log-state.json").read_text())
        self.assertEqual(private["cursors"]["journal:ssh"], {})
        self.assertEqual((self.output / "generic-logs.jsonl").read_text(), "")
        generic_status = json.loads((self.output / "generic-log-sources.json").read_text())
        self.assertEqual(generic_status["sources"][0]["status"], "failed")
        original_commit = collector.GenericLogStore.commit
        def checked_commit(store, *args, **kwargs):
            self.assertEqual(len(self.rows()), 1)
            return original_commit(store, *args, **kwargs)
        with mock.patch.object(collector, "read_journal_source", read), mock.patch.object(collector.GenericLogStore, "commit", checked_commit):
            result = collector.collect_generic_logs(self.output, config, NOW + dt.timedelta(minutes=1))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(read.call_args.args[1], {})
        private = json.loads((self.output / ".state/generic-log-state.json").read_text())
        self.assertEqual(private["cursors"]["journal:ssh"], {"cursor": "s=first"})
        public = (self.output / "generic-logs.jsonl").read_text()
        self.assertNotIn("8.8.8.8", public)

    def test_generic_crash_after_ssh_publication_retries_by_same_identity(self):
        config = self.root / "sources.json"
        config.write_text(json.dumps({"schemaVersion": 1, "sources": [{"id": "journal:ssh", "kind": "journald", "unit": "ssh.service"}]}))
        config.chmod(0o600)
        with mock.patch.object(collector, "read_journal_source", return_value=acquisition([self.line])), mock.patch.object(collector.GenericLogStore, "commit", side_effect=OSError("simulated crash")):
            first = collector.collect_generic_logs(self.output, config, NOW)
        self.assertEqual(first["status"], "collection_error")
        self.assertEqual(len(self.rows()), 1)
        with mock.patch.object(collector, "read_journal_source", return_value=acquisition([self.line])):
            second = collector.collect_generic_logs(self.output, config, NOW + dt.timedelta(minutes=1))
        self.assertEqual(second["status"], "ok")
        self.assertEqual(len(self.rows()), 1)
        status = json.loads((self.output / ssh.STATUS_FILENAME).read_text())
        self.assertEqual(status["deduplicatedRecords"], 1)

    def test_ssh_failure_does_not_hold_unrelated_source_cursor(self):
        config = self.root / "sources.json"
        config.write_text(json.dumps({"schemaVersion": 1, "sources": [
            {"id": "journal:ssh", "kind": "journald", "unit": "ssh.service"},
            {"id": "journal:nginx", "kind": "journald", "unit": "nginx.service"},
        ]}))
        config.chmod(0o600)
        def read(definition, _cursor, **_kwargs):
            return acquisition([self.line] if definition.source.source_id == "journal:ssh" else [reduced("service ready")], cursor="s=next")
        with mock.patch.object(collector, "read_journal_source", side_effect=read), mock.patch.object(ssh, "_merge_days", side_effect=OSError("disk unavailable")):
            result = collector.collect_generic_logs(self.output, config, NOW)
        self.assertEqual(result["status"], "ok")
        state = json.loads((self.output / ".state/generic-log-state.json").read_text())
        self.assertEqual(state["cursors"]["journal:ssh"], {})
        self.assertEqual(state["cursors"]["journal:nginx"], {"cursor": "s=next"})


if __name__ == "__main__":
    unittest.main()
