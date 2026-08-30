import datetime as dt
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import infrastructure_ledger as ledger  # noqa: E402


def localized(ko="값", en="Value"):
    return {"ko": ko, "en": en}


def event(**changes):
    value = {
        "id": "event.alpha.1",
        "itemKey": "item.alpha",
        "revision": 1,
        "occurredAt": "2026-08-29T01:00:00Z",
        "recordedAt": "2026-08-29T02:00:00Z",
        "category": "security",
        "workType": "audit",
        "status": "pending",
        "priority": "high",
        "confidence": "current-state",
        "verification": "verified",
        "applicability": "applicable",
        "impact": "none",
        "sensitivity": "internal",
        "csfFunctions": ["identify"],
        "title": localized("방화벽 점검", "Firewall review"),
        "summary": localized("안전한 요약", "Safe summary"),
        "rationale": localized("노출 확인", "Establish exposure"),
        "details": localized("고정 스키마", "Fixed schema"),
        "outcome": localized("후속 검토", "Follow-up review"),
        "nextAction": localized("승인 후 적용", "Apply after approval"),
        "actor": "codex",
        "scope": ["host"],
        "evidence": [{
            "kind": "runtime",
            "reference": "runtime:firewall-summary",
            "observedAt": "2026-08-29T01:00:00Z",
            "note": localized("비밀 없는 근거", "Credential-free evidence"),
        }],
        "referenceIds": ["nist-csf-2"],
        "relatedIds": [],
        "supersedes": None,
        "dueAt": None,
        "recurrence": None,
    }
    value.update(changes)
    return value


def document(events=None):
    return {
        "schemaVersion": 1,
        "updatedAt": "2026-08-30T02:00:00Z",
        "coverage": {
            "from": None,
            "through": "2026-08-30T02:00:00Z",
            "sources": [{
                "id": "runtime-audit",
                "label": localized("현재 상태 감사", "Current-state audit"),
                "from": "2026-08-29T01:00:00Z",
                "through": "2026-08-30T02:00:00Z",
            }],
            "limitations": [localized("보존 전 기록은 복원 불가", "Pre-retention records are unavailable")],
        },
        "references": [{
            "id": "nist-csf-2",
            "title": "Cybersecurity Framework 2.0",
            "publisher": "NIST",
            "url": "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
            "publishedAt": None,
            "accessedAt": "2026-08-30T01:00:00Z",
        }],
        "entries": events if events is not None else [event()],
    }


class InfrastructureLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.private.chmod(0o700)
        self.public = self.root / "export" / "infrastructure-ledger.json"
        self.public.parent.mkdir(mode=0o750)
        self.public.parent.chmod(0o750)
        self.seed = self.root / "seed.json"
        self.uid = os.geteuid()
        self.gid = os.getegid()
        now_patch = mock.patch.object(
            ledger,
            "_utc_now",
            return_value=dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc),
        )
        now_patch.start()
        self.addCleanup(now_patch.stop)

    def write_json(self, path, value, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)

    def sync(self, value=None):
        self.write_json(self.seed, value if value is not None else document())
        return ledger.sync_seed(
            self.seed,
            self.private,
            self.public,
            private_uid=self.uid,
            private_gid=self.gid,
            public_gid=self.gid,
        )

    def test_sync_is_idempotent_append_only_and_publishes_safe_modes(self):
        self.assertEqual(self.sync(), (1, 1))
        self.assertEqual(self.sync(), (0, 1))
        canonical_lines = (self.private / "events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(canonical_lines), 1)
        self.assertEqual(stat.S_IMODE((self.private / "events.jsonl").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.private / "catalog.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o640)
        published = json.loads(self.public.read_text(encoding="utf-8"))
        self.assertEqual([item["id"] for item in published["entries"]], ["event.alpha.1"])

    def test_sync_monotonically_extends_an_existing_coverage_source(self):
        self.assertEqual(self.sync(), (1, 1))
        extended = document()
        extended["updatedAt"] = "2026-08-30T03:00:00Z"
        extended["coverage"]["through"] = "2026-08-30T03:00:00Z"
        extended["coverage"]["sources"][0]["through"] = "2026-08-30T03:00:00Z"
        self.assertEqual(self.sync(extended), (0, 1))
        published = json.loads(self.public.read_text(encoding="utf-8"))
        self.assertEqual(published["coverage"]["through"], "2026-08-30T03:00:00.000Z")
        self.assertEqual(
            published["coverage"]["sources"][0]["through"],
            "2026-08-30T03:00:00.000Z",
        )

    def test_append_revision_updates_catalog_and_public_snapshot(self):
        self.sync()
        second = event(
            id="event.alpha.2",
            revision=2,
            occurredAt="2026-08-31T01:00:00Z",
            recordedAt="2026-08-31T02:00:00Z",
            status="completed",
            supersedes="event.alpha.1",
        )
        input_path = self.root / "event.json"
        self.write_json(input_path, second)
        self.assertTrue(ledger.append_entry(
            input_path,
            self.private,
            self.public,
            private_uid=self.uid,
            private_gid=self.gid,
            public_gid=self.gid,
        ))
        self.assertFalse(ledger.append_entry(
            input_path,
            self.private,
            self.public,
            private_uid=self.uid,
            private_gid=self.gid,
            public_gid=self.gid,
        ))
        published = json.loads(self.public.read_text(encoding="utf-8"))
        self.assertEqual(published["updatedAt"], "2026-08-31T02:00:00.000Z")
        self.assertEqual([item["id"] for item in published["entries"]], ["event.alpha.2", "event.alpha.1"])
        self.assertEqual(len((self.private / "events.jsonl").read_text(encoding="utf-8").splitlines()), 2)

    def test_validation_rejects_secrets_forbidden_scope_and_unverified_completion(self):
        unsafe = event(details=localized("token=unsafe-value", "Unsafe"))
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(document([unsafe]))
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(document([event(scope=["wgang"])]))
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(document([event(status="completed", evidence=[])]))
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(document([event(details=localized("client 203.0.113.7", "Unsafe"))]))
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(document([event(details=localized("operator@example.test", "Unsafe"))]))

    def test_validation_rejects_future_and_incoherent_coverage(self):
        with mock.patch.object(
            ledger,
            "_utc_now",
            return_value=dt.datetime(2026, 8, 30, 3, tzinfo=dt.timezone.utc),
        ):
            future = document()
            future["updatedAt"] = "2026-08-31T03:00:00Z"
            future["coverage"]["through"] = "2026-08-31T03:00:00Z"
            with self.assertRaises(ledger.LedgerError):
                ledger.validate_document(future)

        inverted = document()
        inverted["coverage"]["from"] = "2026-08-31T03:00:00Z"
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_document(inverted)

    def test_mutation_rejects_broadly_writable_input(self):
        self.write_json(self.seed, document(), mode=0o666)
        with self.assertRaises(ledger.LedgerError):
            ledger.sync_seed(
                self.seed,
                self.private,
                self.public,
                private_uid=self.uid,
                private_gid=self.gid,
                public_gid=self.gid,
            )

    def test_conflicting_seed_id_does_not_overwrite_canonical_history(self):
        self.sync()
        conflicting = event(summary=localized("다른 내용", "Different content"))
        with self.assertRaises(ledger.LedgerError):
            self.sync(document([conflicting]))
        canonical = json.loads((self.private / "events.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(canonical["summary"]["en"], "Safe summary")

    def test_interrupted_publication_recovers_without_duplicate_events(self):
        self.sync()
        second = event(
            id="event.beta.1",
            itemKey="item.beta",
            occurredAt="2026-08-30T01:00:00Z",
            recordedAt="2026-08-30T02:00:00Z",
            category="backup-recovery",
            status="recommended",
            confidence="recommendation",
            verification="unverified",
            applicability="needs-assessment",
        )
        next_seed = document([event(), second])
        self.write_json(self.seed, next_seed)
        original = ledger._atomic_json
        calls = 0

        def fail_public(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if path == self.public:
                raise ledger.LedgerError("simulated publication interruption")
            return original(path, *args, **kwargs)

        with mock.patch.object(ledger, "_atomic_json", side_effect=fail_public):
            with self.assertRaises(ledger.LedgerError):
                ledger.sync_seed(
                    self.seed,
                    self.private,
                    self.public,
                    private_uid=self.uid,
                    private_gid=self.gid,
                    public_gid=self.gid,
                )
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.sync(next_seed), (0, 2))
        self.assertEqual(len((self.private / "events.jsonl").read_text(encoding="utf-8").splitlines()), 2)

    def test_interrupted_append_publication_is_republished_on_identical_retry(self):
        self.sync()
        second = event(
            id="event.alpha.2",
            revision=2,
            occurredAt="2026-08-31T01:00:00Z",
            recordedAt="2026-08-31T02:00:00Z",
            status="completed",
            supersedes="event.alpha.1",
        )
        input_path = self.root / "event.json"
        self.write_json(input_path, second)
        original = ledger._atomic_json

        def fail_public(path, *args, **kwargs):
            if path == self.public:
                raise ledger.LedgerError("simulated append publication interruption")
            return original(path, *args, **kwargs)

        with mock.patch.object(ledger, "_atomic_json", side_effect=fail_public):
            with self.assertRaises(ledger.LedgerError):
                ledger.append_entry(
                    input_path,
                    self.private,
                    self.public,
                    private_uid=self.uid,
                    private_gid=self.gid,
                    public_gid=self.gid,
                )

        self.assertEqual(len((self.private / "events.jsonl").read_text(encoding="utf-8").splitlines()), 2)
        self.assertEqual(len(json.loads(self.public.read_text(encoding="utf-8"))["entries"]), 1)
        self.assertFalse(ledger.append_entry(
            input_path,
            self.private,
            self.public,
            private_uid=self.uid,
            private_gid=self.gid,
            public_gid=self.gid,
        ))
        self.assertEqual(len(json.loads(self.public.read_text(encoding="utf-8"))["entries"]), 2)

    def test_refuses_symlinked_seed_and_hardlinked_canonical_stream(self):
        real_seed = self.root / "real-seed.json"
        self.write_json(real_seed, document())
        self.seed.symlink_to(real_seed)
        with self.assertRaises(ledger.LedgerError):
            self.sync()

        self.seed.unlink()
        self.sync()
        os.link(self.private / "events.jsonl", self.private / "second-link")
        with self.assertRaises(ledger.LedgerError):
            ledger.publish(
                self.private,
                self.public,
                private_uid=self.uid,
                private_gid=self.gid,
                public_gid=self.gid,
            )


if __name__ == "__main__":
    unittest.main()
