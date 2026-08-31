import gzip
import importlib.util
import io
import json
import os
import signal
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "state_backup.py"
SPEC = importlib.util.spec_from_file_location("state_backup", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
state_backup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = state_backup
SPEC.loader.exec_module(state_backup)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class StateBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.sources = self.root / "sources"
        self.sources.mkdir(mode=0o700)
        self.backups = self.root / "backups"
        self.backups.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.certificate = self.root / "recipient.crt"
        self.private_key = self.root / "recipient.key"
        self.signer_certificate = self.root / "signer.crt"
        self.signer_private_key = self.root / "signer.key"
        self._create_certificate(
            self.certificate, self.private_key, "monitor-state-backup-recipient"
        )
        self._create_certificate(
            self.signer_certificate,
            self.signer_private_key,
            "monitor-state-backup-pinned-signer",
        )

    def _create_certificate(self, certificate: Path, private_key: Path, common_name: str) -> None:
        subprocess.run(
            [
                shutil.which("openssl") or "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                f"/CN={common_name}",
                "-keyout",
                str(private_key),
                "-out",
                str(certificate),
                "-days",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )
        private_key.chmod(0o600)
        certificate.chmod(0o644)

    def create_backup(
        self,
        source_map: Path,
        archive: Path,
        *,
        confirm_quiesced: bool = False,
    ) -> dict[str, object]:
        return state_backup.create_backup(
            source_map,
            archive,
            self.certificate,
            signer_certificate=self.signer_certificate,
            signer_private_key=self.signer_private_key,
            confirm_quiesced=confirm_quiesced,
        )

    def verify_backup(self, source_map: Path, archive: Path):
        return state_backup.verify_backup(
            source_map,
            archive,
            self.certificate,
            self.private_key,
            self.signer_certificate,
        )

    def write_source(self, name: str, payload: bytes, mode: int = 0o600) -> Path:
        path = self.sources / name
        path.write_bytes(payload)
        path.chmod(mode)
        return path

    def entry(
        self,
        source_id: str,
        kind: str,
        path: Path,
        restore_path: str,
        *,
        mode: int = 0o600,
        max_bytes: int = 1024 * 1024,
    ) -> dict[str, object]:
        return {
            "id": source_id,
            "kind": kind,
            "path": str(path),
            "restorePath": restore_path,
            "uid": self.uid,
            "gid": self.gid,
            "mode": f"{mode:04o}",
            "maxBytes": max_bytes,
        }

    def write_map(
        self,
        entries: list[dict[str, object]],
        name: str = "sources.json",
        *,
        schema_version: int = 1,
    ) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(
                {"schemaVersion": schema_version, "sources": entries},
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def security_family_entry(self, directory: Path) -> dict[str, object]:
        members: list[dict[str, object]] = [
            {
                "id": "api-keys",
                "name": "api-keys.json",
                "kind": "json",
                "mode": "0600",
                "maxBytes": 128 * 1024,
                "required": True,
            }
        ]
        for rotation in range(4):
            name = (
                "application-audit.jsonl"
                if rotation == 0
                else f"application-audit.{rotation}.jsonl"
            )
            members.append(
                {
                    "id": f"audit-{rotation}",
                    "name": name,
                    "kind": "jsonl",
                    "mode": "0600",
                    "maxBytes": 1024 * 1024,
                    "required": False,
                }
            )
        return {
            "id": "application-security",
            "kind": "family",
            "path": str(directory),
            "restorePath": "var/lib/monitor-security",
            "uid": self.uid,
            "gid": self.gid,
            "mode": "0700",
            "members": members,
        }

    def write_security_family_map(
        self,
        directory: Path,
        name: str = "security-sources.json",
    ) -> Path:
        return self.write_map(
            [self.security_family_entry(directory)],
            name,
            schema_version=2,
        )

    def make_wal_database(self) -> tuple[Path, sqlite3.Connection]:
        path = self.sources / "delivery.sqlite"
        previous_umask = os.umask(0o077)
        try:
            writer = sqlite3.connect(path)
            self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
            writer.commit()
            writer.execute("INSERT INTO events(body) VALUES (?)", ("committed-in-wal",))
            writer.commit()
        finally:
            os.umask(previous_umask)
        path.chmod(0o600)
        for suffix in ("-wal", "-shm"):
            companion = Path(f"{path}{suffix}")
            self.assertTrue(companion.exists())
            companion.chmod(0o600)
        return path, writer

    def create_two_json_archive(self) -> tuple[Path, Path, bytes, bytes]:
        first_payload = b'{"value":1, "spacing":"preserved"}\n'
        second_payload = b'{"value":2}\n'
        first = self.write_source("first.json", first_payload)
        second = self.write_source("second.json", second_payload)
        source_map = self.write_map(
            [
                self.entry("first", "json", first, "state/first.json"),
                self.entry("second", "json", second, "state/second.json"),
            ]
        )
        archive = self.backups / "state.cms"
        self.create_backup(source_map, archive)
        return source_map, archive, first_payload, second_payload

    def test_actual_backup_verify_and_clean_host_restore_is_byte_exact(self) -> None:
        json_payload = b'{\n  "state": "exact",\n  "count": 2\n}\n'
        jsonl_payload = b'{"seq":1}\n{"seq":2,"unicode":"\xed\x95\x9c\xea\xb8\x80"}\n'
        json_path = self.write_source("identity.json", json_payload)
        jsonl_path = self.write_source("events.jsonl", jsonl_payload)
        sqlite_path, writer = self.make_wal_database()
        self.addCleanup(writer.close)
        source_map = self.write_map(
            [
                self.entry("identity", "json", json_path, "state/identity.json"),
                self.entry("events", "jsonl", jsonl_path, "state/events.jsonl"),
                self.entry(
                    "delivery",
                    "sqlite",
                    sqlite_path,
                    "state/delivery.sqlite",
                    max_bytes=4 * 1024 * 1024,
                ),
            ]
        )
        archive = self.backups / "state.cms"

        manifest = self.create_backup(source_map, archive)
        verified = self.verify_backup(source_map, archive)

        self.assertEqual(manifest, verified.manifest)
        self.assertEqual(verified.payloads[0], json_payload)
        self.assertEqual(verified.payloads[1], jsonl_payload)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.assertEqual([path.name for path in self.backups.iterdir()], ["state.cms"])
        self.assertEqual(
            sqlite3.connect(":memory:").execute("SELECT 1").fetchone(), (1,)
        )

        restore_root = self.root / "clean-host"
        restore_root.mkdir(mode=0o700)
        result = state_backup.restore_backup(
            source_map,
            archive,
            self.certificate,
            self.private_key,
            self.signer_certificate,
            restore_root,
        )

        self.assertEqual(len(result.targets), 3)
        self.assertEqual(result.preserved, ())
        self.assertEqual((restore_root / "state/identity.json").read_bytes(), json_payload)
        self.assertEqual((restore_root / "state/events.jsonl").read_bytes(), jsonl_payload)
        self.assertEqual(stat.S_IMODE((restore_root / "state").stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((restore_root / "state/identity.json").stat().st_mode), 0o600
        )
        restored_database = sqlite3.connect(restore_root / "state/delivery.sqlite")
        try:
            self.assertEqual(
                restored_database.execute("SELECT body FROM events").fetchall(),
                [("committed-in-wal",)],
            )
            self.assertEqual(restored_database.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
        finally:
            restored_database.close()

        unsafe_root = self.root / "sqlite-sidecar-root"
        unsafe_state = unsafe_root / "state"
        unsafe_state.mkdir(parents=True, mode=0o700)
        unsafe_root.chmod(0o700)
        unsafe_state.chmod(0o700)
        stale_sidecar = unsafe_state / "delivery.sqlite-wal"
        stale_sidecar.write_bytes(b"stale-sidecar")
        stale_sidecar.chmod(0o600)
        with self.assertRaisesRegex(state_backup.StateBackupError, "SQLite.*sidecar"):
            state_backup.restore_backup(
                source_map,
                archive,
                self.certificate,
                self.private_key,
                self.signer_certificate,
                unsafe_root,
            )
        self.assertEqual(list(unsafe_state.iterdir()), [stale_sidecar])
        self.assertFalse((unsafe_root / state_backup.RESTORE_JOURNAL_NAME).exists())

    def test_v2_security_family_preserves_mixed_rotation_presence_on_clean_host(self) -> None:
        security = self.sources / "monitor-security"
        security.mkdir(mode=0o700)
        api_payload = b'{"schemaVersion":1,"keys":[]}\n'
        audit_current = b'{"schemaVersion":1,"sequence":4}\n'
        audit_two = b'{"schemaVersion":1,"sequence":2}\n'
        for name, payload in (
            ("api-keys.json", api_payload),
            ("application-audit.jsonl", audit_current),
            ("application-audit.2.jsonl", audit_two),
        ):
            member = security / name
            member.write_bytes(payload)
            member.chmod(0o600)
        source_map = self.write_security_family_map(security)
        archive = self.backups / "security-family.cms"

        with self.assertRaisesRegex(state_backup.StateBackupError, "confirm-quiesced"):
            self.create_backup(source_map, archive)
        manifest = self.create_backup(source_map, archive, confirm_quiesced=True)
        verified = self.verify_backup(source_map, archive)

        expected_ids = [
            "application-security.api-keys",
            "application-security.audit-0",
            "application-security.audit-2",
        ]
        self.assertEqual(
            [entry["id"] for entry in manifest["sources"]],
            expected_ids,
        )
        self.assertEqual(
            [spec.source_id for spec in verified.plan.sources],
            expected_ids,
        )
        self.assertEqual(
            verified.payloads,
            (api_payload, audit_current, audit_two),
        )

        restore_root = self.root / "security-clean-host"
        restore_root.mkdir(mode=0o700)
        result = state_backup.restore_backup(
            source_map,
            archive,
            self.certificate,
            self.private_key,
            self.signer_certificate,
            restore_root,
        )
        restored = restore_root / "var/lib/monitor-security"
        self.assertEqual(len(result.targets), 3)
        self.assertEqual(
            {path.name for path in restored.iterdir()},
            {
                "api-keys.json",
                "application-audit.jsonl",
                "application-audit.2.jsonl",
            },
        )
        self.assertEqual((restored / "api-keys.json").read_bytes(), api_payload)
        self.assertEqual(
            (restored / "application-audit.jsonl").read_bytes(), audit_current
        )
        self.assertEqual(
            (restored / "application-audit.2.jsonl").read_bytes(), audit_two
        )
        self.assertFalse((restored / "application-audit.1.jsonl").exists())
        self.assertFalse((restored / "application-audit.3.jsonl").exists())
        metadata = restored.lstat()
        self.assertEqual((metadata.st_uid, metadata.st_gid), (self.uid, self.gid))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
        for path in restored.iterdir():
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
        self.assertEqual(
            json.loads((restored / "api-keys.json").read_text(encoding="utf-8")),
            {"schemaVersion": 1, "keys": []},
        )
        self.assertEqual(
            [
                json.loads(line)
                for line in (restored / "application-audit.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ],
            [{"schemaVersion": 1, "sequence": 4}],
        )

    def test_security_family_rejects_concurrent_rotation_and_missing_required_state(self) -> None:
        security = self.sources / "rotating-security"
        security.mkdir(mode=0o700)
        api_path = security / "api-keys.json"
        audit_path = security / "application-audit.jsonl"
        api_path.write_bytes(b'{"schemaVersion":1,"keys":[]}\n')
        audit_path.write_bytes(b'{"schemaVersion":1,"sequence":1}\n')
        api_path.chmod(0o600)
        audit_path.chmod(0o600)
        source_map = self.write_security_family_map(security, "rotating-map.json")
        original_read = state_backup._read_descriptor
        rotated = False

        def rotate_after_api_read(descriptor, expected_size, field):
            nonlocal rotated
            payload = original_read(descriptor, expected_size, field)
            if field == "application-security.api-keys" and not rotated:
                audit_path.rename(security / "application-audit.1.jsonl")
                rotated = True
            return payload

        with mock.patch.object(
            state_backup,
            "_read_descriptor",
            side_effect=rotate_after_api_read,
        ):
            with self.assertRaisesRegex(
                state_backup.StateBackupError,
                "changed .*snapshot",
            ):
                self.create_backup(
                    source_map,
                    self.backups / "rotating.cms",
                    confirm_quiesced=True,
                )
        self.assertFalse((self.backups / "rotating.cms").exists())

        api_path.unlink()
        with self.assertRaisesRegex(
            state_backup.StateBackupError,
            "required family member",
        ):
            self.create_backup(
                source_map,
                self.backups / "missing-required.cms",
                confirm_quiesced=True,
            )

    def test_security_family_rejects_in_place_change_after_an_earlier_capture(self) -> None:
        security = self.sources / "in-place-security"
        security.mkdir(mode=0o700)
        api_path = security / "api-keys.json"
        audit_path = security / "application-audit.jsonl"
        api_path.write_bytes(b'{"version":"old"}\n')
        audit_path.write_bytes(b'{"audit":1}\n')
        api_path.chmod(0o600)
        audit_path.chmod(0o600)
        source_map = self.write_security_family_map(security, "in-place-map.json")
        archive = self.backups / "in-place.cms"
        original_read = state_backup._read_descriptor
        changed = False

        def change_api_after_audit_capture(descriptor, expected_size, field):
            nonlocal changed
            payload = original_read(descriptor, expected_size, field)
            if field == "application-security.audit-0" and not changed:
                replacement = b'{"version":"new"}\n'
                self.assertEqual(len(replacement), len(api_path.read_bytes()))
                api_path.write_bytes(replacement)
                changed = True
            return payload

        with mock.patch.object(
            state_backup,
            "_read_descriptor",
            side_effect=change_api_after_audit_capture,
        ):
            with self.assertRaisesRegex(
                state_backup.StateBackupError,
                "family member (?:changed before|content changed during) final revalidation",
            ):
                self.create_backup(
                    source_map,
                    archive,
                    confirm_quiesced=True,
                )
        self.assertTrue(changed)
        self.assertFalse(archive.exists())

    def test_security_family_rejects_unreviewed_links_and_unsafe_metadata(self) -> None:
        def secure_family(label: str) -> tuple[Path, Path]:
            directory = self.sources / label
            directory.mkdir(mode=0o700)
            api = directory / "api-keys.json"
            api.write_bytes(b'{"schemaVersion":1,"keys":[]}\n')
            api.chmod(0o600)
            return directory, self.write_security_family_map(
                directory, f"{label}-map.json"
            )

        directory, source_map = secure_family("unreviewed-family")
        extra = directory / "unexpected.json"
        extra.write_bytes(b'{}\n')
        extra.chmod(0o600)
        with self.assertRaisesRegex(state_backup.StateBackupError, "unreviewed entry"):
            self.create_backup(
                source_map,
                self.backups / "unreviewed.cms",
                confirm_quiesced=True,
            )

        directory, source_map = secure_family("symlink-family")
        outside = self.write_source("outside-audit.jsonl", b'{"safe":true}\n')
        (directory / "application-audit.jsonl").symlink_to(outside)
        with self.assertRaisesRegex(state_backup.StateBackupError, "metadata is unsafe"):
            self.create_backup(
                source_map,
                self.backups / "symlink-family.cms",
                confirm_quiesced=True,
            )

        directory, source_map = secure_family("hardlink-family")
        audit = directory / "application-audit.jsonl"
        audit.write_bytes(b'{"safe":true}\n')
        audit.chmod(0o600)
        os.link(audit, self.root / "audit-hardlink-copy")
        with self.assertRaisesRegex(state_backup.StateBackupError, "metadata is unsafe"):
            self.create_backup(
                source_map,
                self.backups / "hardlink-family.cms",
                confirm_quiesced=True,
            )

        directory, source_map = secure_family("mode-family")
        audit = directory / "application-audit.jsonl"
        audit.write_bytes(b'{"safe":true}\n')
        audit.chmod(0o644)
        with self.assertRaisesRegex(state_backup.StateBackupError, "metadata is unsafe"):
            self.create_backup(
                source_map,
                self.backups / "mode-family.cms",
                confirm_quiesced=True,
            )

        real, _ = secure_family("real-family")
        linked = self.sources / "linked-family"
        linked.symlink_to(real, target_is_directory=True)
        linked_map = self.write_security_family_map(linked, "linked-family-map.json")
        with self.assertRaisesRegex(state_backup.StateBackupError, "must not contain symlinks"):
            self.create_backup(
                linked_map,
                self.backups / "linked-root.cms",
                confirm_quiesced=True,
            )

    def test_security_family_source_map_rejects_globs_traversal_and_v1_aliases(self) -> None:
        for index, unsafe_name in enumerate(
            ("*.jsonl", "../api-keys.json", "nested/api-keys.json")
        ):
            with self.subTest(name=unsafe_name):
                family = self.security_family_entry(self.sources / f"unused-{index}")
                members = family["members"]
                assert isinstance(members, list)
                members[0]["name"] = unsafe_name
                source_map = self.write_map(
                    [family],
                    f"unsafe-family-name-{index}.json",
                    schema_version=2,
                )
                with self.assertRaisesRegex(
                    state_backup.StateBackupError,
                    "fixed safe filename without a glob",
                ):
                    state_backup.load_source_map(source_map)

        family = self.security_family_entry(self.sources / "v1-family-alias")
        v1_map = self.write_map([family], "v1-family-alias.json")
        with self.assertRaisesRegex(state_backup.StateBackupError, "require.*schemaVersion 2"):
            state_backup.load_source_map(v1_map)

        family = self.security_family_entry(self.sources / "unknown-member")
        members = family["members"]
        assert isinstance(members, list)
        members[0]["unexpected"] = True
        unknown_map = self.write_map(
            [family],
            "unknown-family-member.json",
            schema_version=2,
        )
        with self.assertRaisesRegex(state_backup.StateBackupError, "exactly"):
            state_backup.load_source_map(unknown_map)

        first = self.security_family_entry(self.sources / "duplicate-family-first")
        second = self.security_family_entry(self.sources / "duplicate-family-second")
        second["restorePath"] = "var/lib/monitor-security-second"
        duplicate_family_map = self.write_map(
            [first, second],
            "duplicate-family-id.json",
            schema_version=2,
        )
        with self.assertRaisesRegex(state_backup.StateBackupError, "family ids must be unique"):
            state_backup.load_source_map(duplicate_family_map)

    def test_security_family_tamper_and_stale_absent_destination_fail_closed(self) -> None:
        security = self.sources / "tamper-security"
        security.mkdir(mode=0o700)
        for name, payload in (
            ("api-keys.json", b'{"schemaVersion":1,"keys":[]}\n'),
            ("application-audit.jsonl", b'{"schemaVersion":1,"sequence":1}\n'),
        ):
            path = security / name
            path.write_bytes(payload)
            path.chmod(0o600)
        source_map = self.write_security_family_map(security, "tamper-security-map.json")
        archive = self.backups / "tamper-security.cms"
        self.create_backup(source_map, archive, confirm_quiesced=True)

        tampered = self.backups / "tamper-security-modified.cms"
        ciphertext = bytearray(archive.read_bytes())
        ciphertext[len(ciphertext) // 2] ^= 0x01
        tampered.write_bytes(ciphertext)
        tampered.chmod(0o600)
        clean_root = self.root / "tamper-clean-root"
        clean_root.mkdir(mode=0o700)
        with self.assertRaises(state_backup.StateBackupError):
            state_backup.restore_backup(
                source_map,
                tampered,
                self.certificate,
                self.private_key,
                self.signer_certificate,
                clean_root,
            )
        self.assertEqual(list(clean_root.iterdir()), [])

        stale_root = self.root / "stale-security-root"
        stale_directory = stale_root / "var/lib/monitor-security"
        stale_directory.mkdir(parents=True, mode=0o700)
        stale_root.chmod(0o700)
        (stale_root / "var").chmod(0o700)
        (stale_root / "var/lib").chmod(0o700)
        stale_directory.chmod(0o700)
        stale = stale_directory / "application-audit.1.jsonl"
        stale.write_bytes(b'{"stale":true}\n')
        stale.chmod(0o600)
        with self.assertRaisesRegex(
            state_backup.StateBackupError,
            "member absent from the backup",
        ):
            state_backup.restore_backup(
                source_map,
                archive,
                self.certificate,
                self.private_key,
                self.signer_certificate,
                stale_root,
                replace_existing=True,
                confirm_quiesced=True,
            )
        self.assertEqual(stale.read_bytes(), b'{"stale":true}\n')
        self.assertFalse((stale_root / state_backup.RESTORE_JOURNAL_NAME).exists())

    def test_security_family_subset_sigkill_recovery_restores_old_generation_set(self) -> None:
        security = self.sources / "crash-security"
        security.mkdir(mode=0o700)
        source_payloads = {
            "api-keys.json": b'{"schemaVersion":1,"keys":[{"id":"new"}]}\n',
            "application-audit.2.jsonl": b'{"generation":"new-two"}\n',
        }
        for name, payload in source_payloads.items():
            path = security / name
            path.write_bytes(payload)
            path.chmod(0o600)
        source_map = self.write_security_family_map(security, "crash-security-map.json")
        archive = self.backups / "crash-security.cms"
        self.create_backup(source_map, archive, confirm_quiesced=True)

        restore_root = self.root / "crash-security-root"
        restored = restore_root / "var/lib/monitor-security"
        restored.mkdir(parents=True, mode=0o700)
        restore_root.chmod(0o700)
        (restore_root / "var").chmod(0o700)
        (restore_root / "var/lib").chmod(0o700)
        restored.chmod(0o700)
        old_payloads = {
            "api-keys.json": b'{"schemaVersion":1,"keys":[{"id":"old"}]}\n',
            "application-audit.2.jsonl": b'{"generation":"old-two"}\n',
        }
        for name, payload in old_payloads.items():
            path = restored / name
            path.write_bytes(payload)
            path.chmod(0o600)

        child = f"""
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("state_backup_family_crash_child", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original = module._install_staged_file
def kill_after_install(stage, target):
    original(stage, target)
    os.kill(os.getpid(), signal.SIGKILL)
module._install_staged_file = kill_after_install
module.restore_backup(
    Path({str(source_map)!r}),
    Path({str(archive)!r}),
    Path({str(self.certificate)!r}),
    Path({str(self.private_key)!r}),
    Path({str(self.signer_certificate)!r}),
    Path({str(restore_root)!r}),
    replace_existing=True,
    confirm_quiesced=True,
)
"""
        killed = subprocess.run(
            [sys.executable, "-c", child],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr.decode())
        journal_path = restore_root / state_backup.RESTORE_JOURNAL_NAME
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual(
            [record["id"] for record in journal["records"]],
            ["application-security.api-keys", "application-security.audit-2"],
        )

        recovery = state_backup.recover_restore(
            source_map,
            restore_root,
            confirm_rollback=True,
        )
        self.assertEqual(recovery.action, "rolled-back")
        self.assertFalse(journal_path.exists())
        self.assertEqual(
            {path.name for path in restored.iterdir()},
            set(old_payloads),
        )
        for name, payload in old_payloads.items():
            self.assertEqual((restored / name).read_bytes(), payload)
        self.assertEqual(list(restored.glob("*.restore.tmp-*")), [])
        self.assertEqual(list(restored.glob("*.pre-restore-*")), [])

    @unittest.skipUnless(os.geteuid() == 0, "production ownership recovery requires root")
    def test_root_sigkill_recovery_removes_created_uid_1001_family_directory(self) -> None:
        security = self.sources / "production-owned-security"
        security.mkdir(mode=0o700)
        api = security / "api-keys.json"
        api.write_bytes(b'{"schemaVersion":1,"keys":[]}\n')
        api.chmod(0o600)
        os.chown(api, 1001, 1001)
        os.chown(security, 1001, 1001)
        family = self.security_family_entry(security)
        family["uid"] = 1001
        family["gid"] = 1001
        source_map = self.write_map(
            [family],
            "production-owned-security-map.json",
            schema_version=2,
        )
        archive = self.backups / "production-owned-security.cms"
        self.create_backup(source_map, archive, confirm_quiesced=True)
        restore_root = self.root / "production-clean-root"
        restore_root.mkdir(mode=0o700)

        child = f"""
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("state_backup_root_family_crash", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original = module._install_staged_file
def kill_after_install(stage, target):
    original(stage, target)
    os.kill(os.getpid(), signal.SIGKILL)
module._install_staged_file = kill_after_install
module.restore_backup(
    Path({str(source_map)!r}),
    Path({str(archive)!r}),
    Path({str(self.certificate)!r}),
    Path({str(self.private_key)!r}),
    Path({str(self.signer_certificate)!r}),
    Path({str(restore_root)!r}),
)
"""
        killed = subprocess.run(
            [sys.executable, "-c", child],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr.decode())
        created_family = restore_root / "var/lib/monitor-security"
        self.assertEqual(
            (created_family.lstat().st_uid, created_family.lstat().st_gid),
            (1001, 1001),
        )
        self.assertTrue((restore_root / state_backup.RESTORE_JOURNAL_NAME).exists())

        recovery = state_backup.recover_restore(
            source_map,
            restore_root,
            confirm_rollback=True,
        )
        self.assertEqual(recovery.action, "rolled-back")
        self.assertFalse(created_family.exists())
        self.assertEqual(list(restore_root.iterdir()), [])

    def test_ciphertext_tamper_is_rejected_before_restore(self) -> None:
        source_map, archive, _, _ = self.create_two_json_archive()
        tampered = self.backups / "tampered.cms"
        payload = bytearray(archive.read_bytes())
        payload[len(payload) // 2] ^= 0x01
        tampered.write_bytes(payload)
        tampered.chmod(0o600)
        restore_root = self.root / "restore"
        restore_root.mkdir(mode=0o700)

        with self.assertRaises(state_backup.StateBackupError):
            state_backup.verify_backup(
                source_map,
                tampered,
                self.certificate,
                self.private_key,
                self.signer_certificate,
            )
        with self.assertRaises(state_backup.StateBackupError):
            state_backup.restore_backup(
                source_map,
                tampered,
                self.certificate,
                self.private_key,
                self.signer_certificate,
                restore_root,
            )

        appended = self.backups / "appended.cms"
        appended.write_bytes(archive.read_bytes() + b"trailing-untrusted-data")
        appended.chmod(0o600)
        with self.assertRaises(state_backup.StateBackupError):
            state_backup.verify_backup(
                source_map,
                appended,
                self.certificate,
                self.private_key,
                self.signer_certificate,
            )

        self.assertEqual(list(restore_root.iterdir()), [])

    def test_pinned_external_signer_mismatch_is_rejected(self) -> None:
        source_map, archive, _, _ = self.create_two_json_archive()
        wrong_certificate = self.root / "wrong-signer.crt"
        wrong_private_key = self.root / "wrong-signer.key"
        self._create_certificate(
            wrong_certificate, wrong_private_key, "monitor-state-backup-wrong-signer"
        )

        commands: list[list[str]] = []
        original_run = state_backup._run_openssl

        def record_command(command, payload, **kwargs):
            commands.append(list(command))
            return original_run(command, payload, **kwargs)

        with mock.patch.object(state_backup, "_run_openssl", side_effect=record_command):
            with self.assertRaisesRegex(
                state_backup.StateBackupError, "pinned signer"
            ):
                state_backup.verify_backup(
                    source_map,
                    archive,
                    self.certificate,
                    self.private_key,
                    wrong_certificate,
                )

        verify_commands = [command for command in commands if "-verify" in command]
        self.assertEqual(len(verify_commands), 1)
        self.assertIn("-nointern", verify_commands[0])
        self.assertIn("-certfile", verify_commands[0])

        signer_bundle = self.root / "signer-bundle.crt"
        signer_bundle.write_bytes(
            self.signer_certificate.read_bytes() + wrong_certificate.read_bytes()
        )
        signer_bundle.chmod(0o644)
        with self.assertRaisesRegex(
            state_backup.StateBackupError, "exactly one PEM certificate"
        ):
            state_backup.verify_backup(
                source_map,
                archive,
                self.certificate,
                self.private_key,
                signer_bundle,
            )

    def test_sigkill_restore_is_explicitly_and_idempotently_rolled_back(self) -> None:
        source_map, archive, _, _ = self.create_two_json_archive()
        restore_root = self.root / "crash-root"
        state_directory = restore_root / "state"
        state_directory.mkdir(parents=True, mode=0o700)
        restore_root.chmod(0o700)
        state_directory.chmod(0o700)
        first_target = state_directory / "first.json"
        second_target = state_directory / "second.json"
        first_target.write_bytes(b'{"old":1}\n')
        second_target.write_bytes(b'{"old":2}\n')
        first_target.chmod(0o600)
        second_target.chmod(0o600)

        child = f"""
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("state_backup_crash_child", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original = module._install_staged_file
def kill_after_install(stage, target):
    original(stage, target)
    os.kill(os.getpid(), signal.SIGKILL)
module._install_staged_file = kill_after_install
module.restore_backup(
    Path({str(source_map)!r}),
    Path({str(archive)!r}),
    Path({str(self.certificate)!r}),
    Path({str(self.private_key)!r}),
    Path({str(self.signer_certificate)!r}),
    Path({str(restore_root)!r}),
    replace_existing=True,
    confirm_quiesced=True,
)
"""
        killed = subprocess.run(
            [sys.executable, "-c", child],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr.decode())

        journal_path = restore_root / state_backup.RESTORE_JOURNAL_NAME
        self.assertTrue(journal_path.exists())
        self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["state"], "active")
        self.assertEqual(journal["pendingAction"]["kind"], "install-target")

        with self.assertRaisesRegex(state_backup.StateBackupError, "confirm-rollback"):
            state_backup.recover_restore(
                source_map, restore_root, confirm_rollback=False
            )
        self.assertTrue(journal_path.exists())

        recovery = state_backup.recover_restore(
            source_map, restore_root, confirm_rollback=True
        )
        self.assertTrue(recovery.journal_found)
        self.assertEqual(recovery.action, "rolled-back")
        self.assertEqual(first_target.read_bytes(), b'{"old":1}\n')
        self.assertEqual(second_target.read_bytes(), b'{"old":2}\n')
        self.assertFalse(journal_path.exists())
        self.assertFalse(
            (restore_root / state_backup.RESTORE_JOURNAL_PENDING_NAME).exists()
        )
        self.assertEqual(list(state_directory.glob("*.restore.tmp-*")), [])
        self.assertEqual(list(state_directory.glob("*.pre-restore-*")), [])

        repeated = state_backup.recover_restore(
            source_map, restore_root, confirm_rollback=True
        )
        self.assertFalse(repeated.journal_found)
        self.assertEqual(repeated.action, "none")

    def test_restore_root_lock_rejects_concurrent_recovery(self) -> None:
        source = self.write_source("lock-state.json", b'{"safe":true}\n')
        source_map = self.write_map(
            [self.entry("lock-state", "json", source, "state/lock-state.json")]
        )
        restore_root = self.root / "locked-root"
        restore_root.mkdir(mode=0o700)
        descriptor = state_backup._acquire_restore_root_lock(restore_root)
        try:
            with self.assertRaisesRegex(state_backup.StateBackupError, "another restore"):
                state_backup.recover_restore(
                    source_map, restore_root, confirm_rollback=True
                )
        finally:
            os.close(descriptor)

    def test_committed_journal_is_validated_and_finalized_without_rollback(self) -> None:
        source_map, archive, first_payload, second_payload = self.create_two_json_archive()
        restore_root = self.root / "commit-finalize-root"
        restore_root.mkdir(mode=0o700)
        original_remove = state_backup._remove_restore_journal

        with mock.patch.object(
            state_backup,
            "_remove_restore_journal",
            side_effect=OSError("injected final journal cleanup interruption"),
        ):
            with self.assertRaisesRegex(state_backup.StateBackupError, "restore committed"):
                state_backup.restore_backup(
                    source_map,
                    archive,
                    self.certificate,
                    self.private_key,
                    self.signer_certificate,
                    restore_root,
                )

        journal_path = restore_root / state_backup.RESTORE_JOURNAL_NAME
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["state"], "committed")
        self.assertEqual((restore_root / "state/first.json").read_bytes(), first_payload)
        self.assertEqual((restore_root / "state/second.json").read_bytes(), second_payload)

        # The patch is gone: recovery authenticates/readbacks the committed
        # targets and only removes the durable marker. It must not delete them.
        self.assertIs(state_backup._remove_restore_journal, original_remove)
        result = state_backup.recover_restore(
            source_map, restore_root, confirm_rollback=True
        )
        self.assertEqual(result.action, "finalized-committed")
        self.assertEqual((restore_root / "state/first.json").read_bytes(), first_payload)
        self.assertEqual((restore_root / "state/second.json").read_bytes(), second_payload)
        self.assertFalse(journal_path.exists())

    def test_source_symlink_nonregular_hardlink_and_unsafe_mode_are_rejected(self) -> None:
        target = self.write_source("target.json", b'{"safe":true}\n')
        cases: list[tuple[str, Path]] = []

        linked = self.sources / "linked.json"
        linked.symlink_to(target)
        cases.append(("symlink", linked))

        fifo = self.sources / "state.fifo"
        os.mkfifo(fifo, 0o600)
        cases.append(("nonregular", fifo))

        hardlinked = self.write_source("hardlinked.json", b'{"safe":true}\n')
        os.link(hardlinked, self.sources / "hardlink-copy.json")
        cases.append(("hardlink", hardlinked))

        exposed = self.write_source("exposed.json", b'{"safe":true}\n', mode=0o644)
        cases.append(("unsafe-mode", exposed))

        for index, (label, path) in enumerate(cases):
            with self.subTest(label=label):
                source_map = self.write_map(
                    [self.entry(f"case-{index}", "json", path, f"state/{index}.json")],
                    name=f"map-{index}.json",
                )
                with self.assertRaises(state_backup.StateBackupError):
                    self.create_backup(source_map, self.backups / f"unsafe-{index}.cms")

    def test_exact_source_map_rejects_unknown_and_duplicate_members(self) -> None:
        source = self.write_source("state.json", b'{"safe":true}\n')
        unknown = self.entry("state", "json", source, "state/state.json")
        unknown["unexpected"] = True
        source_map = self.write_map([unknown], "unknown.json")
        with self.assertRaises(state_backup.StateBackupError):
            state_backup.load_source_map(source_map)

        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schemaVersion":1,"schemaVersion":1,"sources":[]}', encoding="utf-8"
        )
        duplicate.chmod(0o600)
        with self.assertRaises(state_backup.StateBackupError):
            state_backup.load_source_map(duplicate)

        reserved = self.write_map(
            [
                self.entry(
                    "reserved",
                    "json",
                    source,
                    state_backup.RESTORE_JOURNAL_NAME,
                )
            ],
            "reserved-restore-path.json",
        )
        with self.assertRaisesRegex(state_backup.StateBackupError, "control state"):
            state_backup.load_source_map(reserved)

    def test_every_plaintext_layer_has_a_64_mib_ceiling_and_payload_reserve(self) -> None:
        self.assertEqual(state_backup.MAX_PLAINTEXT_BYTES, 64 * 1024 * 1024)
        self.assertEqual(state_backup.MAX_TAR_BYTES, state_backup.MAX_PLAINTEXT_BYTES)
        self.assertLess(state_backup.MAX_TOTAL_BYTES, state_backup.MAX_PLAINTEXT_BYTES)
        source = self.write_source("bounded.json", b'{"safe":true}\n')
        source_map = self.write_map(
            [
                self.entry(
                    "bounded",
                    "json",
                    source,
                    "state/bounded.json",
                    max_bytes=state_backup.MAX_TOTAL_BYTES + 1,
                )
            ],
            "oversized-advertised-total.json",
        )
        with self.assertRaisesRegex(state_backup.StateBackupError, "global limit"):
            state_backup.load_source_map(source_map)

    def test_verbose_cms_inspection_keeps_only_bounded_head_and_tail(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import sys; sys.stdin.buffer.read(); "
                "sys.stdout.buffer.write(b'HEAD'+b'x'*(1024*1024)+b'TAIL')"
            ),
        ]
        result = state_backup._run_openssl_inspection(command, b"bounded-input")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith(b"HEAD"))
        self.assertTrue(result.stdout.endswith(b"TAIL"))
        self.assertIn(b"bounded CMS inspection output omitted", result.stdout)
        self.assertLessEqual(len(result.stdout), 257 * 1024)

    def test_replace_requires_quiescence_preserves_old_files_and_rolls_back_all(self) -> None:
        source_map, archive, first_payload, second_payload = self.create_two_json_archive()
        restore_root = self.root / "replace-root"
        state_directory = restore_root / "state"
        state_directory.mkdir(parents=True, mode=0o700)
        restore_root.chmod(0o700)
        state_directory.chmod(0o700)
        first_target = state_directory / "first.json"
        second_target = state_directory / "second.json"
        first_target.write_bytes(b'{"old":1}\n')
        second_target.write_bytes(b'{"old":2}\n')
        first_target.chmod(0o600)
        second_target.chmod(0o600)

        with self.assertRaises(state_backup.StateBackupError):
            state_backup.restore_backup(
                source_map,
                archive,
                self.certificate,
                self.private_key,
                self.signer_certificate,
                restore_root,
            )
        self.assertEqual(first_target.read_bytes(), b'{"old":1}\n')
        self.assertEqual(second_target.read_bytes(), b'{"old":2}\n')

        original_install = state_backup._install_staged_file

        def fail_second(stage: Path, target: Path) -> None:
            if target.name == "second.json":
                raise OSError("injected second-target install failure")
            original_install(stage, target)

        with mock.patch.object(state_backup, "_install_staged_file", side_effect=fail_second):
            with self.assertRaises(state_backup.StateBackupError):
                state_backup.restore_backup(
                    source_map,
                    archive,
                    self.certificate,
                    self.private_key,
                    self.signer_certificate,
                    restore_root,
                    replace_existing=True,
                    confirm_quiesced=True,
                )

        self.assertEqual(first_target.read_bytes(), b'{"old":1}\n')
        self.assertEqual(second_target.read_bytes(), b'{"old":2}\n')
        self.assertEqual(list(state_directory.glob("*.tmp-*")), [])
        self.assertEqual(list(state_directory.glob("*.pre-restore-*")), [])

        result = state_backup.restore_backup(
            source_map,
            archive,
            self.certificate,
            self.private_key,
            self.signer_certificate,
            restore_root,
            replace_existing=True,
            confirm_quiesced=True,
        )
        self.assertEqual(first_target.read_bytes(), first_payload)
        self.assertEqual(second_target.read_bytes(), second_payload)
        self.assertEqual(len(result.preserved), 2)
        self.assertEqual(
            sorted(path.read_bytes() for path in result.preserved),
            sorted([b'{"old":1}\n', b'{"old":2}\n']),
        )

    def _hostile_tar(self, members: list[tarfile.TarInfo]) -> bytes:
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for member in members:
                    payload = b"{}\n" if member.isreg() else None
                    if payload is not None:
                        member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload) if payload is not None else None)
        return buffer.getvalue()

    @staticmethod
    def _member(name: str, *, kind: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.mode = 0o600
        member.uid = 0
        member.gid = 0
        member.mtime = 0
        if kind != tarfile.REGTYPE:
            member.linkname = "outside"
        return member

    def test_tar_traversal_links_and_duplicates_are_rejected(self) -> None:
        source = self.write_source("state.json", b'{"safe":true}\n')
        source_map = self.write_map(
            [self.entry("state", "json", source, "state/state.json")]
        )
        plan = state_backup.load_source_map(source_map)
        hostile_archives = {
            "traversal": self._hostile_tar([self._member("../manifest.json")]),
            "link": self._hostile_tar(
                [self._member(state_backup.MANIFEST_NAME, kind=tarfile.SYMTYPE)]
            ),
            "duplicate": self._hostile_tar(
                [
                    self._member(state_backup.MANIFEST_NAME),
                    self._member(state_backup.MANIFEST_NAME),
                ]
            ),
        }
        for label, plaintext in hostile_archives.items():
            with self.subTest(label=label):
                with self.assertRaises(state_backup.StateBackupError):
                    state_backup._parse_plain_archive(plaintext, plan)


if __name__ == "__main__":
    unittest.main()
