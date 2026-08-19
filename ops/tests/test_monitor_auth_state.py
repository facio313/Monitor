import base64
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "monitor_auth_state.py"
SPEC = importlib.util.spec_from_file_location("monitor_auth_state", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
auth_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth_state)


class MonitorAuthStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state_dir = self.root / "state"
        self.backup_dir = self.root / "backups"
        self.uid = os.geteuid()

    @staticmethod
    def valid_state(epoch: int = 1) -> dict[str, object]:
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        return {
            "version": 1,
            "password": {
                "algorithm": "scrypt",
                "n": 65_536,
                "r": 8,
                "p": 1,
                "keyLength": 32,
                "salt": encode(bytes([epoch]) * 16),
                "digest": encode(bytes([epoch + 1]) * 32),
            },
            "sessionEpoch": encode(bytes([epoch + 2]) * 32),
        }

    def write_state(self, payload: dict[str, object] | None = None) -> Path:
        auth_state.prepare(self.state_dir, self.uid)
        state_file = self.state_dir / auth_state.STATE_FILENAME
        state_file.write_text(
            json.dumps(payload or self.valid_state()),
            encoding="utf-8",
        )
        state_file.chmod(0o600)
        return state_file

    def test_prepare_creates_private_directory_without_state(self) -> None:
        auth_state.prepare(self.state_dir, self.uid)

        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        self.assertFalse((self.state_dir / auth_state.STATE_FILENAME).exists())
        self.assertEqual(
            auth_state.status(self.state_dir, self.uid),
            "directory=ready state=awaiting-initialization",
        )

    def test_prepare_preserves_existing_valid_state(self) -> None:
        state_file = self.write_state()
        before = state_file.read_bytes()

        auth_state.prepare(self.state_dir, self.uid)

        self.assertEqual(state_file.read_bytes(), before)
        self.assertEqual(
            auth_state.status(self.state_dir, self.uid), "directory=ready state=ready"
        )

    def test_symlink_state_is_refused(self) -> None:
        auth_state.prepare(self.state_dir, self.uid)
        target = self.root / "outside.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        (self.state_dir / auth_state.STATE_FILENAME).symlink_to(target)

        with self.assertRaises(auth_state.StateError):
            auth_state.status(self.state_dir, self.uid)

    def test_symlinked_state_directory_is_refused_before_creation(self) -> None:
        real_parent = self.root / "real"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        state_dir = linked_parent / "state"

        with self.assertRaises(auth_state.StateError):
            auth_state.prepare(state_dir, self.uid)

        self.assertFalse((real_parent / "state").exists())

    def test_group_readable_state_is_refused(self) -> None:
        state_file = self.write_state()
        state_file.chmod(0o640)

        with self.assertRaises(auth_state.StateError):
            auth_state.backup(self.state_dir, self.backup_dir, self.uid)

    def test_hard_linked_state_is_refused(self) -> None:
        state_file = self.write_state()
        os.link(state_file, self.root / "linked.json")

        with self.assertRaises(auth_state.StateError):
            auth_state.status(self.state_dir, self.uid)

    def test_backup_is_private_and_byte_exact(self) -> None:
        state_file = self.write_state()

        snapshot = auth_state.backup(self.state_dir, self.backup_dir, self.uid)

        self.assertEqual(snapshot.read_bytes(), state_file.read_bytes())
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.backup_dir.stat().st_mode), 0o700)

    def test_restore_preserves_previous_state_and_replaces_atomically(self) -> None:
        state_file = self.write_state(self.valid_state(2))
        old_snapshot = auth_state.backup(self.state_dir, self.backup_dir, self.uid)
        state_file.write_text(
            json.dumps(self.valid_state(3)),
            encoding="utf-8",
        )
        state_file.chmod(0o600)
        current = state_file.read_bytes()

        previous_snapshot, restored = auth_state.restore(
            old_snapshot, self.state_dir, self.backup_dir, self.uid
        )

        self.assertIsNotNone(previous_snapshot)
        assert previous_snapshot is not None
        self.assertEqual(previous_snapshot.read_bytes(), current)
        restored_payload = json.loads(restored.read_bytes())
        snapshot_payload = json.loads(old_snapshot.read_bytes())
        self.assertEqual(restored_payload["password"], snapshot_payload["password"])
        self.assertNotEqual(restored_payload["sessionEpoch"], snapshot_payload["sessionEpoch"])
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
        self.assertEqual(list(self.state_dir.glob(".*.tmp-*")), [])

    def test_post_replace_directory_sync_failure_keeps_committed_state(self) -> None:
        state_file = self.write_state(self.valid_state(2))
        auth_state.prepare(self.backup_dir, self.uid)
        replacement = self.root / "replacement.json"
        replacement.write_text(json.dumps(self.valid_state(3)), encoding="utf-8")
        replacement.chmod(0o600)

        with mock.patch.object(
            auth_state,
            "_fsync_directory",
            side_effect=OSError("injected directory sync failure"),
        ):
            with mock.patch("sys.stderr") as stderr:
                _, restored = auth_state.restore(
                    replacement, self.state_dir, self.backup_dir, self.uid
                )

        self.assertEqual(restored, state_file)
        restored_payload = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(restored_payload["password"], self.valid_state(3)["password"])
        self.assertNotEqual(
            restored_payload["sessionEpoch"], self.valid_state(3)["sessionEpoch"]
        )
        self.assertTrue(stderr.write.called)

    def test_invalid_json_snapshot_is_refused_without_replacing_state(self) -> None:
        state_file = self.write_state()
        before = state_file.read_bytes()
        invalid = self.root / "invalid.json"
        invalid.write_text("not-json", encoding="utf-8")
        invalid.chmod(0o600)

        with self.assertRaises(auth_state.StateError):
            auth_state.restore(invalid, self.state_dir, self.backup_dir, self.uid)

        self.assertEqual(state_file.read_bytes(), before)

    def test_invalid_state_schema_is_refused_without_replacing_state(self) -> None:
        state_file = self.write_state()
        before = state_file.read_bytes()
        invalid = self.root / "invalid-schema.json"
        payload = self.valid_state()
        assert isinstance(payload["password"], dict)
        payload["password"]["algorithm"] = "unsupported"
        invalid.write_text(json.dumps(payload), encoding="utf-8")
        invalid.chmod(0o600)

        with self.assertRaises(auth_state.StateError):
            auth_state.restore(invalid, self.state_dir, self.backup_dir, self.uid)

        self.assertEqual(state_file.read_bytes(), before)

    def test_unknown_state_fields_match_backend_forward_compatibility(self) -> None:
        payload = self.valid_state()
        payload["futureMetadata"] = {"ignored": True}
        assert isinstance(payload["password"], dict)
        payload["password"]["futureParameter"] = "ignored"
        self.write_state(payload)

        snapshot = auth_state.backup(self.state_dir, self.backup_dir, self.uid)

        self.assertTrue(snapshot.is_file())

    def test_wrong_scrypt_material_length_is_refused(self) -> None:
        payload = self.valid_state()
        assert isinstance(payload["password"], dict)
        payload["password"]["salt"] = (
            base64.urlsafe_b64encode(b"short").decode("ascii").rstrip("=")
        )
        state_file = self.write_state(payload)

        with self.assertRaises(auth_state.StateError):
            auth_state.status(self.state_dir, self.uid)

        self.assertTrue(state_file.exists())

    def test_backup_directory_inside_state_mount_is_refused(self) -> None:
        self.write_state()
        nested_backup = self.state_dir / "backups"

        with self.assertRaises(auth_state.StateError):
            auth_state.backup(self.state_dir, nested_backup, self.uid)

        self.assertFalse(nested_backup.exists())


if __name__ == "__main__":
    unittest.main()
