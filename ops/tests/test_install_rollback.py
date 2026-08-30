import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]
INSTALLER = OPS / "install.sh"


class InstallDirectoryRollbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = INSTALLER.read_text(encoding="utf-8")

    @classmethod
    def shell_function(cls, name: str) -> str:
        start = cls.installer.index(f"{name}() {{")
        end = cls.installer.index("\n}\n", start) + 3
        return cls.installer[start:end]

    def run_restore(
        self,
        path: Path,
        *,
        existed: bool,
        created: bool,
    ) -> subprocess.CompletedProcess[str]:
        script = "\n".join(
            (
                self.shell_function("restore_directory"),
                'restore_directory "$1" "$2" "$3" "" "" ""',
            )
        )
        return subprocess.run(
            [
                "sh",
                "-c",
                script,
                "install-directory-rollback-test",
                str(path),
                str(existed).lower(),
                str(created).lower(),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_preexisting_metadata_is_captured_together_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "preexisting"
            target.mkdir()
            os.chmod(target, 0o751)
            original = target.stat()
            chown_log = Path(temporary) / "chown.log"
            # Record the exact numeric chown request without requiring the
            # test process to have permission to change directory ownership.
            script = "\n".join(
                (
                    "chown() { printf '%s\\n' \"$1\" \"$2\" > \"$TEST_CHOWN_LOG\"; }",
                    self.shell_function("capture_directory_metadata"),
                    self.shell_function("restore_directory"),
                    'capture_directory_metadata "$1"',
                    "printf '%s %s %s\\n' \"$captured_directory_uid\" \"$captured_directory_gid\" \"$captured_directory_mode\"",
                    'chmod 0750 "$1"',
                    'restore_directory "$1" true false "$captured_directory_uid" "$captured_directory_gid" "$captured_directory_mode"',
                )
            )
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "install-directory-rollback-test", str(target)],
                check=False,
                text=True,
                capture_output=True,
                env={**os.environ, "TEST_CHOWN_LOG": str(chown_log)},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.strip(),
                f"{original.st_uid} {original.st_gid} {stat.S_IMODE(original.st_mode):o}",
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o751)
            self.assertEqual(
                chown_log.read_text(encoding="utf-8").splitlines(),
                [f"{original.st_uid}:{original.st_gid}", str(target)],
            )

    def test_failure_before_creation_does_not_remove_a_late_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "not-created-by-installer"

            result = self.run_restore(target, existed=False, created=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(target.exists())

            target.mkdir()
            result = self.run_restore(target, existed=False, created=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(target.is_dir())

    def test_only_a_tracked_new_empty_directory_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary) / "empty"
            empty.mkdir()
            result = self.run_restore(empty, existed=False, created=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(empty.exists())

            nonempty = Path(temporary) / "nonempty"
            nonempty.mkdir()
            payload = nonempty / "collector-output.json"
            payload.write_text("{}", encoding="utf-8")
            result = self.run_restore(nonempty, existed=False, created=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(payload.read_text(encoding="utf-8"), "{}")

    def test_snapshots_and_creation_markers_bracket_the_transaction(self) -> None:
        transaction = self.installer.index("\ntransaction_started=true\n")
        cases = (
            (
                "/var/lib/monitor-export",
                "created_output_directory",
            ),
            (
                "/run/monitor-collector",
                "created_collector_runtime_directory",
            ),
            (
                "/run/monitor-container-exporter",
                "created_exporter_runtime_directory",
            ),
        )
        for directory, created_variable in cases:
            snapshot = self.installer.index(f"capture_directory_metadata {directory}")
            mkdir = self.installer.index(f"mkdir -- {directory}")
            marked_created = self.installer.index(f"{created_variable}=true", mkdir)
            install = self.installer.index(f"-m 0750 {directory}", marked_created)
            self.assertLess(snapshot, transaction)
            self.assertLess(transaction, mkdir)
            self.assertLess(mkdir, marked_created)
            self.assertLess(marked_created, install)


if __name__ == "__main__":
    unittest.main()
