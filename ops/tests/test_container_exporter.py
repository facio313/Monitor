import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import container_exporter  # noqa: E402


class ContainerExporterTests(unittest.TestCase):
    def arguments(self, root: Path) -> list[str]:
        return [
            "--socket", str(container_exporter.EXPECTED_SOCKET),
            "--output", str(root / "containers.json"),
            "--state", str(root / "cpu-state.json"),
        ]

    def test_writes_only_reduced_snapshot_and_private_cpu_state(self) -> None:
        container = {
            "name": "monitor",
            "owner": "cks",
            "state": "running",
            "health": "healthy",
            "cpuPercent": 250.0,
            "memoryBytes": 123,
            "memoryPercent": 1.5,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(container_exporter.collector, "docker_get", return_value=[{}]), \
                 mock.patch.object(
                     container_exporter.collector,
                     "collect_containers",
                     return_value=([container], {"cks:abc": {"cpuTotal": 1}}),
                 ):
                container_exporter.run(self.arguments(root))

            public = json.loads((root / "containers.json").read_text(encoding="utf-8"))
            private = json.loads((root / "cpu-state.json").read_text(encoding="utf-8"))
            self.assertEqual(set(public), {"generatedAt", "containers"})
            self.assertEqual(public["containers"], [container])
            self.assertEqual(set(private), {"generatedAt", "containers"})
            self.assertEqual(private["containers"], {"cks:abc": {"cpuTotal": 1}})
            self.assertEqual(os.stat(root / "containers.json").st_mode & 0o777, 0o640)
            self.assertEqual(os.stat(root / "cpu-state.json").st_mode & 0o777, 0o600)

    def test_unavailable_source_does_not_replace_previous_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            root.mkdir()
            output = root / "containers.json"
            output.write_text('{"previous":true}\n', encoding="utf-8")
            state = root / "cpu-state.json"
            state.write_text('{"containers":{"cks:old":{"cpuTotal":1}}}\n', encoding="utf-8")
            calls = 0

            def partial_failure(_socket, path, _curl, _timeout):
                nonlocal calls
                calls += 1
                return [] if calls < 2 else None

            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(
                     container_exporter.collector, "docker_get", side_effect=partial_failure
                 ):
                with self.assertRaisesRegex(RuntimeError, "source unavailable"):
                    container_exporter.run(self.arguments(root))
            self.assertEqual(calls, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), '{"previous":true}\n')
            self.assertEqual(
                state.read_text(encoding="utf-8"),
                '{"containers":{"cks:old":{"cpuTotal":1}}}\n',
            )

    def test_rejects_privilege_or_foreign_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            with mock.patch.object(container_exporter.os, "geteuid", return_value=0):
                with self.assertRaises(PermissionError):
                    container_exporter.run(self.arguments(root))
            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(container_exporter.collector, "docker_get", return_value=[{}]), \
                 mock.patch.object(
                     container_exporter.collector,
                     "collect_containers",
                     return_value=([{"owner": "foreign"}], {}),
                 ):
                with self.assertRaisesRegex(ValueError, "unexpected container owner"):
                    container_exporter.run(self.arguments(root))


if __name__ == "__main__":
    unittest.main()
