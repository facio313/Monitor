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
            "name": "monitor", "project": "monitor", "owner": "cks",
            "state": "running", "health": "healthy", "healthcheckConfigured": True,
            "cpuPercent": 250.0, "memoryBytes": 123, "memoryPercent": 1.5,
            "memoryLimitBytes": 1024, "cpuLimitCores": 0.5, "pidLimit": 64,
            "restartCount": 3, "restartCountDelta": 1, "oomKilled": False,
            "startedAt": "2026-08-30T01:00:00Z", "finishedAt": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(container_exporter.collector, "docker_get", return_value=[{}]), \
                 mock.patch.object(
                     container_exporter.collector,
                     "collect_containers",
                     return_value=([container], {"cks:abc": {
                         "cpuTotal": 1, "systemTotal": 2, "onlineCpus": 1,
                         "restartCount": 3,
                     }}),
                 ):
                container_exporter.run(self.arguments(root))

            public = json.loads((root / "containers.json").read_text(encoding="utf-8"))
            private = json.loads((root / "cpu-state.json").read_text(encoding="utf-8"))
            self.assertEqual(set(public), {"generatedAt", "containerCollection", "containers"})
            self.assertEqual(public["containerCollection"], {
                "status": "fresh", "observedAt": public["generatedAt"],
            })
            self.assertEqual(public["containers"], [container])
            self.assertEqual(set(private), {"generatedAt", "containers"})
            self.assertEqual(private["containers"], {"cks:abc": {
                "cpuTotal": 1, "systemTotal": 2, "onlineCpus": 1,
                "restartCount": 3,
            }})
            self.assertEqual(os.stat(root / "containers.json").st_mode & 0o777, 0o640)
            self.assertEqual(os.stat(root / "cpu-state.json").st_mode & 0o777, 0o600)

    def test_unavailable_source_exports_last_known_without_replacing_cpu_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            root.mkdir()
            output = root / "containers.json"
            observed_at = container_exporter.collector.iso_timestamp(
                container_exporter.collector.utc_now()
            )
            previous_container = {
                "name": "monitor", "project": "monitor", "owner": "cks",
                "state": "running", "health": "healthy", "healthcheckConfigured": True,
                "cpuPercent": 1.0, "memoryBytes": 123, "memoryPercent": 1.5,
                "memoryLimitBytes": 1024, "cpuLimitCores": 0.5, "pidLimit": 64,
                "restartCount": 3, "restartCountDelta": 1, "oomKilled": False,
                "startedAt": "2026-08-30T01:00:00Z", "finishedAt": None,
            }
            output.write_text(json.dumps({
                "generatedAt": observed_at,
                "containerCollection": {"status": "fresh", "observedAt": observed_at},
                "containers": [previous_container],
            }) + "\n", encoding="utf-8")
            output.chmod(0o640)
            state = root / "cpu-state.json"
            state.write_text('{"containers":{"cks:old":{"cpuTotal":1}}}\n', encoding="utf-8")
            calls = 0

            def partial_failure(_socket, path, _curl, _timeout):
                nonlocal calls
                calls += 1
                return None

            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(
                     container_exporter.collector,
                     "load_container_snapshot_state",
                     return_value=(
                         [previous_container],
                         {"status": "fresh", "observedAt": observed_at},
                     ),
                 ), \
                 mock.patch.object(
                     container_exporter.collector, "docker_get", side_effect=partial_failure
                ):
                container_exporter.run(self.arguments(root))
            self.assertEqual(calls, len(container_exporter.collector.ALLOWED_COMPOSE_PROJECTS))
            public = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(public["containerCollection"], {
                "status": "last-known", "observedAt": observed_at,
            })
            self.assertEqual(public["containers"], [previous_container])
            self.assertNotIn("source unavailable", output.read_text(encoding="utf-8"))
            self.assertEqual(
                state.read_text(encoding="utf-8"),
                '{"containers":{"cks:old":{"cpuTotal":1}}}\n',
            )

    def test_permission_failure_is_bounded_when_no_previous_observation_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            with mock.patch.object(container_exporter.os, "geteuid", return_value=1001), \
                 mock.patch.object(
                     container_exporter.collector,
                     "collect_containers",
                     side_effect=PermissionError("secret socket path"),
                 ):
                container_exporter.run(self.arguments(root))
            public_text = (root / "containers.json").read_text(encoding="utf-8")
            public = json.loads(public_text)
            self.assertEqual(public["containerCollection"], {
                "status": "permission-denied", "observedAt": None,
            })
            self.assertEqual(public["containers"], [])
            self.assertNotIn("secret", public_text)

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
