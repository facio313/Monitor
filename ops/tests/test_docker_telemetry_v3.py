import datetime as dt
import json
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector  # noqa: E402


NOW = dt.datetime(2026, 8, 30, 12, 1, tzinfo=dt.timezone.utc)
CONTAINER_ID = "a" * 64
IMAGE_A = "sha256:" + "1" * 64
IMAGE_B = "sha256:" + "2" * 64


def raw_container() -> dict[str, object]:
    return {
        "Id": CONTAINER_ID,
        "Labels": {
            "com.docker.compose.project": "monitor",
            "com.docker.compose.service": "monitor",
        },
        "State": "running",
        "SizeRw": 1_500_000_000,
    }


def reduced_inspect(image: str = IMAGE_B) -> dict[str, object]:
    full = {
        "Id": CONTAINER_ID,
        "Image": image,
        "Config": {
            "Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            },
            "Image": "registry.example/ops/monitor:latest",
            "User": "0:0",
            "Env": ["TOKEN=never-export-this"],
            "Cmd": ["--password=never-export-this"],
            "Healthcheck": {"Test": ["CMD-SHELL", "curl -H 'secret' localhost"]},
        },
        "State": {
            "OOMKilled": False,
            "StartedAt": "2026-08-30T11:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
            "Health": {"Status": "healthy", "Log": [{"Output": "secret"}]},
        },
        "RestartCount": 4,
        "HostConfig": {
            "Memory": 2_000_000_000,
            "NanoCpus": 2_000_000_000,
            "PidsLimit": 200,
            "Privileged": True,
            "PidMode": "host",
            "IpcMode": "private",
            "NetworkMode": "host",
            "ReadonlyRootfs": False,
            "CapAdd": ["NET_ADMIN", "SYS_PTRACE"],
        },
        "Mounts": [
            {
                "Type": "bind", "Source": "/run/user/1001/docker.sock",
                "Destination": "/run/docker.sock", "RW": True,
            },
            {"Type": "volume", "Source": "/secret/volume-id", "Destination": "/data"},
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp"},
        ],
        "NetworkSettings": {
            "Networks": {"monitor_default": {"IPAddress": "10.0.0.2", "MacAddress": "secret"}},
            "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
    }
    reduced = collector.reduce_container_inspect(full)
    serialized = json.dumps(reduced)
    for secret in ("TOKEN", "password", "/secret/volume-id", "10.0.0.2", "MacAddress", "curl"):
        assert secret not in serialized
    return reduced


def reduced_stats(read: str = "2026-08-30T12:01:00Z") -> dict[str, object]:
    return collector.reduce_container_stats({
        "read": read,
        "cpu_stats": {
            "cpu_usage": {"total_usage": 5000},
            "system_cpu_usage": 10000,
            "online_cpus": 2,
            "throttling_data": {"periods": 200, "throttled_periods": 50, "throttled_time": 2_500_000_000},
        },
        "memory_stats": {"usage": 900_000_000, "limit": 2_000_000_000},
        "pids_stats": {"current": 180},
        "blkio_stats": {"io_service_bytes_recursive": [
            {"major": 8, "minor": 0, "op": "Read", "value": 7000},
            {"major": 8, "minor": 0, "op": "Write", "value": 9000},
        ]},
        "networks": {
            "eth0": {"rx_bytes": 20_000, "tx_bytes": 30_000, "rx_errors": 2, "tx_errors": 3},
        },
    })


class DockerTelemetryV3Tests(unittest.TestCase):
    def test_sensitive_bind_writability_is_reduced_without_exporting_paths(self) -> None:
        read_only = collector.reduce_container_inspect({
            "Mounts": [{
                "Type": "bind",
                "Source": "/home/cks/.config/monitor/edge-secret",
                "Destination": "/run/secrets/monitor-edge",
                "RW": False,
            }],
        })["MountSummary"]
        self.assertTrue(read_only["sensitiveBindMounted"])
        self.assertFalse(read_only["writableSensitiveBindMounted"])

        unknown = collector.reduce_container_inspect({
            "Mounts": [{
                "Type": "bind", "Source": "/etc/monitor/config", "Destination": "/config",
            }],
        })["MountSummary"]
        self.assertTrue(unknown["sensitiveBindMounted"])
        self.assertIsNone(unknown["writableSensitiveBindMounted"])

        writable = collector.reduce_container_inspect({
            "Mounts": [
                {"Type": "bind", "Source": "/etc/monitor/a", "Destination": "/a", "RW": False},
                {"Type": "bind", "Source": "/root/monitor/b", "Destination": "/b", "RW": True},
            ],
        })["MountSummary"]
        self.assertTrue(writable["writableSensitiveBindMounted"])
        self.assertNotIn("/etc/monitor", json.dumps(writable))
        self.assertNotIn("/root/monitor", json.dumps(writable))

        no_sensitive_bind = collector.reduce_container_inspect({
            "Mounts": [{
                "Type": "bind", "Source": "/srv/monitor", "Destination": "/etc/monitor", "RW": True,
            }],
        })["MountSummary"]
        self.assertFalse(no_sensitive_bind["sensitiveBindMounted"])
        self.assertFalse(no_sensitive_bind["writableSensitiveBindMounted"])

    def test_digest_pinned_latest_reference_and_root_group_are_reduced_correctly(self) -> None:
        inspect = {
            **reduced_inspect(),
            "Config": {
                **reduced_inspect()["Config"],
                "Image": f"registry.example/ops/monitor:latest@{IMAGE_A}",
                "RootUser": True,
            },
        }
        details = collector.docker_image_details(inspect)
        self.assertEqual(details[:5], (
            "registry.example/ops/monitor", "latest", IMAGE_A, "repo-digest", True,
        ))
        changed_pin = {
            **inspect,
            "Config": {
                **inspect["Config"],
                "Image": f"registry.example/ops/monitor:latest@{IMAGE_B}",
            },
        }
        self.assertNotEqual(details[5], collector.docker_image_details(changed_pin)[5])

        raw_inspect = {
            "Config": {"User": "0:application", "Image": "monitor:latest", "Labels": {}},
            "State": {}, "HostConfig": {}, "Mounts": [],
        }
        self.assertTrue(collector.reduce_container_inspect(raw_inspect)["Config"]["RootUser"])

    def test_reduces_current_resources_security_storage_and_image_without_secrets(self) -> None:
        inspect = reduced_inspect()
        stats = reduced_stats()
        image_fingerprint = collector.docker_image_details(inspect)[5]
        row = collector.container_from_api(
            raw_container(),
            "cks",
            stats,
            previous_state={
                "cpuTotal": 4000,
                "systemTotal": 8000,
                "onlineCpus": 2,
                "restartCount": 3,
                "sampleAtUnixMs": int((NOW - dt.timedelta(seconds=60)).timestamp() * 1000),
                "cpuPeriods": 100,
                "cpuThrottledPeriods": 10,
                "cpuThrottledTimeNanoseconds": 1_300_000_000,
                "blockReadBytes": 1000,
                "blockWriteBytes": 3000,
                "networkRxBytes": 8000,
                "networkTxBytes": 12_000,
                "networkErrors": 1,
            },
            inspect=inspect,
            previous_service_state={
                "imageDigest": IMAGE_A,
                "imageReferenceFingerprint": image_fingerprint,
            },
        )
        self.assertEqual(tuple(row), collector.CONTAINER_FIELDS)
        self.assertRegex(row["instanceId"], r"^[a-f0-9]{32}$")
        self.assertEqual(row["pidCount"], 180)
        self.assertEqual(row["cpuThrottledPercent"], 2)
        self.assertEqual(row["cpuThrottledPeriods"], 50)
        self.assertEqual(row["cpuThrottledSeconds"], 2.5)
        self.assertEqual(
            collector.private_container_counters(stats)["cpuThrottledTimeNanoseconds"],
            2_500_000_000,
        )
        self.assertEqual(row["blockReadBytesPerSecond"], 100)
        self.assertEqual(row["blockWriteBytesPerSecond"], 100)
        self.assertEqual(row["networkRxBytesPerSecond"], 200)
        self.assertEqual(row["networkTxBytesPerSecond"], 300)
        self.assertAlmostEqual(row["networkErrorsPerSecond"], 4 / 60, places=3)
        self.assertEqual(row["writableLayerBytes"], 1_500_000_000)
        self.assertEqual((row["volumeCount"], row["bindMountCount"], row["tmpfsMountCount"]), (1, 1, 1))
        self.assertTrue(row["privileged"])
        self.assertTrue(row["hostPid"])
        self.assertTrue(row["hostNetwork"])
        self.assertTrue(row["dockerSocketMounted"])
        self.assertTrue(row["sensitiveBindMounted"])
        self.assertTrue(row["writableSensitiveBindMounted"])
        self.assertTrue(row["rootUser"])
        self.assertFalse(row["readOnlyRootFilesystem"])
        self.assertEqual(row["dangerousCapabilityCount"], 2)
        self.assertEqual(row["imageName"], "registry.example/ops/monitor")
        self.assertEqual(row["imageTag"], "latest")
        self.assertEqual(row["imageDigest"], IMAGE_B)
        self.assertEqual(row["imageDigestSource"], "local-image-id")
        self.assertTrue(row["usesLatestTag"])
        self.assertTrue(row["imageDigestChanged"])
        serialized = json.dumps(row)
        for secret in (CONTAINER_ID, "TOKEN", "password", "10.0.0.2", "/secret"):
            self.assertNotIn(secret, serialized)

        normalized = collector.normalize_container_values([row], NOW + dt.timedelta(seconds=60))
        self.assertEqual(normalized, [row])
        legacy_row = dict(row)
        legacy_row.pop("writableSensitiveBindMounted")
        legacy_normalized = collector.normalize_container_values(
            [legacy_row], NOW + dt.timedelta(seconds=60)
        )
        self.assertIsNone(legacy_normalized[0]["writableSensitiveBindMounted"])
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{**row, "rawMount": "/secret"}], NOW)
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{
                **row,
                "sensitiveBindMounted": False,
                "writableSensitiveBindMounted": True,
            }], NOW)
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{**row, "usesLatestTag": False}], NOW)
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{
                **row,
                "imageName": None,
                "imageTag": None,
                "usesLatestTag": True,
            }], NOW)
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{
                **row,
                "imageDigest": None,
                "imageDigestSource": None,
                "imageDigestDrift": False,
            }], NOW)
        with self.assertRaises(ValueError):
            collector.normalize_container_values([{**row, "excessiveCapabilities": False}], NOW)

        reset_row = collector.container_from_api(
            raw_container(), "cks", stats,
            previous_state={
                "sampleAtUnixMs": int((NOW - dt.timedelta(seconds=60)).timestamp() * 1000),
                "cpuThrottledTimeNanoseconds": 3_000_000_000,
            },
            inspect=inspect,
        )
        self.assertIsNone(reset_row["cpuThrottledPercent"])

    def test_digest_drift_is_unknown_with_missing_digest_and_true_for_mixed_replicas(self) -> None:
        rows = [
            {"project": "monitor", "name": "monitor", "imageDigest": IMAGE_A, "imageDigestDrift": None},
            {"project": "monitor", "name": "monitor", "imageDigest": IMAGE_B, "imageDigestDrift": None},
        ]
        collector.apply_container_image_drift(rows)
        self.assertTrue(all(row["imageDigestDrift"] is True for row in rows))
        rows[1]["imageDigest"] = None
        collector.apply_container_image_drift(rows)
        self.assertTrue(all(row["imageDigestDrift"] is None for row in rows))

    def event_payload(self, action: str = "die", event_time: dt.datetime = NOW) -> bytes:
        return (json.dumps({
            "Type": "container",
            "Action": action,
            "Actor": {
                "ID": CONTAINER_ID,
                "Attributes": {
                    "com.docker.compose.project": "monitor",
                    "com.docker.compose.service": "monitor",
                    "exitCode": "137",
                    "token": "never-export-this",
                },
            },
            "time": int(event_time.timestamp()),
            "timeNano": int(event_time.timestamp() * 1_000_000_000),
        }) + "\n").encode()

    def test_event_cursor_reconnect_dedup_gap_and_redaction(self) -> None:
        request = collector.docker_event_request_path(NOW - dt.timedelta(minutes=1), NOW)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request).query)
        filters = json.loads(query["filters"][0])
        self.assertEqual(filters["type"], ["container"])
        self.assertEqual(
            set(filters["label"]),
            {
                f"com.docker.compose.project={project}"
                for project in collector.ALLOWED_COMPOSE_PROJECTS
            },
        )
        prior = {
            "status": "unavailable",
            "observedAt": collector.iso_timestamp(NOW - dt.timedelta(minutes=1)),
            "cursorAt": collector.iso_timestamp(NOW - dt.timedelta(minutes=1)),
            "reconnectCount": 2,
            "gapCount": 0,
            "gapDetected": False,
            "events": [],
        }
        with mock.patch.object(
            collector, "docker_get_events", return_value=self.event_payload() * 2,
        ):
            collection, events, state = collector.collect_docker_events(
                Path("/run/user/1001/docker.sock"), "/usr/bin/curl", 2, prior, NOW,
            )
        self.assertEqual(collection["status"], "gap")
        self.assertEqual(collection["reconnectCount"], 3)
        self.assertTrue(collection["gapDetected"])
        self.assertEqual(collection["gapCount"], 1)
        self.assertEqual(collection["logCollectionStatus"], "unsupported")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["action"], "die")
        self.assertEqual(events[0]["exitCode"], 137)
        self.assertNotIn(CONTAINER_ID, json.dumps([collection, events, state]))
        self.assertNotIn("never-export-this", json.dumps([collection, events, state]))

        stale = {**state, "cursorAt": collector.iso_timestamp(NOW - dt.timedelta(hours=1)), "gapDetected": False}
        with mock.patch.object(collector, "docker_get_events", return_value=b""):
            gap_collection, retained, _gap_state = collector.collect_docker_events(
                Path("/run/user/1001/docker.sock"), "/usr/bin/curl", 2, stale,
                NOW + dt.timedelta(minutes=1),
            )
        self.assertEqual(gap_collection["status"], "gap")
        self.assertTrue(gap_collection["gapDetected"])
        self.assertEqual(gap_collection["gapCount"], 2)
        self.assertEqual(retained, events)

    def test_strict_snapshot_document_admits_v3_and_rejects_event_or_row_extras(self) -> None:
        row = collector.container_from_api(raw_container(), "cks", reduced_stats(), inspect=reduced_inspect())
        event = collector.normalize_docker_event(json.loads(self.event_payload()), NOW)
        self.assertIsNotNone(event)
        document = {
            "generatedAt": collector.iso_timestamp(NOW),
            "containerCollection": {"status": "fresh", "observedAt": collector.iso_timestamp(NOW)},
            "containers": [row],
            "dockerEventCollection": {
                "status": "fresh",
                "observedAt": collector.iso_timestamp(NOW),
                "cursorAt": collector.iso_timestamp(NOW),
                "reconnectCount": 0,
                "gapCount": 0,
                "gapDetected": False,
                "logCollectionStatus": "unsupported",
            },
            "dockerEvents": [event],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "containers.json"

            def write(value: object) -> None:
                path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                path.chmod(0o640)

            write(document)
            loaded = collector.load_container_snapshot_document(
                path, NOW, expected_uid=None, expected_gid=None,
            )
            self.assertEqual(loaded[0], [row])
            self.assertEqual(loaded[2], document["dockerEventCollection"])
            self.assertEqual(loaded[3], [event])
            write({**document, "dockerEvents": [{**event, "raw": "secret"}]})
            with self.assertRaises(ValueError):
                collector.load_container_snapshot_document(path, NOW, expected_uid=None, expected_gid=None)


if __name__ == "__main__":
    unittest.main()
