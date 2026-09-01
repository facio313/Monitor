import datetime as dt
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector  # noqa: E402
from monitoring_catalog import (  # noqa: E402
    MAX_CATALOG_BYTES,
    build_monitoring_catalog,
)


NOW = dt.datetime(2026, 9, 1, 3, 4, 5, tzinfo=dt.timezone.utc)
RULE_PACK = Path(__file__).resolve().parents[1] / "rules" / "default-rules.v1.json"


def build(**overrides):
    values = {
        "now": NOW,
        "rule_pack_path": RULE_PACK,
        "collection_interval_seconds": 75,
        "retention_days": 45,
        "max_log_records": 4_321,
        "incident_retention_days": 21,
        "max_incident_records": 876,
        "generic_log_retention_days": 14,
        "generic_log_max_records": 12_345,
        "generic_log_max_file_bytes": 12 * 1024 * 1024,
    }
    values.update(overrides)
    return build_monitoring_catalog(**values)


def all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)


class MonitoringCatalogTests(unittest.TestCase):
    def test_catalog_has_exact_root_schema_and_every_loaded_rule(self):
        catalog = build()
        self.assertEqual(set(catalog), {
            "schemaVersion", "generatedAt", "collectionIntervalSeconds",
            "rulePackVersion", "evidenceSources", "observations", "rules",
        })
        pack = json.loads(RULE_PACK.read_text(encoding="utf-8"))
        self.assertEqual(catalog["schemaVersion"], 1)
        self.assertEqual(catalog["generatedAt"], "2026-09-01T03:04:05.000Z")
        self.assertEqual(catalog["rulePackVersion"], pack["version"])
        self.assertEqual(
            [rule["id"] for rule in catalog["rules"]],
            [rule["id"] for rule in pack["rules"]],
        )
        self.assertEqual(len(catalog["rules"]), 82)
        for rule in catalog["rules"]:
            self.assertEqual(rule["effectiveEvaluationIntervalSeconds"], 75)
            self.assertEqual(rule["eventRetention"], {
                "maxRecords": 4_321,
                "maxBytes": 32 * 1024 * 1024,
            })
            self.assertEqual(rule["stateEvidenceSourceId"], "rule-evaluation-state")
            self.assertEqual(rule["eventEvidenceSourceId"], "rule-alert-events")

    def test_runtime_retention_and_pruning_cadence_are_resolved(self):
        sources = {source["id"]: source for source in build()["evidenceSources"]}
        self.assertEqual(len(sources), 14)
        self.assertEqual(sources["telemetry-history"]["retention"], {
            "policy": "daily-age-and-count",
            "pruneCadence": "every-collection",
            "maxAgeDays": 45,
            "maxRecords": 2_000,
            "recordScope": "daily-partition",
            "maxBytes": None,
        })
        self.assertEqual(sources["incident-events"]["retention"], {
            "policy": "bounded-age-count-and-bytes",
            "pruneCadence": "on-incident-write-or-daily",
            "maxAgeDays": 21,
            "maxRecords": 876,
            "recordScope": "artifact",
            "maxBytes": 16 * 1024 * 1024,
        })
        self.assertEqual(sources["generic-log-events"]["retention"], {
            "policy": "bounded-age-count-and-bytes",
            "pruneCadence": "every-generic-collection",
            "maxAgeDays": 14,
            "maxRecords": 12_345,
            "recordScope": "artifact",
            "maxBytes": 12 * 1024 * 1024,
        })
        self.assertEqual(
            sources["system-update-state"]["retention"]["pruneCadence"],
            "replace-on-change",
        )
        self.assertEqual(
            sources["infrastructure-ledger"]["retention"]["pruneCadence"],
            "external-no-auto-prune",
        )

    def test_observation_manifest_covers_every_public_family(self):
        catalog = build()
        observations = {item["id"]: item for item in catalog["observations"]}
        required = {
            "agent.identity-heartbeat", "agent.remote-inventory",
            "host.identity-capacity", "resources.cpu-load-pressure",
            "resources.memory-swap-pressure", "resources.process-capacity",
            "resources.process-usage", "storage.filesystems-inodes",
            "storage.block-io", "storage.device-health",
            "network.interfaces-quality", "network.tcp-sockets",
            "network.application-traffic", "reliability.systemd-units",
            "reliability.clock-time-sync", "reliability.host-links",
            "reliability.kernel-events", "reliability.pcie", "reliability.nvme",
            "power.thermal-cooling", "power.platform-state",
            "containers.inventory-lifecycle", "containers.resources-limits",
            "containers.io-network", "containers.mount-network-surface",
            "containers.security-posture", "containers.image-integrity",
            "containers.docker-events", "synthetic.http-tls",
            "incidents.resource-windows", "system.versions-firmware",
            "maintenance.system-updates", "logs.semantic-events",
            "logs.generic-events", "logs.source-health",
            "alerts.rule-evaluation", "alerts.transitions-delivery",
            "monitoring.self-health", "infrastructure.change-ledger",
        }
        self.assertEqual(set(observations), required)
        source_ids = {source["id"] for source in catalog["evidenceSources"]}
        for observation in observations.values():
            self.assertTrue(observation["evidenceSourceIds"])
            self.assertLessEqual(set(observation["evidenceSourceIds"]), source_ids)
            self.assertEqual(set(observation["displayName"]), {"ko", "en"})
            self.assertEqual(set(observation["description"]), {"ko", "en"})

    def test_catalog_never_exports_configured_paths_or_private_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            rule_copy = Path(temporary) / "private-rule-pack.json"
            rule_copy.write_bytes(RULE_PACK.read_bytes())
            catalog = build(rule_pack_path=rule_copy)
            strings = list(all_strings(catalog))
            self.assertNotIn(str(rule_copy), strings)
            self.assertFalse(any(value.startswith("/") for value in strings))
            self.assertFalse(any(".state/" in value for value in strings))
            self.assertFalse(any("raw-secret-value" in value for value in strings))
            encoded = json.dumps(catalog, ensure_ascii=False).encode("utf-8")
            self.assertLess(len(encoded), MAX_CATALOG_BYTES)

    def test_atomic_publisher_uses_public_mode_and_removes_stale_catalog_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "export"
            config = collector.Config(output_dir=output, rule_pack=RULE_PACK)
            self.assertTrue(collector.publish_monitoring_catalog(config, NOW))
            path = output / "monitoring-catalog.json"
            first = path.read_bytes()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(json.loads(first)["rules"][0]["id"], "HostDown")

            invalid_pack = Path(temporary) / "invalid-rules.json"
            invalid_pack.write_text('{"schemaVersion":1,"version":"bad","rules":[]}', encoding="utf-8")
            os.chmod(invalid_pack, 0o600)
            config.rule_pack = invalid_pack
            self.assertFalse(collector.publish_monitoring_catalog(config, NOW))
            self.assertFalse(path.exists())

    def test_catalog_drops_non_public_labels_and_rejects_secret_shaped_rule_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            rule_copy = Path(temporary) / "rules.json"
            pack = json.loads(RULE_PACK.read_text(encoding="utf-8"))
            pack["rules"][0]["labels"] = {"secret": "opaqueCredential123"}
            rule_copy.write_text(json.dumps(pack), encoding="utf-8")
            catalog = build(rule_pack_path=rule_copy)
            self.assertEqual(catalog["rules"][0]["labels"], {})

            pack["rules"][0]["labels"] = {"scope": "host"}
            pack["rules"][0]["runbook"] = "Use ghp_abcdefghijklmnopqrstuvwxyz1234567890"
            rule_copy.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "forbidden material"):
                build(rule_pack_path=rule_copy)

            pack["rules"][0]["runbook"] = "Read /opt/monitor/private.conf"
            rule_copy.write_text(json.dumps(pack), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "forbidden material"):
                build(rule_pack_path=rule_copy)

    def test_install_and_uninstall_track_the_catalog_module(self):
        ops = Path(__file__).resolve().parents[1]
        installer = (ops / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ops / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn(
            "monitoring_catalog_target=/usr/local/lib/monitor-collector/monitoring_catalog.py",
            installer,
        )
        self.assertIn(
            'restore_file "$backup_dir/monitoring_catalog.py" "$monitoring_catalog_target"',
            installer,
        )
        self.assertIn(
            'install -m 0644 "$script_dir/monitoring_catalog.py" "$monitoring_catalog_target"',
            installer,
        )
        self.assertIn(
            "/usr/local/lib/monitor-collector/monitoring_catalog.py",
            uninstaller,
        )


if __name__ == "__main__":
    unittest.main()
