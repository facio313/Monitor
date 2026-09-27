import contextlib
import datetime as dt
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import alert_delivery as delivery
from ops import notification_reports as reports
from ops.tests.test_alert_delivery import channel, config_value, event
from ops.tests.test_security_signals import ssh_row


NOW = dt.datetime(2026, 9, 13, 9, 0, tzinfo=dt.timezone.utc)


class NotificationReportsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "delivery.json"
        self.config = config_value(channels=[channel("smtp-mail", "smtp", secret_key="SMTP_SECRET")], lease_seconds=90)
        self.config["queue"].update({"maxHistory": 200, "maxDeliveryLog": 400})
        self.write("delivery.json", self.config)
        self.refresh(NOW)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, filename, value):
        path = self.root / filename
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def refresh(self, now, cpu=20):
        text = reports._iso(now)
        self.current = {"generatedAt": text, "latest": {"cpuPercent": cpu, "memoryPercent": 25,
                        "temperatureC": 65, "memoryPressureSomeAvg10": 0, "ioPressureSomeAvg10": 0},
                        "currentTraffic": [{"app": "monitor", "requestCount": 2, "status4xx": 0,
                                            "status5xx": 0}], "disks": []}
        self.evaluation = {"evaluatedAt": text, "status": "ok", "states": {}}
        self.write("generic-log-sources.json", {"generatedAt": text, "sources": [
            {"sourceId": "journal:ssh", "status": "no_data", "observedAt": text}]})
        self.write("ssh-access-status.json", {
            "status": "fresh", "observedAt": text, "droppedRecords": 0,
        })

    def run_producer(self, now=NOW):
        return reports.produce_notifications(self.root, now, current=self.current,
                                             evaluation=self.evaluation, delivery_config_path=self.config_path)

    def refresh_network(self, now, rate=0):
        self.refresh(now)
        self.current["latest"]["networkRxErrorsPerSecond"] = rate

    def refresh_temperature(self, now, value=65):
        self.refresh(now)
        self.current["latest"]["temperatureC"] = value

    def outbox(self):
        config = delivery.parse_delivery_config(self.config)
        return delivery.DeliveryOutbox(self.root / ".state/alert-delivery/alert-delivery.sqlite", config.queue)

    def queued(self):
        with contextlib.closing(self.outbox()._connect()) as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT payload_json FROM outbox ORDER BY created_at")]

    def test_healthy_daily_report_durable_dedup_and_korean(self):
        first = self.run_producer()
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["hourly"]["enqueued"], 1)
        self.assertEqual(first["immediate"]["enqueued"], 0)
        self.assertEqual(first["delivery"]["pending"], 1)
        self.assertEqual(first["delivery"]["sent"], 0)
        self.assertIn("정상", self.queued()[0]["presentation"]["body"])
        self.assertIn("09/13 18:00:00 KST", self.queued()[0]["presentation"]["body"])
        # New module invocation/outbox instance simulates collector restart.
        again = self.run_producer(NOW + dt.timedelta(seconds=30))
        self.assertEqual(again["hourly"]["enqueued"], 0)
        self.refresh(NOW + dt.timedelta(hours=1))
        same_day = self.run_producer(NOW + dt.timedelta(hours=1))
        self.assertEqual(same_day["hourly"]["enqueued"], 0)
        self.refresh(NOW + dt.timedelta(days=1))
        next_day = self.run_producer(NOW + dt.timedelta(days=1))
        self.assertEqual(next_day["hourly"]["enqueued"], 1)
        self.assertEqual(len(self.queued()), 2)

    def test_warning_escalation_and_recovery_are_once(self):
        for minute, temperature, expected in (
                (0, 80, 0), (1, 80, 0), (2, 80, 0), (3, 80, 0), (4, 80, 1),
                (5, 85, 0), (6, 85, 1),
                (7, 75, 0), (8, 75, 0), (9, 75, 0), (10, 75, 0), (11, 75, 0),
                (12, 75, 1)):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, temperature)
            recovered = self.run_producer(now)
            self.assertEqual(recovered["immediate"]["enqueued"], expected, minute)
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], 0)
        self.assertEqual(recovered["detections"][0]["status"], "resolved")
        self.assertIn("해소 전 마지막 이상 관측: 온도 85°C", recovered["detections"][0]["evidence"])

    def test_ssh_episode_and_source_loss_do_not_false_recover(self):
        self.write("generic-logs.jsonl", ssh_row("User root from [REDACTED_IP] not allowed because not listed in AllowUsers"))
        first = self.run_producer()
        self.assertEqual(first["immediate"]["enqueued"], 0)  # One refused login remains in the report.
        self.assertEqual(first["detections"][0]["kind"], "ssh-auth-attempt")
        self.assertEqual(self.run_producer()["immediate"]["enqueued"], 0)
        later = NOW + dt.timedelta(minutes=10)
        self.refresh(later)
        self.write("generic-log-sources.json", {"generatedAt": reports._iso(later), "sources": []})
        unavailable = self.run_producer(later)
        unavailable = self.run_producer(later)
        self.assertTrue(any(row["kind"] == "ssh-auth-attempt" and row["status"] == "active"
                            for row in unavailable["detections"]))
        self.assertEqual(unavailable["sourceHealth"][2]["status"], "unavailable")

    def test_existing_rule_delivery_identity_and_excluded_target(self):
        rule = event(observed_at=reports._iso(NOW))
        rule["openedAt"] = reports._iso(NOW)
        excluded = {**rule, "target": "container/wgang"}
        (self.root / "rule-alerts.jsonl").write_text(json.dumps(rule) + "\n" + json.dumps(excluded))
        (self.root / "rule-alerts.jsonl").chmod(0o600)
        config = delivery.parse_delivery_config(self.config)
        delivery.enqueue_operational_events(self.outbox(), config, [rule], NOW)
        result = self.run_producer()
        self.assertEqual(result["immediate"]["deduplicated"], 1)
        self.assertEqual(len(self.queued()), 2)  # existing rule plus hourly
        self.assertNotIn("wgang", json.dumps(result))

    def test_transaction_rollback_does_not_consume_hour_or_warning(self):
        self.current["system"] = {"reboot": {"status": "ok", "required": True, "observedAt": reports._iso(NOW)}}
        real = delivery.DeliveryOutbox._enqueue_prepared
        calls = []
        def fail_after_insert(outbox, connection, prepared, **kwargs):
            value = real(outbox, connection, prepared, **kwargs)
            calls.append(value)
            raise sqlite3.OperationalError("simulated crash")
        with mock.patch.object(delivery.DeliveryOutbox, "_enqueue_prepared", fail_after_insert):
            self.assertEqual(self.run_producer()["status"], "error")
        self.assertEqual(self.queued(), [])
        result = self.run_producer()
        self.assertEqual(result["hourly"]["enqueued"], 1)
        self.assertEqual(result["immediate"]["enqueued"], 1)

    def test_disabled_no_secret_lookup_and_enable_sends_active(self):
        self.config["channels"][0]["enabled"] = False
        self.write("delivery.json", self.config)
        self.current["system"] = {"reboot": {"status": "ok", "required": True, "observedAt": reports._iso(NOW)}}
        with mock.patch.object(delivery, "resolve_secret", side_effect=AssertionError("secret access")):
            disabled = self.run_producer()
        self.assertEqual(disabled["status"], "disabled")
        self.assertEqual(len(disabled["detections"]), 1)
        self.assertEqual(self.queued(), [])
        self.config["channels"][0]["enabled"] = True
        self.write("delivery.json", self.config)
        result = self.run_producer()
        self.assertEqual(result["hourly"]["enqueued"], 1)
        self.assertEqual(result["immediate"]["enqueued"], 1)

    def test_presentation_survives_validation_and_fake_smtp(self):
        self.run_producer()
        task = self.outbox().claim_due(NOW, "tests")[0]
        payload = delivery._validated_payload(task)
        fake = mock.Mock()
        fake.send_message.return_value = {}
        adapter = delivery.SmtpAdapter(smtp_ssl_factory=mock.Mock(return_value=fake))
        result = adapter.send(delivery.parse_delivery_config(self.config).channels[0], task, payload, "fake-secret")
        self.assertEqual(result.outcome, "success")
        message = fake.send_message.call_args.args[0]
        self.assertIn("일일 보고", str(message["Subject"]))
        self.assertIn("CPU · 관측: 20%", message.get_body(preferencelist=("plain",)).get_content())
        self.assertNotIn("fake-secret", str(message))
        with self.assertRaises(ValueError):
            delivery._normalize_presentation({"subject": "bad\nBcc: other", "body": "safe"})

    def test_stale_snapshot_mail_marks_coverage_instead_of_healthy(self):
        later = NOW + dt.timedelta(minutes=10)
        result = self.run_producer(later)
        self.assertEqual(result["status"], "ok")
        hourly = next(item for item in self.queued() if item["event"]["ruleId"] == "HourlyReport")
        self.assertIn("관측 불가", hourly["presentation"]["subject"])
        self.assertNotIn("CPU: 20%", hourly["presentation"]["body"])

    def test_missing_metric_and_repeated_snapshot_cannot_clear_warning(self):
        self.refresh_temperature(NOW, 80)
        self.run_producer()
        for minute in (1, 2):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, None)
            status = self.run_producer(now)
            self.assertEqual(status["immediate"]["enqueued"], 0)
            self.assertEqual(status["detections"][0]["status"], "active")
        now = NOW + dt.timedelta(minutes=3)
        self.refresh_temperature(now, 75)
        self.run_producer(now)
        status = self.run_producer(now)
        self.assertEqual(status["immediate"]["enqueued"], 0)
        self.assertEqual(status["detections"][0]["status"], "active")

    def test_old_current_rule_delivered_on_enable_with_original_identity(self):
        old = reports._iso(NOW - dt.timedelta(hours=1))
        rule = event(observed_at=old)
        rule["openedAt"] = old
        self.write("rule-alerts.jsonl", rule)
        self.evaluation["states"] = {"CpuUsageHigh:host/node-a": {
            "ruleId": "CpuUsageHigh", "target": "host/node-a", "openedAt": old,
            "phase": "firing", "severity": "warning"}}
        first = self.run_producer()
        self.assertEqual(first["immediate"]["enqueued"], 1)
        self.assertEqual(self.run_producer()["immediate"]["enqueued"], 0)
        self.assertIn(rule["idempotencyKey"], [row["event"]["idempotencyKey"] for row in self.queued()])

    def test_reboot_caution_dedup_unknown_and_hourly_history(self):
        reboot = {"status": "ok", "required": True, "observedAt": reports._iso(NOW),
                  "packages": ["linux-image-rpi", "wgang-package"]}
        self.current["system"] = {"reboot": reboot, "kernel": {"rcuExpedited": {
            "count": 1, "lastEventAt": "2026-09-09T12:10:34Z"}}}
        first = self.run_producer()
        self.assertEqual(first["immediate"]["enqueued"], 1)
        self.assertEqual(self.run_producer()["immediate"]["enqueued"], 0)
        hourly = next(row for row in self.queued() if row["event"]["ruleId"] == "HourlyReport")
        self.assertIn("재부팅 필요: 예", hourly["presentation"]["body"])
        self.assertIn("RCU 지연 이력 1건", hourly["presentation"]["body"])
        self.assertNotIn("wgang", str(self.queued()))
        reboot["required"] = None
        for minute in (1, 2):
            now = NOW + dt.timedelta(minutes=minute)
            self.current["generatedAt"] = reboot["observedAt"] = reports._iso(now)
            status = self.run_producer(now)
            self.assertEqual(status["immediate"]["enqueued"], 0)
            self.assertTrue(any(item["status"] == "active" for item in status["detections"]))

    def test_known_idle_http_source_is_healthy(self):
        self.current["currentTraffic"] = []
        status = reports.produce_notifications(self.root, NOW, current=self.current,
                  evaluation=self.evaluation, delivery_config_path=self.config_path, traffic_available=True)
        self.assertEqual(status["sourceHealth"][3]["status"], "fresh")
        self.assertEqual(status["immediate"]["enqueued"], 0)

    def test_queue_full_does_not_consume_hour_and_warning_retries_same_identity(self):
        self.config["queue"]["maxPending"] = 1
        self.write("delivery.json", self.config)
        config = delivery.parse_delivery_config(self.config)
        blocker = event("blocker", severity="critical", observed_at=reports._iso(NOW))
        blocker["openedAt"] = reports._iso(NOW)
        self.outbox().enqueue(blocker, config.channels[0], "operational", NOW)
        self.current["system"] = {"reboot": {"status": "ok", "required": True, "observedAt": reports._iso(NOW)}}
        full = self.run_producer()
        self.assertEqual(full["hourly"]["enqueued"], 0)
        self.assertEqual(full["hourly"]["dropped"], 1)
        self.assertIsNone(full["hourly"]["lastQueuedAt"])
        self.assertEqual(full["immediate"]["dropped"], 1)
        dropped_key = next(row["event"]["idempotencyKey"] for row in self.queued()
                           if row["event"]["ruleId"] == "OperationalCaution")
        outbox = self.outbox()
        task = outbox.claim_due(NOW, "tests")[0]
        outbox.complete(task, delivery.DeliveryResult.success(), NOW)
        retry = self.run_producer()
        self.assertEqual(retry["immediate"]["enqueued"], 1)
        warning = outbox.claim_due(NOW, "tests")[0]
        self.assertEqual(warning.event_key, dropped_key)
        outbox.complete(warning, delivery.DeliveryResult.success(), NOW)
        retry = self.run_producer()
        self.assertEqual(retry["hourly"]["enqueued"], 1)
        self.assertEqual(retry["immediate"]["enqueued"], 0)
        self.assertEqual(retry["delivery"]["sent"], 2)
        self.assertEqual(len(self.queued()), 3)

    def test_evicted_hourly_is_readmitted_after_warning_delivery(self):
        self.config["queue"]["maxPending"] = 1
        self.write("delivery.json", self.config)
        self.run_producer()
        self.refresh(NOW + dt.timedelta(minutes=1))
        self.current["system"] = {"reboot": {"status": "ok", "required": True,
                                            "observedAt": reports._iso(NOW + dt.timedelta(minutes=1))}}
        self.run_producer(NOW + dt.timedelta(minutes=1))
        outbox = self.outbox()
        task = outbox.claim_due(NOW + dt.timedelta(minutes=1), "tests")[0]
        self.assertEqual(task.payload["event"]["ruleId"], "OperationalCaution")
        outbox.complete(task, delivery.DeliveryResult.success(), NOW + dt.timedelta(minutes=1))
        retry = self.run_producer(NOW + dt.timedelta(minutes=1))
        self.assertEqual(retry["hourly"]["enqueued"], 1)
        self.assertEqual(len(self.queued()), 2)

    def test_truncated_recent_log_window_reports_partial_coverage(self):
        self.write("generic-logs.jsonl", {"timestamp": reports._iso(NOW),
                   "sourceId": "journal:monitor-collector", "message": "x" * 600})
        with mock.patch.object(reports, "MAX_LOG_TAIL_BYTES", 512):
            status = self.run_producer()
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["sourceHealth"][2]["status"], "partial")
        self.assertEqual(status["detections"][0]["kind"], "source-unavailable")

    def test_legacy_direct_tcp_state_retires_without_recovery_mail(self):
        self.run_producer()
        key = "tcp:retransmission"
        legacy = {
            "id": "c" * 64, "kind": "operational-caution", "severity": "warning",
            "status": "active", "openedAt": reports._iso(NOW), "observedAt": reports._iso(NOW),
            "count": 8, "windowSeconds": 300, "evidence": "legacy TCP retransmission",
            "source": "snapshot", "notifiedSeverity": "warning",
        }
        with contextlib.closing(self.outbox()._connect()) as connection:
            state = json.loads(connection.execute(
                "SELECT value FROM notification_producer_state WHERE id=1"
            ).fetchone()[0])
            state["active"][key] = legacy
            state["recent"] = [legacy]
            connection.execute("UPDATE notification_producer_state SET value=? WHERE id=1",
                               (json.dumps(state),))
        now = NOW + dt.timedelta(minutes=1)
        self.refresh(now)
        result = self.run_producer(now)
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertNotIn(key, reports._readonly_producer_state(self.root)["active"])
        retired = next(row for row in result["detections"] if row["id"] == legacy["id"])
        self.assertEqual(retired["status"], "resolved")
        self.assertIn("TcpRetransmissionHigh", retired["evidence"])
        self.assertFalse(any(row["event"]["ruleId"] == "OperationalCaution"
                             for row in self.queued()))

    def test_legacy_resolved_projection_updates_public_and_mail_without_rewriting_stored_evidence(self):
        legacy = "복구: TCP 재전송률: 8.696%. 최신 관측 기준입니다. 새 관측에서 조건이 해제되었습니다."
        self.run_producer()
        now = NOW + dt.timedelta(minutes=1)
        resolved = {
            "id": "b" * 64, "kind": "operational-caution", "severity": "warning",
            "status": "resolved", "openedAt": reports._iso(NOW), "observedAt": reports._iso(now),
            "count": 0, "windowSeconds": 300, "evidence": legacy,
        }
        with contextlib.closing(self.outbox()._connect()) as connection:
            state = json.loads(connection.execute("SELECT value FROM notification_producer_state WHERE id=1").fetchone()[0])
            state["recent"] = [resolved]
            connection.execute("UPDATE notification_producer_state SET value=? WHERE id=1", (json.dumps(state),))
        self.refresh(now)
        status = self.run_producer(now)
        evidence = status["detections"][0]["evidence"]
        self.assertIn("해소 전 마지막 이상 관측: TCP 재전송률: 8.696%", evidence)
        self.assertNotIn("최신 관측 기준", evidence)
        with contextlib.closing(self.outbox()._connect()) as connection:
            stored = json.loads(connection.execute("SELECT value FROM notification_producer_state WHERE id=1").fetchone()[0])
        self.assertEqual(stored["recent"][0]["evidence"], legacy)
        mail = reports._immediate_presentation(event(transition="resolved"), legacy)
        self.assertIn("해소 전 마지막 이상 관측", mail["body"])
        self.assertNotIn("최신 관측 기준", mail["body"])
        self.assertEqual(reports._project_legacy_recovery(evidence), evidence)
        unrelated = "외부 규칙 복구: 현재 정상으로 관측됨"
        self.assertEqual(reports._project_legacy_recovery(unrelated), unrelated)
        bounded = reports._project_legacy_recovery("복구: " + "x" * 600 + " 새 관측에서 조건이 해제되었습니다.")
        self.assertLessEqual(len(bounded), 500)

    def test_one_sample_cpu_spike_has_no_firing_or_recovery_mail(self):
        for minute, cpu in ((0, 99), (1, 20), (2, 20)):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh(now, cpu)
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], 0)
        self.assertEqual([row["event"]["ruleId"] for row in self.queued()], ["HourlyReport"])

    def test_missing_repeated_or_backdated_data_cannot_qualify_warning(self):
        self.refresh_temperature(NOW, 80)
        self.run_producer()
        for minute in (1, 2):
            self.assertEqual(self.run_producer(NOW + dt.timedelta(minutes=minute))["immediate"]["enqueued"], 0)
        self.refresh_temperature(NOW - dt.timedelta(seconds=30), 85)
        self.run_producer(NOW)
        self.refresh_temperature(NOW + dt.timedelta(minutes=3), None)
        self.run_producer(NOW + dt.timedelta(minutes=3))
        for minute in (4, 5):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, 80)
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], 0)
        self.refresh_temperature(NOW + dt.timedelta(minutes=6), 80)
        self.assertEqual(self.run_producer(NOW + dt.timedelta(minutes=6))["immediate"]["enqueued"], 1)

    def test_warning_cooldown_persists_but_critical_escalation_can_notify(self):
        for minute, temperature, expected in (
                (0, 80, 0), (1, 80, 0), (2, 80, 1),
                (3, 75, 0), (4, 75, 0), (5, 75, 1),
                (6, 80, 0), (7, 80, 0), (8, 80, 0),
                (9, 85, 0), (10, 85, 0), (11, 85, 1)):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, temperature)
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], expected, minute)

    def test_synthetic_latency_mail_is_owned_only_by_canonical_rule(self):
        self.config["routes"][0]["excludeRuleIds"] = ["TcpRetransmissionHigh"]
        self.write("delivery.json", self.config)
        for minute in range(5):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh(now)
            checked = NOW + dt.timedelta(minutes=minute, milliseconds=-357)
            checked_text = checked.isoformat().replace("+00:00", "Z")
            self.current["syntheticProbeCollection"] = {"status": "fresh", "observedAt": checked_text}
            self.current["syntheticProbes"] = [{"id": "public-monitor-readiness", "status": "ok",
                "checkedAt": checked_text, "latencyMilliseconds": 1200,
                "certificateDaysRemaining": 90}]
            if minute == 4:
                rule = event("synthetic-rule", observed_at=reports._iso(now))
                rule.update({"ruleId": "HttpLatencyHigh", "target": "synthetic/public-monitor-readiness"})
                self.write("rule-alerts.jsonl", rule)
            status = self.run_producer(now)
            self.assertEqual(status["status"], "ok", minute)
            self.assertEqual(status["immediate"]["enqueued"], 1 if minute == 4 else 0, minute)
        messages = [row for row in self.queued() if row["event"]["ruleId"] != "HourlyReport"]
        self.assertEqual([row["event"]["ruleId"] for row in messages], ["HttpLatencyHigh"])
        self.assertFalse(any(row["event"]["ruleId"] == "OperationalCaution" for row in messages))

    def test_synthetic_availability_mail_is_owned_only_by_canonical_rule(self):
        for minute in range(3):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh(now)
            checked = NOW + dt.timedelta(minutes=minute, milliseconds=-357)
            checked_text = checked.isoformat().replace("+00:00", "Z")
            self.current["syntheticProbeCollection"] = {"status": "fresh", "observedAt": checked_text}
            self.current["syntheticProbes"] = [{"id": "public-monitor-readiness", "status": "timeout",
                "checkedAt": checked_text, "latencyMilliseconds": 10000,
                "certificateDaysRemaining": 90}]
            if minute == 2:
                rule = event("synthetic-availability-rule", observed_at=reports._iso(now))
                rule.update({"ruleId": "HttpEndpointDown",
                             "target": "synthetic/public-monitor-readiness"})
                self.write("rule-alerts.jsonl", rule)
            status = self.run_producer(now)
            self.assertEqual(status["immediate"]["enqueued"], 1 if minute == 2 else 0, minute)
            self.assertFalse(any(key.startswith("synthetic:") and key.endswith(":status")
                                 for key in reports._readonly_producer_state(self.root)["active"]))
        messages = [row for row in self.queued() if row["event"]["ruleId"] != "HourlyReport"]
        self.assertEqual([row["event"]["ruleId"] for row in messages], ["HttpEndpointDown"])

    def test_canonical_rules_own_duplicate_direct_signals(self):
        owners = {
            "tcp:retransmission": "TcpRetransmissionHigh",
            "host:networkRxErrorsPerSecond": "NetworkErrorsHigh",
            "host:networkTxDroppedPerSecond": "NetworkDropsHigh",
            "collection:container": "DockerDaemonUnavailable",
            "collection:synthetic": "HttpEndpointDown",
            "ssh-foreign-attempt": "ssh-auth",
            "synthetic:0123456789ab:certificate": "TlsCertificateExpiring",
            "container:0123456789ab:state": "ContainerDown",
            "container:0123456789ab:health": "ContainerUnhealthy",
            "container:0123456789ab:oom": "ContainerOOMKilled",
            "container:0123456789ab:restarts": "ContainerRestartLoop",
            "container:0123456789ab:cpu-throttle": "ContainerCpuThrottlingHigh",
            "container:0123456789ab:network-errors": "ContainerNetworkErrors",
            "container:0123456789ab:memory": "ContainerMemoryNearLimit",
            "container:0123456789ab:pids": "ContainerPidNearLimit",
        }
        for key, owner in owners.items():
            with self.subTest(key=key):
                self.assertIn(owner, reports._retired_signal_reason(key))

    def test_sustained_docker_event_gap_fires_and_recovers_once(self):
        for minute, gap, expected in ((0, True, 0), (1, True, 0), (2, True, 1),
                                      (3, False, 0), (4, False, 1)):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh(now)
            self.current["dockerEventCollection"] = {
                "status": "gap" if gap else "fresh", "observedAt": reports._iso(now),
                "gapDetected": gap, "gapCount": 1,
            }
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], expected, minute)
        messages = [row for row in self.queued()
                    if row["event"]["ruleId"] == "OperationalCaution"]
        self.assertEqual([row["event"]["transition"] for row in messages], ["firing", "resolved"])

    def test_one_kernel_warning_event_is_not_recounted_each_minute(self):
        event_at = reports._iso(NOW)
        for minute in range(8):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh(now)
            self.current["linux"] = {
                "collectedAt": reports._iso(now),
                "eventSources": {"kernelLogStatus": "supported"},
            }
            self.current["system"] = {"kernel": {"warning": {
                "count": 1, "lastEventAt": event_at,
            }}}
            self.assertEqual(self.run_producer(now)["immediate"]["enqueued"], 0, minute)
        self.assertTrue(any(row["status"] == "resolved" for row in
                            self.run_producer(NOW + dt.timedelta(minutes=7))["detections"]))

    def test_availability_requires_two_samples_but_ssh_burst_remains_immediate(self):
        self.current["reliability"] = {"networkLinkAvailable": False}
        self.assertEqual(self.run_producer()["immediate"]["enqueued"], 0)
        later = NOW + dt.timedelta(minutes=1)
        self.refresh(later)
        self.current["reliability"] = {"networkLinkAvailable": False}
        self.assertEqual(self.run_producer(later)["immediate"]["enqueued"], 1)
        rows = [ssh_row("Failed password for invalid user account", -index) for index in range(20)]
        path = self.root / "generic-logs.jsonl"
        path.write_text("\n".join(json.dumps(row) for row in rows))
        path.chmod(0o600)
        self.assertEqual(self.run_producer(later)["immediate"]["enqueued"], 1)
        self.assertTrue(any(row["event"]["ruleId"] == "SecurityPattern" and
                            row["event"]["severity"] == "warning" for row in self.queued()))

    def preview(self, now):
        self.write("current.json", self.current)
        self.write("rule-evaluation.json", self.evaluation)
        database = self.root / ".state/alert-delivery/alert-delivery.sqlite"
        before = database.read_bytes() if database.exists() else None
        with mock.patch.object(delivery, "DeliveryOutbox", side_effect=AssertionError("preview cannot create an outbox")), \
             mock.patch.object(delivery, "resolve_secret", side_effect=AssertionError("preview cannot read credentials")):
            presentation = reports.build_hourly_presentation(self.root, now)
        self.assertEqual(before, database.read_bytes() if database.exists() else None)
        return presentation

    def test_hourly_and_preview_share_qualified_incidents_and_recovery(self):
        for minute, temperature, expected in (
                (0, 80, "warning"), (1, 80, "warning"), (2, 80, "warning"),
                (3, 85, "warning"), (4, 85, "warning"), (5, 85, "critical"),
                (6, None, "critical"), (7, 75, "critical"),
                (8, 75, "critical"), (9, 75, "warning")):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, temperature)
            result = self.run_producer(now)
            self.assertEqual(result["status"], "ok")
            preview = self.preview(now)
            self.assertEqual(preview["visual"]["status"], expected, minute)
            self.assertIn("위험" if expected == "critical" else "주의", preview["subject"])
            if minute == 0:
                # Other intentionally absent fixture metrics are coverage caution,
                # not an emergency from the first temperature observation.
                hourly = self.queued()[0]["presentation"]
                self.assertEqual(hourly["visual"]["status"], expected)
                self.assertEqual(hourly["visual"]["cards"][0]["tone"], "neutral")
                self.assertEqual(result["immediate"]["enqueued"], 0)
            if minute == 6:
                self.assertEqual(preview["visual"]["cards"][0]["tone"], "neutral")
                active = reports._readonly_producer_state(self.root)["active"]["host:temperatureC"]
                self.assertEqual(active["qualifiedSeverity"], "critical")
            if minute == 7:
                self.assertIn("복구 확인 중", preview["body"])
                self.assertEqual(preview["visual"]["cards"][0]["tone"], "neutral")
        self.assertFalse(any(row["status"] == "active" for row in result["detections"]))

    def test_hourly_does_not_promote_first_critical_sample_after_warning(self):
        for minute, temperature, expected in (
                (0, 80, "warning"), (1, 80, "warning"), (2, 80, "warning"),
                (3, 85, "warning"), (4, 85, "warning"), (5, 85, "critical")):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, temperature)
            self.run_producer(now)
            preview = self.preview(now)
            self.assertEqual(preview["visual"]["status"], expected, minute)
            if minute == 3:
                active = reports._readonly_producer_state(self.root)["active"]["host:temperatureC"]
                self.assertEqual(active["qualifiedSeverity"], "warning")

    def test_confirmed_severity_does_not_depend_on_delivery_enabled(self):
        self.config["channels"][0]["enabled"] = False
        self.write("delivery.json", self.config)
        for minute in (0, 1, 2):
            now = NOW + dt.timedelta(minutes=minute)
            self.refresh_temperature(now, 85)
            self.assertEqual(self.run_producer(now)["status"], "disabled")
        self.assertEqual(self.queued(), [])
        self.assertEqual(self.preview(now)["visual"]["status"], "critical")

    def test_public_raw_critical_is_not_preview_authority(self):
        self.write("notification-reports.json", {"observedAt": reports._iso(NOW), "sourceHealth": [],
                   "detections": [{"id": "raw", "status": "active", "severity": "critical",
                                   "evidence": "first CPU sample"}]})
        presentation = self.preview(NOW)
        self.assertNotEqual(presentation["visual"]["status"], "critical")
        self.assertFalse((self.root / ".state").exists())

    def test_warning_threshold_text_does_not_claim_critical_was_exceeded(self):
        alarm = reports._event("OperationalCaution", "test", "warning", reports._iso(NOW),
                               reports._iso(NOW), "I/O PSI full 1.08%; 주의 1, 위험 8 기준 초과.")
        mail = reports._immediate_presentation(alarm, alarm["description"])
        self.assertIn("[Monitor 주의]", mail["subject"])
        self.assertIn("판정 기준: 주의 1 / 위험 8", mail["body"])
        self.assertNotIn("위험 8 기준 초과", str(mail))


if __name__ == "__main__":
    unittest.main()
