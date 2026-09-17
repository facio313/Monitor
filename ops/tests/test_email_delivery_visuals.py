import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import alert_delivery as delivery
from ops.tests.test_alert_delivery import NOW, channel, config_value, event


def visual():
    return {
        "schemaVersion": 1, "kind": "hourly", "theme": "light", "status": "warning",
        "title": "확인할 항목이 있습니다", "subtitle": "최근 1시간 · 실제 수집 기록",
        "cards": [{"label": "CPU", "value": "25", "unit": "%", "tone": "ok"}],
        "highlights": ["재부팅 필요 상태를 유지보수 시간에 확인하세요."],
        "sources": [{"label": "서버", "status": "fresh"}],
        "trend": {"from": "2026-08-30T11:00:00Z", "to": "2026-08-30T12:00:00Z",
                  "cpu": [float(i) for i in range(30)], "memory": [30.0] * 30,
                  "tcp": [None] * 4 + [0.15] * 26},
    }


class VisualDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.config = delivery.parse_delivery_config(config_value(
            channels=[channel("smtp-mail", "smtp")], lease_seconds=90))
        self.channel = self.config.channels[0]
        self.presentation = {"subject": "Monitor 디자인", "body": "완전한 텍스트 대체 본문", "visual": visual()}

    def payload(self):
        return {"schemaVersion": 1, "purpose": "test", "test": True, "event": event(),
                "presentation": delivery._normalize_presentation(self.presentation)}

    def test_legacy_and_new_presentations_are_validated_at_both_boundaries(self):
        self.assertEqual(delivery._normalize_presentation({"subject": "old", "body": "old text"}),
                         {"subject": "old", "body": "old text"})
        with tempfile.TemporaryDirectory() as directory:
            outbox = delivery.DeliveryOutbox(Path(directory) / "outbox.sqlite", self.config.queue)
            outbox.enqueue(event(), self.channel, "operational", NOW, self.presentation)
            task = outbox.claim_due(NOW, "worker", 1)[0]
            result = delivery._validated_payload(task)
            self.assertEqual(result["presentation"]["visual"]["trend"]["cpu"], list(map(float, range(30))))
            self.assertEqual(delivery._message_text(result), self.presentation["body"])
        for extra in ({"html": "<script>bad</script>"}, {"visual": {"html": "bad"}}):
            bad = {**self.presentation, **extra}
            with self.assertRaises(ValueError):
                delivery._normalize_presentation(bad)

    def test_multipart_message_keeps_text_and_binds_each_inline_png(self):
        with mock.patch.object(delivery, "resolve_secret", side_effect=AssertionError("No secret needed")):
            message = delivery.build_smtp_message(self.channel, self.payload(), "a" * 64)
        self.assertEqual(message.get_content_type(), "multipart/alternative")
        self.assertEqual(message.get_body(preferencelist=("plain",)).get_content().strip(), self.presentation["body"])
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("CPU", html)
        self.assertIn("Monitor", html)
        images = [part for part in message.walk() if part.get_content_type() == "image/png"]
        self.assertGreaterEqual(len(images), 1)
        self.assertLessEqual(len(images), 2)
        for part in images:
            content_id = str(part["Content-ID"]).strip("<>")
            self.assertIn("cid:" + content_id, html)
            self.assertEqual(part.get_content_disposition(), "inline")
            self.assertTrue(part.get_payload(decode=True).startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual(str(message["Message-ID"]), "<monitor." + "a" * 64 + "@localhost>")
        self.assertLess(len(message.as_bytes()), 600 * 1024)

    def test_visual_failure_falls_back_without_losing_text_or_headers(self):
        failures = [ValueError("bad visual"), ("x" * (61 * 1024), []),
                    ("<p>safe</p>", [("bad\nheader", b"\x89PNG\r\n\x1a\n")])]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with mock.patch.object(delivery.email_visuals, "render_email", **kwargs):
                    message = delivery.build_smtp_message(self.channel, self.payload(), "b" * 64)
                self.assertEqual(message.get_content_type(), "text/plain")
                self.assertEqual(message.get_content().strip(), self.presentation["body"])
                self.assertEqual(str(message["Subject"]), self.presentation["subject"])

    def test_optional_visual_is_dropped_at_existing_sqlite_envelope_cap(self):
        supplied = copy.deepcopy(self.presentation)
        supplied["body"] = "x" * 10000
        model = supplied["visual"]
        model.update(title="가" * 80, subtitle="가" * 120, highlights=["가" * 160] * 4, trend=None)
        model["cards"] = [{"label": "가" * 24, "value": "가" * 12, "unit": "%", "tone": "ok"}] * 4
        normalized = delivery._normalize_presentation(supplied)
        oversized_event = event()
        oversized_event.update(description="나" * 500, runbook="다" * 500)
        with tempfile.TemporaryDirectory() as directory:
            outbox = delivery.DeliveryOutbox(Path(directory) / "outbox.sqlite", self.config.queue)
            disposition = outbox.enqueue(oversized_event, self.channel, "operational", NOW, supplied)
            self.assertEqual(disposition, "enqueued")
            task = outbox.claim_due(NOW, "worker", 1)[0]
            self.assertNotIn("visual", task.payload["presentation"])
            self.assertEqual(task.payload["presentation"]["body"], supplied["body"])
            self.assertIn("visual", normalized)
            self.assertLessEqual(len(json.dumps(task.payload, ensure_ascii=False, separators=(",", ":")).encode()), 16384)

    def test_design_preview_remains_a_deduplicated_test_not_an_operational_incident(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = delivery.DeliveryOutbox(Path(directory) / "outbox.sqlite", self.config.queue)
            first = delivery.enqueue_test_delivery(outbox, self.config, "smtp-mail", "design-preview",
                                                   "Design preview only", NOW, self.presentation)
            second = delivery.enqueue_test_delivery(outbox, self.config, "smtp-mail", "design-preview",
                                                    "Design preview only", NOW, self.presentation)
            self.assertEqual(first[0], "enqueued")
            self.assertEqual(second[0], "deduplicated")
            task = outbox.claim_due(NOW, "worker", 1)[0]
            self.assertEqual(task.purpose, "test")
            self.assertEqual(task.payload["event"]["ruleId"], "TestNotification")
            self.assertIn("visual", task.payload["presentation"])

    def test_renderer_modules_participate_in_install_preflight_and_rollback(self):
        ops = Path(__file__).resolve().parents[1]
        installer = (ops / "install.sh").read_text()
        uninstaller = (ops / "uninstall.sh").read_text()
        transaction = installer.index("\ntransaction_started=true\n")
        for name in ("email_visuals", "notification_visuals"):
            self.assertIn(f'"$script_dir/{name}.py"', installer)
            self.assertIn(f'"${name}_target" \\', installer)
            self.assertLess(installer.index(f'restore_file "$backup_dir/{name}.py"'), transaction)
            self.assertLess(installer.index(f'"$backup_dir/{name}.py"; had_{name}=true'), transaction)
            self.assertGreater(installer.index(f'install -m 0644 "$script_dir/{name}.py"'), transaction)
            self.assertIn(f"/usr/local/lib/monitor-collector/{name}.py", uninstaller)
