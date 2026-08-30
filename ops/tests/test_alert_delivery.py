import contextlib
import datetime as dt
import io
import json
import os
import signal
import stat
import tempfile
import threading
import time as wall_time
import unittest
from pathlib import Path
from unittest import mock

from ops import alert_delivery


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


def channel(
    channel_id="ops-webhook", kind="webhook", max_attempts=3,
    base_backoff=10, max_backoff=25, secret_key="MONITOR_TEST_WEBHOOK",
):
    settings = {
        "webhook": {"headers": {"X-Monitor-Site": "test"}},
        "slack": {"username": "Monitor"},
        "discord": {"username": "Monitor"},
        "telegram": {"chatId": "-100123", "disableNotification": False},
        "smtp": {
            "host": "smtp.example.test", "port": 465,
            "from": "monitor@example.test", "to": ["ops@example.test"],
            "username": "monitor@example.test", "tlsMode": "implicit",
        },
    }[kind]
    return {
        "id": channel_id,
        "kind": kind,
        "enabled": True,
        "timeoutSeconds": 2,
        "maxAttempts": max_attempts,
        "baseBackoffSeconds": base_backoff,
        "maxBackoffSeconds": max_backoff,
        "secretRef": {"provider": "env", "key": secret_key},
        "settings": settings,
    }


def config_value(max_pending=10, channels=None, lease_seconds=10):
    channels = channels if channels is not None else [channel()]
    return {
        "schemaVersion": 1,
        "queue": {
            "maxPending": max_pending,
            "maxHistory": 20,
            "maxDeliveryLog": 40,
            "leaseSeconds": lease_seconds,
            "batchSize": 10,
            "replayWindowSeconds": 900,
        },
        "channels": channels,
        "routes": [{
            "id": "all-operational",
            "priority": 100,
            "enabled": True,
            "severities": ["info", "warning", "critical"],
            "transitions": ["firing", "resolved"],
            "labels": {},
            "channels": [item["id"] for item in channels],
            "continue": False,
        }] if channels else [],
    }


def event(
    suffix="a", severity="warning", notification="ready", transition="firing",
    observed_at="2026-08-30T12:00:00Z",
):
    key = (suffix * 64)[:64]
    if any(character not in "0123456789abcdef" for character in key):
        key = __import__("hashlib").sha256(suffix.encode()).hexdigest()
    return {
        "schemaVersion": 1,
        "rulePackVersion": "2026.08.30.test",
        "idempotencyKey": key,
        "ruleId": "CpuUsageHigh",
        "target": "host/node-a",
        "transition": transition,
        "severity": severity,
        "notificationState": notification,
        "observedAt": observed_at,
        "openedAt": "2026-08-30T12:00:00Z",
        "value": 95.0,
        "status": "ok",
        "labels": {"scope": "host"},
        "description": "CPU usage remains high.",
        "runbook": "Inspect load and bounded process groups.",
    }


class AlertDeliveryTests(unittest.TestCase):
    def outbox(self, root: Path, value=None):
        config = alert_delivery.parse_delivery_config(value or config_value())
        return alert_delivery.DeliveryOutbox(root / "outbox.sqlite", config.queue), config

    def test_config_has_all_channel_plugins_and_rejects_inline_secrets(self):
        channels = [
            channel("generic-hook", "webhook", secret_key="GENERIC_SECRET"),
            channel("slack-hook", "slack", secret_key="SLACK_SECRET"),
            channel("discord-hook", "discord", secret_key="DISCORD_SECRET"),
            channel("telegram-bot", "telegram", secret_key="TELEGRAM_SECRET"),
            channel("smtp-mail", "smtp", secret_key="SMTP_SECRET"),
        ]
        parsed = alert_delivery.parse_delivery_config(
            config_value(channels=channels, lease_seconds=90)
        )
        self.assertEqual({item.kind for item in parsed.channels}, alert_delivery.CHANNEL_KINDS)
        self.assertEqual(set(alert_delivery.DEFAULT_ADAPTERS), alert_delivery.CHANNEL_KINDS)

        inline = config_value()
        inline["channels"][0]["secretRef"]["value"] = "plaintext-secret"
        with self.assertRaisesRegex(ValueError, "schema"):
            alert_delivery.parse_delivery_config(inline)
        unsafe_header = config_value()
        unsafe_header["channels"][0]["settings"]["headers"] = {
            "Authorization": "Bearer plaintext-secret",
        }
        with self.assertRaisesRegex(ValueError, "unsafe header"):
            alert_delivery.parse_delivery_config(unsafe_header)
        endpoint = config_value()
        endpoint["channels"][0]["settings"]["url"] = "https://secret.example.test"
        with self.assertRaisesRegex(ValueError, "schema"):
            alert_delivery.parse_delivery_config(endpoint)

        example = alert_delivery.load_delivery_config(
            Path(__file__).parents[1] / "rules" / "alert-delivery.example.v1.json"
        )
        self.assertEqual(len(example.channels), 5)
        self.assertTrue(all(not item.enabled for item in example.channels))

    def test_smtp_lease_budget_counts_tls_and_every_recipient(self):
        smtp_channel = channel("smtp-mail", "smtp", secret_key="SMTP_SECRET")
        smtp_channel["timeoutSeconds"] = 5
        smtp_channel["settings"]["tlsMode"] = "starttls"
        smtp_channel["settings"]["to"] = [
            f"recipient-{index}@example.test" for index in range(20)
        ]
        boundary = config_value(channels=[smtp_channel], lease_seconds=250)
        parsed = alert_delivery.parse_delivery_config(boundary)
        self.assertEqual(parsed.queue.lease_seconds, 250)
        self.assertEqual(
            alert_delivery._required_channel_lease_seconds(parsed.channels[0]), 250,
        )

        boundary["queue"]["leaseSeconds"] = 249
        with self.assertRaisesRegex(ValueError, "too short"):
            alert_delivery.parse_delivery_config(boundary)

        smtp_channel["settings"]["tlsMode"] = "implicit"
        smtp_channel["timeoutSeconds"] = 10
        impossible = config_value(channels=[smtp_channel], lease_seconds=300)
        with self.assertRaisesRegex(ValueError, "too short"):
            alert_delivery.parse_delivery_config(impossible)

    def test_routing_deduplicates_and_never_queues_suppressed_or_silenced(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            first = alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            second = alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            skipped = alert_delivery.enqueue_operational_events(
                outbox,
                config,
                [event("b", notification="suppressed"), event("c", notification="silenced")],
                NOW,
            )
            self.assertEqual(first, {"enqueued": 1, "deduplicated": 0, "dropped": 0, "skipped": 0})
            self.assertEqual(second, {"enqueued": 0, "deduplicated": 1, "dropped": 0, "skipped": 0})
            self.assertEqual(skipped["skipped"], 2)
            self.assertEqual(outbox.status()["states"]["pending"], 1)
            self.assertEqual(stat.S_IMODE(outbox.path.stat().st_mode), 0o600)

    def test_delivery_failure_self_alerts_never_reenter_the_failed_outbox(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            for cycle in range(6):
                self_alert = event(
                    f"self-{cycle}",
                    severity="critical",
                    transition="firing" if cycle % 2 == 0 else "resolved",
                    observed_at=f"2026-08-30T12:0{cycle}:00Z",
                )
                self_alert["ruleId"] = "NotificationDeliveryFailure"
                result = alert_delivery.enqueue_operational_events(
                    outbox,
                    config,
                    [self_alert],
                    NOW + dt.timedelta(minutes=cycle),
                )
                self.assertEqual(result, {
                    "enqueued": 0,
                    "deduplicated": 0,
                    "dropped": 0,
                    "skipped": 1,
                })
                self.assertEqual(
                    alert_delivery.route_channels(config, self_alert), ()
                )
                self.assertTrue(
                    all(count == 0 for count in outbox.status()["states"].values())
                )

    def test_route_priority_and_continue_are_deterministic(self):
        value = config_value(channels=[
            channel("primary-hook", secret_key="PRIMARY_SECRET"),
            channel("secondary-hook", secret_key="SECONDARY_SECRET"),
        ])
        value["routes"] = [
            {
                "id": "fallback", "priority": 10, "enabled": True,
                "severities": ["warning"], "transitions": ["firing"],
                "labels": {}, "channels": ["secondary-hook"], "continue": False,
            },
            {
                "id": "host-first", "priority": 100, "enabled": True,
                "severities": ["warning"], "transitions": ["firing"],
                "labels": {"scope": "host"}, "channels": ["primary-hook"], "continue": False,
            },
        ]
        config = alert_delivery.parse_delivery_config(value)
        self.assertEqual(
            [item.channel_id for item in alert_delivery.route_channels(config, event())],
            ["primary-hook"],
        )
        value["routes"][1]["continue"] = True
        config = alert_delivery.parse_delivery_config(value)
        self.assertEqual(
            [item.channel_id for item in alert_delivery.route_channels(config, event())],
            ["primary-hook", "secondary-hook"],
        )

    def test_retry_backoff_retry_after_and_max_attempts_use_virtual_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            sender = mock.Mock(return_value=alert_delivery.DeliveryResult.retryable(
                "network_error", retry_after_seconds=5,
            ))
            first = alert_delivery.process_due(
                outbox, config, NOW, "worker-a", sender=sender, jitter=lambda: 0,
            )
            self.assertEqual(first["retryScheduled"], 1)
            self.assertEqual(outbox.claim_due(NOW + dt.timedelta(seconds=9), "worker-a"), [])

            second = alert_delivery.process_due(
                outbox, config, NOW + dt.timedelta(seconds=10), "worker-a",
                sender=sender, jitter=lambda: 0,
            )
            self.assertEqual(second["retryScheduled"], 1)
            self.assertEqual(outbox.claim_due(NOW + dt.timedelta(seconds=29), "worker-a"), [])

            third = alert_delivery.process_due(
                outbox, config, NOW + dt.timedelta(seconds=30), "worker-a",
                sender=sender, jitter=lambda: 0,
            )
            self.assertEqual(third["finalFailures"], 1)
            status = outbox.status()
            self.assertEqual(status["states"]["failed"], 1)
            self.assertEqual(status["stats"]["operational_final_failure"], 1)
            self.assertEqual(
                [item["outcome"] for item in reversed(outbox.delivery_log())],
                ["retry", "retry", "exhausted"],
            )

    def test_backoff_jitter_is_bounded_and_never_exceeds_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            value = config_value(channels=[channel(max_attempts=4)])
            outbox, config = self.outbox(Path(directory), value)
            alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            sender = lambda _task: alert_delivery.DeliveryResult.retryable("network_error")

            alert_delivery.process_due(
                outbox, config, NOW, "worker-a", sender=sender, jitter=lambda: 1,
            )
            self.assertEqual(outbox.claim_due(
                NOW + dt.timedelta(seconds=11, milliseconds=999), "probe-a",
            ), [])
            second_time = NOW + dt.timedelta(seconds=12)
            second = outbox.claim_due(second_time, "worker-a", 1)[0]
            outbox.complete(second, sender(second), second_time, lambda: 1)
            self.assertEqual(outbox.claim_due(
                NOW + dt.timedelta(seconds=35, milliseconds=999), "probe-b",
            ), [])
            third_time = NOW + dt.timedelta(seconds=36)
            third = outbox.claim_due(third_time, "worker-a", 1)[0]
            outbox.complete(third, sender(third), third_time, lambda: 1)
            self.assertEqual(outbox.claim_due(
                NOW + dt.timedelta(seconds=60, milliseconds=999), "probe-c",
            ), [])
            self.assertEqual(
                outbox.claim_due(NOW + dt.timedelta(seconds=61), "worker-a", 1)[0].attempt,
                4,
            )

    def test_expired_lease_recovers_after_crash_and_preserves_attempt_log(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            first = outbox.claim_due(NOW, "crashed-worker", 1)
            self.assertEqual(first[0].attempt, 1)
            self.assertEqual(outbox.claim_due(NOW + dt.timedelta(seconds=9), "worker-b", 1), [])
            recovered = outbox.claim_due(NOW + dt.timedelta(seconds=10), "worker-b", 1)
            self.assertEqual(recovered[0].attempt, 2)
            self.assertTrue(outbox.complete(
                recovered[0], alert_delivery.DeliveryResult.success(204),
                NOW + dt.timedelta(seconds=10),
            ))
            self.assertEqual(
                [item["outcome"] for item in reversed(outbox.delivery_log())],
                ["lease_expired", "success"],
            )
            self.assertEqual(outbox.status()["stats"]["lease_recovered"], 1)

    def test_concurrent_workers_claim_each_delivery_once(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            barrier = threading.Barrier(3)
            claimed = []
            errors = []

            def worker(worker_id):
                try:
                    barrier.wait()
                    claimed.extend(outbox.claim_due(NOW, worker_id, 1))
                except Exception as error:
                    errors.append(error)

            threads = [
                threading.Thread(target=worker, args=("worker-a",)),
                threading.Thread(target=worker, args=("worker-b",)),
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(claimed), 1)

    def test_queue_limit_evicts_only_lower_priority_and_accounts_drops(self):
        with tempfile.TemporaryDirectory() as directory:
            value = config_value(max_pending=2)
            outbox, config = self.outbox(Path(directory), value)
            channel_config = config.channels[0]
            self.assertEqual(outbox.enqueue(event("a", severity="info"), channel_config, "operational", NOW), "enqueued")
            self.assertEqual(outbox.enqueue(event("b", severity="warning"), channel_config, "operational", NOW), "enqueued")
            self.assertEqual(outbox.enqueue(event("c", severity="critical"), channel_config, "operational", NOW), "enqueued")
            self.assertEqual(outbox.enqueue(event("d", severity="info"), channel_config, "test", NOW), "dropped")
            status = outbox.status()
            self.assertEqual(status["states"]["pending"], 2)
            self.assertEqual(status["states"]["dropped"], 2)
            self.assertEqual(status["stats"]["queue_evicted"], 1)
            self.assertEqual(status["stats"]["queue_full"], 1)
            self.assertEqual(status["stats"]["test_dropped"], 1)

    def test_queue_eviction_appends_audit_without_replacing_retry_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(
                Path(directory), config_value(max_pending=1)
            )
            channel_config = config.channels[0]
            self.assertEqual(
                outbox.enqueue(
                    event("retry-victim", severity="info"),
                    channel_config,
                    "operational",
                    NOW,
                ),
                "enqueued",
            )
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            self.assertTrue(outbox.complete(
                task,
                alert_delivery.DeliveryResult.retryable("network_error"),
                NOW,
                lambda: 0,
            ))

            self.assertEqual(
                outbox.enqueue(
                    event("priority-replacement", severity="critical"),
                    channel_config,
                    "operational",
                    NOW + dt.timedelta(seconds=1),
                ),
                "enqueued",
            )

            victim_logs = [
                row for row in reversed(outbox.delivery_log())
                if row["delivery_key"] == task.delivery_key
            ]
            self.assertEqual(
                [(row["attempt"], row["outcome"]) for row in victim_logs],
                [(1, "retry"), (0, "evicted")],
            )

    def test_evaluator_enqueue_batch_is_bounded_and_accounts_overflow(self):
        channels = [
            channel(f"hook-{index}", secret_key=f"HOOK_{index}_SECRET")
            for index in range(3)
        ]
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(
                Path(directory), config_value(channels=channels),
            )
            with mock.patch.object(alert_delivery, "MAX_ENQUEUE_BATCH", 2):
                counts = alert_delivery.enqueue_operational_events(
                    outbox, config, [event()], NOW,
                )
            self.assertEqual(counts["enqueued"], 2)
            self.assertEqual(counts["dropped"], 1)
            status = outbox.status()
            self.assertEqual(status["states"]["pending"], 2)
            self.assertEqual(status["stats"]["enqueue_batch_overflow"], 1)
            self.assertEqual(status["stats"]["operational_dropped"], 1)

    def test_completed_rows_and_delivery_log_have_finite_retention(self):
        value = config_value(max_pending=1)
        value["queue"]["maxHistory"] = 10
        value["queue"]["maxDeliveryLog"] = 10
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory), value)
            channel_config = config.channels[0]
            for index in range(30):
                outbox.enqueue(
                    event(f"event-{index}"), channel_config, "operational", NOW,
                )
            status = outbox.status()
            self.assertEqual(status["states"]["pending"], 1)
            self.assertLessEqual(status["states"]["dropped"], 10)
            self.assertLessEqual(len(outbox.delivery_log(100)), 10)

    def test_delivery_log_prevents_reenqueue_after_outbox_history_prunes(self):
        value = config_value()
        value["queue"]["maxHistory"] = 10
        value["queue"]["maxDeliveryLog"] = 40
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory), value)
            channel_config = config.channels[0]
            first_event = event("completed-0")
            first_delivery_key = alert_delivery.delivery_identity(
                first_event["idempotencyKey"], channel_config.channel_id, "operational",
            )
            for index in range(11):
                observed_at = NOW + dt.timedelta(seconds=index)
                item = first_event if index == 0 else event(f"completed-{index}")
                self.assertEqual(
                    outbox.enqueue(item, channel_config, "operational", observed_at),
                    "enqueued",
                )
                task = outbox.claim_due(observed_at, "worker-a", 1)[0]
                self.assertTrue(outbox.complete(
                    task,
                    alert_delivery.DeliveryResult.success(204),
                    observed_at,
                ))

            with contextlib.closing(outbox._connect()) as connection:
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM outbox WHERE delivery_key = ?",
                    (first_delivery_key,),
                ).fetchone())
                self.assertIsNotNone(connection.execute(
                    "SELECT 1 FROM delivery_log WHERE delivery_key = ?",
                    (first_delivery_key,),
                ).fetchone())

            self.assertEqual(
                outbox.enqueue(
                    first_event,
                    channel_config,
                    "operational",
                    NOW + dt.timedelta(minutes=1),
                ),
                "deduplicated",
            )
            self.assertEqual(outbox.status()["states"].get("pending", 0), 0)

    def test_test_delivery_is_separate_and_deterministically_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            first, first_key, first_delivery_key = alert_delivery.enqueue_test_delivery(
                outbox, config, "ops-webhook", "ui-request-1", "Channel test", NOW,
            )
            second, second_key, second_delivery_key = alert_delivery.enqueue_test_delivery(
                outbox, config, "ops-webhook", "ui-request-1", "Channel test", NOW,
            )
            self.assertEqual((first, second), ("enqueued", "deduplicated"))
            self.assertEqual(first_key, second_key)
            self.assertEqual(first_delivery_key, second_delivery_key)
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            self.assertEqual(task.purpose, "test")
            self.assertTrue(task.payload["test"])
            self.assertEqual(outbox.status()["stats"], {"test_enqueued": 1})

    def test_secret_is_resolved_at_send_time_and_never_persisted_or_logged(self):
        secret = "https://delivery-secret.example.test/a-very-private-token"

        class RaisingAdapter:
            def send(self, _channel, _task, _payload, resolved_secret):
                raise RuntimeError(resolved_secret)

        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {"MONITOR_TEST_WEBHOOK": secret}, clear=False,
        ):
            outbox, config = self.outbox(Path(directory))
            alert_delivery.enqueue_operational_events(outbox, config, [event()], NOW)
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            result = alert_delivery.dispatch_task(
                config, task, adapters={"webhook": RaisingAdapter()},
            )
            self.assertEqual(result, alert_delivery.DeliveryResult.retryable("adapter_error"))
            outbox.complete(task, result, NOW, lambda: 0)
            self.assertNotIn(secret.encode(), outbox.path.read_bytes())
            self.assertEqual(outbox.delivery_log()[0]["error_code"], "adapter_error")

    def test_secret_file_requires_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "secret"
            secret.write_text("private-value\n", encoding="utf-8")
            secret.chmod(0o600)
            self.assertEqual(
                alert_delivery.resolve_secret(alert_delivery.SecretRef("file", str(secret))),
                "private-value",
            )
            secret.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                alert_delivery.resolve_secret(alert_delivery.SecretRef("file", str(secret)))

    def test_outbox_rejects_symlinked_file_or_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = alert_delivery.parse_delivery_config(config_value())
            outside = root / "outside.sqlite"
            outside.write_bytes(b"do-not-replace")
            outside.chmod(0o600)
            linked_file = root / "linked.sqlite"
            linked_file.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                alert_delivery.DeliveryOutbox(linked_file, config.queue)
            self.assertEqual(outside.read_bytes(), b"do-not-replace")

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory is unsafe"):
                alert_delivery.DeliveryOutbox(linked_parent / "outbox.sqlite", config.queue)

    def test_http_classification_and_retry_after_are_bounded(self):
        self.assertEqual(alert_delivery._classify_http_status(204).outcome, "success")
        self.assertEqual(alert_delivery._classify_http_status(429, 30).outcome, "retryable")
        self.assertEqual(alert_delivery._classify_http_status(503).outcome, "retryable")
        self.assertEqual(alert_delivery._classify_http_status(401).outcome, "permanent")

    def test_cli_test_and_status_are_payload_free_and_network_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "delivery.json"
            config_path.write_text(json.dumps(config_value()), encoding="utf-8")
            config_path.chmod(0o600)
            database = root / "outbox.sqlite"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = alert_delivery.run_cli([
                    "--config", str(config_path), "--db", str(database),
                    "test", "--channel", "ops-webhook",
                    "--request-id", "cli-request-1", "--message", "CLI test",
                ])
            self.assertEqual(result, 0)
            response = json.loads(output.getvalue())
            self.assertEqual(response["purpose"], "test")
            self.assertRegex(response["deliveryKey"], r"^[0-9a-f]{64}$")
            self.assertNotIn("CLI test", output.getvalue())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = alert_delivery.run_cli([
                    "--config", str(config_path), "--db", str(database), "status",
                ])
            self.assertEqual(result, 0)
            status = json.loads(output.getvalue())
            self.assertEqual(status["states"]["pending"], 1)
            self.assertNotIn("payload", output.getvalue().lower())

    def test_cli_drain_stops_claiming_when_its_monotonic_budget_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "delivery.json"
            config_path.write_text(json.dumps(config_value()), encoding="utf-8")
            config_path.chmod(0o600)
            database = root / "outbox.sqlite"
            outbox, config = self.outbox(root)
            self.assertEqual(outbox.path, database)
            alert_delivery.enqueue_operational_events(
                outbox, config, [event("a"), event("b")], NOW,
            )
            output = io.StringIO()
            monotonic_values = iter((100.0, 100.0, 101.0))
            with (
                mock.patch.object(
                    alert_delivery.time,
                    "monotonic",
                    side_effect=lambda: next(monotonic_values),
                ),
                mock.patch.object(
                    alert_delivery,
                    "dispatch_task",
                    return_value=alert_delivery.DeliveryResult.success(204),
                ) as dispatch,
                contextlib.redirect_stdout(output),
            ):
                result = alert_delivery.run_cli([
                    "--config", str(config_path), "--db", str(database),
                    "drain", "--worker-id", "test-worker", "--max-items", "2",
                    "--max-runtime-seconds", "1",
                ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["processed"], 1)
            self.assertEqual(dispatch.call_count, 1)
            self.assertEqual(outbox.status()["states"]["succeeded"], 1)
            self.assertEqual(outbox.status()["states"]["pending"], 1)

    def test_worker_runtime_limit_is_finite_and_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            for invalid in (0, 301, float("nan"), True):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    ValueError, "max runtime seconds",
                ):
                    alert_delivery.process_due(
                        outbox,
                        config,
                        NOW,
                        "test-worker",
                        max_runtime_seconds=invalid,
                    )

    def test_adapter_wall_deadline_interrupts_drip_like_work_before_lease_expiry(self):
        class CatchingSlowAdapter:
            def __init__(self):
                self.calls = 0

            def send(self, _channel, _task, _payload, _secret):
                self.calls += 1
                try:
                    # Model a transport parser receiving progress below its
                    # per-read timeout. Exception-catching libraries must not
                    # swallow the watchdog's BaseException.
                    while True:
                        wall_time.sleep(0.1)
                except Exception:
                    return alert_delivery.DeliveryResult.success(204)

        with tempfile.TemporaryDirectory() as directory:
            value = config_value(lease_seconds=6)
            value["channels"][0]["timeoutSeconds"] = 0.25
            outbox, config = self.outbox(Path(directory), value)
            alert_delivery.enqueue_test_delivery(
                outbox, config, "ops-webhook", "deadline-test",
                "Absolute adapter deadline", NOW,
            )
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            adapter = CatchingSlowAdapter()
            started = wall_time.monotonic()
            result = alert_delivery.dispatch_task(
                config,
                task,
                secret_resolver=lambda _ref: "https://example.test/private",
                adapters={"webhook": adapter},
            )
            elapsed = wall_time.monotonic() - started
            self.assertEqual(
                result,
                alert_delivery.DeliveryResult.retryable("delivery_deadline_exceeded"),
            )
            self.assertEqual(adapter.calls, 1)
            self.assertGreaterEqual(elapsed, 0.4)
            self.assertLess(elapsed, 1.5)
            self.assertLess(elapsed, config.queue.lease_seconds)

    def test_adapter_deadline_cleans_up_when_descheduled_during_timer_arm(self):
        class RecordingAdapter:
            def __init__(self):
                self.calls = 0

            def send(self, _channel, _task, _payload, _secret):
                self.calls += 1
                return alert_delivery.DeliveryResult.success(204)

        with tempfile.TemporaryDirectory() as directory:
            value = config_value(lease_seconds=6)
            value["channels"][0]["timeoutSeconds"] = 0.25
            outbox, config = self.outbox(Path(directory), value)
            alert_delivery.enqueue_test_delivery(
                outbox, config, "ops-webhook", "deadline-arm-race",
                "Deadline arm race", NOW,
            )
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            adapter = RecordingAdapter()
            original_handler = signal.getsignal(signal.SIGALRM)
            real_setitimer = signal.setitimer

            def delayed_setitimer(which, seconds, interval=0.0):
                result = real_setitimer(which, seconds, interval)
                if seconds > 0:
                    wall_time.sleep(1.0)
                return result

            with mock.patch.object(
                alert_delivery.signal, "setitimer", side_effect=delayed_setitimer,
            ):
                result = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )

            self.assertEqual(
                result,
                alert_delivery.DeliveryResult.retryable("delivery_deadline_exceeded"),
            )
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(signal.getsignal(signal.SIGALRM), original_handler)
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_adapter_deadline_fails_closed_without_stealing_alarm_or_off_main_thread(self):
        class RecordingAdapter:
            def __init__(self):
                self.calls = 0

            def send(self, _channel, _task, _payload, _secret):
                self.calls += 1
                return alert_delivery.DeliveryResult.success(204)

        with tempfile.TemporaryDirectory() as directory:
            outbox, config = self.outbox(Path(directory))
            alert_delivery.enqueue_test_delivery(
                outbox, config, "ops-webhook", "deadline-unavailable-test",
                "Unavailable adapter deadline", NOW,
            )
            task = outbox.claim_due(NOW, "worker-a", 1)[0]
            adapter = RecordingAdapter()

            signal.setitimer(signal.ITIMER_REAL, 30.0, 0.0)
            try:
                active_timer = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )
                remaining = signal.getitimer(signal.ITIMER_REAL)[0]
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
            self.assertEqual(
                active_timer,
                alert_delivery.DeliveryResult.retryable("deadline_unavailable"),
            )
            self.assertGreater(remaining, 0)
            self.assertEqual(adapter.calls, 0)

            threaded_results = []
            thread = threading.Thread(target=lambda: threaded_results.append(
                alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )
            ))
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(threaded_results, [
                alert_delivery.DeliveryResult.retryable("deadline_unavailable"),
            ])
            self.assertEqual(adapter.calls, 0)

            original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                blocked_mask_before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                blocked_alarm = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )
                blocked_mask_after = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            self.assertEqual(
                blocked_alarm,
                alert_delivery.DeliveryResult.retryable("deadline_unavailable"),
            )
            self.assertIn(signal.SIGALRM, blocked_mask_before)
            self.assertEqual(blocked_mask_after, blocked_mask_before)
            self.assertEqual(adapter.calls, 0)

            with mock.patch.object(
                alert_delivery.signal,
                "pthread_sigmask",
                side_effect=PermissionError("injected mask query denial"),
            ):
                denied_mask_query = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )
            self.assertEqual(
                denied_mask_query,
                alert_delivery.DeliveryResult.retryable("deadline_unavailable"),
            )
            self.assertEqual(adapter.calls, 0)

            original_handler = signal.getsignal(signal.SIGALRM)
            with mock.patch.object(
                alert_delivery.signal,
                "setitimer",
                side_effect=PermissionError("injected timer denial"),
            ):
                denied_timer = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "https://example.test/private",
                    adapters={"webhook": adapter},
                )
            self.assertEqual(
                denied_timer,
                alert_delivery.DeliveryResult.retryable("deadline_unavailable"),
            )
            self.assertEqual(signal.getsignal(signal.SIGALRM), original_handler)
            self.assertEqual(adapter.calls, 0)

    def test_smtp_partial_recipient_refusals_are_never_full_success(self):
        class SmtpClient:
            def __init__(self, refusals):
                self.refusals = refusals
                self.closed = False
                self.quit_called = False

            def ehlo(self):
                return None

            def login(self, _username, _password):
                return None

            def send_message(self, _message):
                return self.refusals

            def quit(self):
                self.quit_called = True
                return None

            def close(self):
                self.closed = True

        cases = (
            (
                {
                    "temporary@example.test": (450, b"try later"),
                    "permanent@example.test": (550, b"unknown user"),
                },
                alert_delivery.DeliveryResult.retryable("smtp_retryable", 450),
            ),
            (
                {"permanent@example.test": (550, b"unknown user")},
                alert_delivery.DeliveryResult.permanent("smtp_permanent", 550),
            ),
            ({}, alert_delivery.DeliveryResult.success(250)),
        )
        for index, (refusals, expected) in enumerate(cases):
            with self.subTest(refusals=refusals), tempfile.TemporaryDirectory() as directory:
                value = config_value(
                    channels=[channel("smtp-channel", "smtp", secret_key="SMTP_SECRET")],
                    lease_seconds=90,
                )
                value["channels"][0]["settings"]["to"] = [
                    "accepted@example.test", "temporary@example.test",
                    "permanent@example.test",
                ]
                outbox, config = self.outbox(Path(directory), value)
                alert_delivery.enqueue_test_delivery(
                    outbox, config, "smtp-channel", f"smtp-partial-{index}",
                    "SMTP partial recipient test", NOW,
                )
                task = outbox.claim_due(NOW, "worker-a", 1)[0]
                client = SmtpClient(refusals)
                result = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref: "smtp-password",
                    adapters={
                        "smtp": alert_delivery.SmtpAdapter(
                            smtp_ssl_factory=lambda *_args, **_kwargs: client,
                        ),
                    },
                )
                self.assertEqual(result, expected)
                self.assertTrue(client.closed)
                self.assertFalse(client.quit_called)

    def test_every_channel_adapter_uses_the_common_task_without_external_network(self):
        class Response:
            status = 204
            headers = {}

            def read(self, _limit):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class Opener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                return Response()

        class SmtpClient:
            def __init__(self, *_args, **_kwargs):
                self.password = None
                self.message = None
                self.quit_called = False

            def ehlo(self):
                return None

            def starttls(self, **_kwargs):
                return None

            def login(self, _username, password):
                self.password = password

            def send_message(self, message):
                self.message = message

            def quit(self):
                self.quit_called = True
                return None

            def close(self):
                return None

        secrets_by_kind = {
            "webhook": "https://webhook.example.test/private",
            "slack": "https://hooks.slack.com/services/private",
            "discord": "https://discord.com/api/webhooks/private",
            "telegram": "123456789:abcdefghijklmnopqrstuvwxyzABCDE",
            "smtp": "smtp-password-private",
        }
        for kind in sorted(alert_delivery.CHANNEL_KINDS):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                value = config_value(channels=[channel(
                    f"{kind}-channel", kind, secret_key=f"{kind.upper()}_SECRET",
                )], lease_seconds=90 if kind == "smtp" else 10)
                outbox, config = self.outbox(Path(directory), value)
                _disposition, _event_key, delivery_key = alert_delivery.enqueue_test_delivery(
                    outbox, config, f"{kind}-channel", f"request-{kind}",
                    "Common channel contract", NOW,
                )
                task = outbox.claim_due(NOW, "worker-a", 1)[0]
                self.assertEqual(task.delivery_key, delivery_key)
                if kind == "smtp":
                    smtp_client = SmtpClient()
                    adapter = alert_delivery.SmtpAdapter(
                        smtp_ssl_factory=lambda *_args, **_kwargs: smtp_client,
                    )
                    adapters = {kind: adapter}
                else:
                    opener = Opener()
                    adapter_type = {
                        "webhook": alert_delivery.WebhookAdapter,
                        "slack": alert_delivery.SlackAdapter,
                        "discord": alert_delivery.DiscordAdapter,
                        "telegram": alert_delivery.TelegramAdapter,
                    }[kind]
                    adapters = {kind: adapter_type(opener)}
                result = alert_delivery.dispatch_task(
                    config,
                    task,
                    secret_resolver=lambda _ref, kind=kind: secrets_by_kind[kind],
                    adapters=adapters,
                )
                self.assertEqual(result.outcome, "success")
                if kind == "smtp":
                    self.assertEqual(smtp_client.password, secrets_by_kind[kind])
                    self.assertEqual(
                        smtp_client.message["X-Monitor-Idempotency-Key"],
                        task.delivery_key,
                    )
                    self.assertFalse(smtp_client.quit_called)
                else:
                    request = opener.requests[0][0]
                    self.assertEqual(request.get_header("Idempotency-key"), task.delivery_key)
                    self.assertIn(
                        b'"test":true' if kind == "webhook" else b"TEST",
                        request.data,
                    )
                self.assertNotIn(secrets_by_kind[kind].encode(), outbox.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
