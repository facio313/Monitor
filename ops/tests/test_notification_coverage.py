"""Independent notification coverage checks against raw collector contracts."""

import copy
import datetime as dt
import hashlib
import json
import unittest

from ops import security_signals as signals


NOW = dt.datetime(2026, 9, 13, 9, 0, tzinfo=dt.timezone.utc)
NOW_TEXT = "2026-09-13T09:00:00Z"
OLD_TEXT = "2026-09-13T08:00:00Z"


def snapshot():
    return {
        "generatedAt": NOW_TEXT,
        "latest": {},
        "linux": {
            "collectedAt": NOW_TEXT,
            "tcp": {"status": "supported", "rateStatus": "ok", "retransmissionPercent": 0},
            "clock": {
                "status": "supported",
                "timeSync": {"status": "supported", "synchronized": True},
            },
            "eventSources": {"kernelLogStatus": "supported"},
        },
        "containerCollection": {"status": "fresh", "observedAt": NOW_TEXT},
        "containers": [{
            "name": "monitor", "project": "monitor", "owner": "cks", "instanceId": "a" * 32,
            "state": "running", "health": "healthy", "healthcheckConfigured": True,
            "oomKilled": False, "restartCountDelta": 0,
            "memoryBytes": 20, "memoryLimitBytes": 100, "pidCount": 20, "pidLimit": 100,
            "cpuThrottledPercent": 0, "networkErrorsPerSecond": 0,
        }],
        "syntheticProbeCollection": {"status": "fresh", "observedAt": NOW_TEXT},
        "syntheticProbes": [{
            "id": "public-monitor-readiness", "status": "ok", "checkedAt": NOW_TEXT,
            "latencyMilliseconds": 100, "certificateDaysRemaining": 90,
        }],
        "system": {"kernel": {
            key: {"count": 0, "lastEventAt": None}
            for key in ("warning", "oops", "panic", "hungTask", "rcuStall", "rcuExpedited",
                        "oomKill", "filesystemError", "nvmeReset", "nvmeIo", "pcieAerCorrectable",
                        "pcieAerNonFatal", "pcieAerFatal")
        }},
    }


class NotificationCoverageTests(unittest.TestCase):
    def only_signal(self, current, severity):
        rows = signals.operational_signals(current, NOW)
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["kind"], "operational-caution")
        self.assertEqual(row["severity"], severity)
        self.assertTrue(signals.observable(row["key"], current))
        return row

    def test_healthy_raw_collector_observations_do_not_warn(self):
        self.assertEqual(signals.operational_signals(snapshot(), NOW), [])

    def test_tcp_warning_and_critical_follow_dashboard_thresholds(self):
        for value, severity in ((0.99, None), (1, "warning"), (4.99, "warning"), (5, "critical")):
            with self.subTest(value=value):
                current = snapshot()
                current["linux"]["tcp"]["retransmissionPercent"] = value
                if severity:
                    self.only_signal(current, severity)
                else:
                    self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_tcp_stale_reset_and_missing_values_cannot_fire_or_prove_recovery(self):
        current = snapshot()
        current["linux"]["tcp"]["retransmissionPercent"] = 8
        key = self.only_signal(current, "critical")["key"]
        for field, value in (("rateStatus", "counter_reset"), ("status", "permission_error"),
                             ("retransmissionPercent", None)):
            with self.subTest(field=field):
                unknown = copy.deepcopy(current)
                unknown["linux"]["tcp"][field] = value
                self.assertEqual(signals.operational_signals(unknown, NOW), [])
                self.assertFalse(signals.observable(key, unknown))
        current["linux"]["collectedAt"] = OLD_TEXT
        self.assertEqual(signals.operational_signals(current, NOW), [])
        self.assertFalse(signals.observable(key, current))

    def test_synthetic_failures_and_latency_match_current_dashboard(self):
        for status in ("dns", "timeout", "tls", "http"):
            with self.subTest(status=status):
                current = snapshot()
                current["syntheticProbes"][0]["status"] = status
                self.only_signal(current, "critical")
        for milliseconds, severity in ((999, None), (1000, "warning"), (2999, "warning"), (3000, "warning")):
            with self.subTest(milliseconds=milliseconds):
                current = snapshot()
                current["syntheticProbes"][0]["latencyMilliseconds"] = milliseconds
                if severity:
                    self.only_signal(current, severity)
                else:
                    self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_certificate_warning_starts_at_30_days_and_includes_expired_certificates(self):
        # The maintenance dashboard warns at 30 days, including the 14-day period.
        for days, severity in ((31, None), (30, "warning"), (14, "warning"), (8, "warning"),
                               (7, "critical"), (0, "critical"), (-1, "critical")):
            with self.subTest(days=days):
                current = snapshot()
                current["syntheticProbes"][0]["certificateDaysRemaining"] = days
                if severity:
                    self.only_signal(current, severity)
                else:
                    self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_synthetic_stale_collection_or_probe_cannot_fire_or_clear(self):
        current = snapshot()
        current["syntheticProbes"][0]["latencyMilliseconds"] = 3000
        key = self.only_signal(current, "warning")["key"]
        variants = []
        stale_status = copy.deepcopy(current)
        stale_status["syntheticProbeCollection"]["status"] = "stale"
        variants.append(stale_status)
        stale_collection = copy.deepcopy(current)
        stale_collection["syntheticProbeCollection"]["observedAt"] = OLD_TEXT
        variants.append(stale_collection)
        stale_probe = copy.deepcopy(current)
        stale_probe["syntheticProbes"][0]["checkedAt"] = OLD_TEXT
        variants.append(stale_probe)
        missing_probe = copy.deepcopy(current)
        missing_probe["syntheticProbes"] = []
        variants.append(missing_probe)
        missing_latency = copy.deepcopy(current)
        missing_latency["syntheticProbes"][0]["latencyMilliseconds"] = None
        variants.append(missing_latency)
        for index, unknown in enumerate(variants):
            with self.subTest(index=index):
                # A collection-health warning is valid; retained probe failures
                # must not be promoted to a new current observation.
                rows = signals.operational_signals(unknown, NOW)
                self.assertTrue(all(row["key"].startswith("collection:") for row in rows), rows)
                self.assertFalse(signals.observable(key, unknown))

    def test_container_runtime_failures_alert_immediately(self):
        for field, value in (("state", "exited"), ("health", "unhealthy"), ("oomKilled", True)):
            with self.subTest(field=field):
                current = snapshot()
                current["containers"][0][field] = value
                row = self.only_signal(current, "critical")
                unknown = copy.deepcopy(current)
                unknown["containers"][0][field] = None
                self.assertFalse(signals.observable(row["key"], unknown))

    def test_container_restart_memory_pid_and_throttle_thresholds(self):
        for field, cases in (
            ("restartCountDelta", ((0, None), (1, "warning"), (2, "warning"), (3, "critical"))),
            ("memoryBytes", ((79, None), (80, "warning"), (89, "warning"), (90, "critical"))),
            ("pidCount", ((79, None), (80, "warning"), (89, "warning"), (90, "critical"))),
            ("cpuThrottledPercent", ((19, None), (20, "warning"), (49, "warning"), (50, "critical"))),
        ):
            for value, severity in cases:
                with self.subTest(field=field, value=value):
                    current = snapshot()
                    current["containers"][0][field] = value
                    if severity:
                        row = self.only_signal(current, severity)
                        current["containers"][0][field] = None
                        self.assertFalse(signals.observable(row["key"], current))
                    else:
                        self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_container_limit_zero_missing_rows_and_stale_collection_do_not_clear_alerts(self):
        for value_field, limit_field in (("memoryBytes", "memoryLimitBytes"), ("pidCount", "pidLimit")):
            with self.subTest(value_field=value_field):
                current = snapshot()
                current["containers"][0][value_field] = 95
                key = self.only_signal(current, "critical")["key"]
                for missing in (None, 0):
                    unknown = copy.deepcopy(current)
                    unknown["containers"][0][limit_field] = missing
                    self.assertEqual(signals.operational_signals(unknown, NOW), [])
                    self.assertFalse(signals.observable(key, unknown))
                for status in ("last-known", "unavailable"):
                    unknown = copy.deepcopy(current)
                    unknown["containerCollection"]["status"] = status
                    rows = signals.operational_signals(unknown, NOW)
                    self.assertTrue(all(row["key"].startswith("collection:") for row in rows), rows)
                    self.assertFalse(signals.observable(key, unknown))
                unknown = copy.deepcopy(current)
                unknown["containerCollection"]["observedAt"] = OLD_TEXT
                self.assertEqual(signals.operational_signals(unknown, NOW), [])
                self.assertFalse(signals.observable(key, unknown))
                current["containers"] = []
                self.assertFalse(signals.observable(key, current))

    def test_clock_false_is_critical_but_unknown_is_not_recovery(self):
        current = snapshot()
        current["linux"]["clock"]["timeSync"]["synchronized"] = False
        key = self.only_signal(current, "critical")["key"]
        for status in ("permission_error", "unavailable", "unsupported"):
            with self.subTest(status=status):
                unknown = copy.deepcopy(current)
                unknown["linux"]["clock"]["timeSync"]["status"] = status
                self.assertEqual(signals.operational_signals(unknown, NOW), [])
                self.assertFalse(signals.observable(key, unknown))
        current["linux"]["clock"]["timeSync"]["synchronized"] = None
        self.assertFalse(signals.observable(key, current))
        current["linux"]["clock"]["timeSync"]["synchronized"] = True
        self.assertTrue(signals.observable(key, current))
        self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_new_kernel_events_notify_but_historical_rcu_does_not(self):
        for event, severity in (("rcuExpedited", "warning"), ("rcuStall", "critical"),
                                ("oomKill", "critical"), ("panic", "critical")):
            with self.subTest(event=event):
                current = snapshot()
                current["system"]["kernel"][event] = {"count": 1, "lastEventAt": NOW_TEXT}
                self.only_signal(current, severity)
        old = snapshot()
        old["system"]["kernel"]["rcuExpedited"] = {"count": 1, "lastEventAt": "2026-09-09T12:10:00Z"}
        self.assertEqual(signals.operational_signals(old, NOW), [])

    def test_future_and_missing_kernel_observations_do_not_assert_new_events(self):
        for event_time in (None, "invalid", "2026-09-14T00:00:00Z"):
            with self.subTest(event_time=event_time):
                current = snapshot()
                current["system"]["kernel"]["panic"] = {"count": 1, "lastEventAt": event_time}
                self.assertEqual(signals.operational_signals(current, NOW), [])

    def test_excluded_service_and_probe_rows_never_enter_signals(self):
        current = snapshot()
        current["containers"][0].update({"name": "wgang", "state": "exited"})
        current["syntheticProbes"][0].update({"id": "wgang-readiness", "status": "http"})
        rows = signals.operational_signals(current, NOW)
        self.assertEqual(rows, [])
        self.assertNotIn("wgang", json.dumps(rows))

    def tcp_current(self, elapsed, outbound, retransmitted):
        current = snapshot()
        stamp = (NOW + dt.timedelta(seconds=elapsed)).isoformat().replace("+00:00", "Z")
        current["generatedAt"] = current["linux"]["collectedAt"] = stamp
        current["identity"] = {"bootId": "a" * 32}
        current["linux"]["tcp"]["counters"] = {"OutSegs": outbound, "RetransSegs": retransmitted}
        return current

    def tcp_project(self, elapsed, outbound, retransmitted, state=None):
        now = NOW + dt.timedelta(seconds=elapsed)
        current = self.tcp_current(elapsed, outbound, retransmitted)
        projected, next_state = signals.prepare_notification_current(current, now, state)
        return projected, next_state

    def test_notification_tcp_isolated_sparse_spike_is_not_an_alarm_or_recovery(self):
        _, state = self.tcp_project(0, 10000, 0)
        for index, (outbound, retransmitted) in enumerate(((60, 6), (120, 6), (180, 6)), 1):
            projected, state = self.tcp_project(index * 60, 10000 + outbound, retransmitted, state)
            self.assertEqual(signals.operational_signals(projected, NOW + dt.timedelta(seconds=index * 60)), [])
            self.assertFalse(signals.observable("tcp:retransmission", projected))

    def test_notification_tcp_uses_weighted_counts_and_real_distinct_samples(self):
        _, state = self.tcp_project(0, 0, 0)
        # One 10% sample diluted by larger healthy samples is below 1% overall.
        for index, outbound, retransmitted in ((1, 60, 6), (2, 1060, 6), (3, 2060, 6)):
            projected, state = self.tcp_project(index * 60, outbound, retransmitted, state)
        self.assertAlmostEqual(projected["linux"]["tcp"]["retransmissionPercent"], 6 / 2060 * 100)
        self.assertTrue(signals.observable("tcp:retransmission", projected))
        self.assertEqual(signals.operational_signals(projected, NOW + dt.timedelta(seconds=180)), [])

    def test_notification_tcp_persistent_high_volume_warns_or_escalates(self):
        for retransmitted, severity in ((10, "warning"), (50, "critical")):
            with self.subTest(severity=severity):
                _, state = self.tcp_project(0, 0, 0)
                for index in range(1, 4):
                    projected, state = self.tcp_project(index * 60, index * 1000, index * retransmitted, state)
                    rows = signals.operational_signals(projected, NOW + dt.timedelta(seconds=index * 60))
                    if index < 3:
                        self.assertEqual(rows, [])
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["severity"], severity)
                self.assertIn("3000", rows[0]["evidence"])
                self.assertIn("180초", rows[0]["evidence"])
                self.assertEqual(len(state["samples"]), 3)

    def test_notification_tcp_persistent_low_volume_can_cross_absolute_failure_floor(self):
        _, state = self.tcp_project(0, 0, 0)
        for index in range(1, 5):
            projected, state = self.tcp_project(index * 60, index * 60, index * 6, state)
            rows = signals.operational_signals(projected, NOW + dt.timedelta(seconds=index * 60))
            if index < 4:
                self.assertEqual(rows, [])
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(projected["linux"]["tcp"]["notificationWindow"]["retransmittedSegmentsDelta"], 24)

    def test_notification_tcp_repeated_and_out_of_order_observations_do_not_advance(self):
        _, baseline = self.tcp_project(0, 0, 0)
        _, state = self.tcp_project(60, 1000, 100, baseline)
        before = copy.deepcopy(state)
        for elapsed in (60, 0, 60):
            current = self.tcp_current(elapsed, 1000, 100)
            projected, state = signals.prepare_notification_current(current, NOW + dt.timedelta(seconds=60), state)
            self.assertFalse(signals.observable("tcp:retransmission", projected))
            self.assertEqual(state, before)
        projected, state = self.tcp_project(120, 2000, 200, state)
        self.assertEqual(len(state["samples"]), 2)
        self.assertFalse(signals.observable("tcp:retransmission", projected))

    def test_notification_tcp_invalid_reset_stale_or_missing_data_breaks_window(self):
        _, state = self.tcp_project(0, 0, 0)
        _, state = self.tcp_project(60, 1000, 100, state)
        variants = []
        for field, value in (("rateStatus", "counter_reset"), ("status", "unsupported"), ("counters", None)):
            current = self.tcp_current(120, 2000, 200)
            current["linux"]["tcp"][field] = value
            variants.append(current)
        for value in (-1, float("nan"), float("inf"), True, 1.5):
            current = self.tcp_current(120, value, 200)
            variants.append(current)
        for value in (None, "invalid", "2026-09-13T08:00:00Z", "2026-09-13T09:02:01Z"):
            current = self.tcp_current(120, 2000, 200)
            current["linux"]["collectedAt"] = value
            variants.append(current)
        for current in variants:
            with self.subTest(current=current):
                projected, next_state = signals.prepare_notification_current(current, NOW + dt.timedelta(seconds=120), state)
                self.assertFalse(signals.observable("tcp:retransmission", projected))
                self.assertEqual(next_state["samples"], [])
                self.assertIsNone(next_state["lastCounters"])

    def test_notification_tcp_boot_change_counter_decrease_and_long_gap_restart_baseline(self):
        _, state = self.tcp_project(0, 10000, 1000)
        _, state = self.tcp_project(60, 11000, 1100, state)
        for mode in ("boot", "counter", "gap", "reboot", "missing-identity"):
            elapsed = 241 if mode == "gap" else 120
            current = self.tcp_current(elapsed, 12000, 1200)
            if mode == "boot":
                current["identity"]["bootId"] = "b" * 32
            elif mode == "counter":
                current["linux"]["tcp"]["counters"]["OutSegs"] = 1
            elif mode == "reboot":
                current["linux"]["clock"]["rebootDetectedSincePreviousSample"] = True
            elif mode == "missing-identity":
                current.pop("identity")
            with self.subTest(mode=mode):
                projected, next_state = signals.prepare_notification_current(current, NOW + dt.timedelta(seconds=elapsed), state)
                self.assertFalse(signals.observable("tcp:retransmission", projected))
                self.assertEqual(next_state["samples"], [])

    def test_notification_tcp_window_is_bounded_and_does_not_mutate_input(self):
        state = None
        for index in range(24):
            current = self.tcp_current(index * 30, index * 1000, index * 20)
            original = copy.deepcopy(current)
            old_state = copy.deepcopy(state)
            projected, new_state = signals.prepare_notification_current(current, NOW + dt.timedelta(seconds=index * 30), state)
            self.assertEqual(current, original)
            self.assertEqual(state, old_state)
            self.assertLessEqual(len(new_state["samples"]), 8)
            self.assertLessEqual(sum(row["intervalSeconds"] for row in new_state["samples"]), 300)
            json.dumps(new_state, allow_nan=False)
            state = new_state
        self.assertTrue(signals.observable("tcp:retransmission", projected))

    def test_notification_sample_identity_comes_from_the_actual_source(self):
        current = snapshot()
        current["linux"]["collectedAt"] = "2026-09-13T08:59:30Z"
        current["containerCollection"]["observedAt"] = "2026-09-13T08:59:40Z"
        current["syntheticProbeCollection"]["observedAt"] = "2026-09-13T08:59:50Z"
        current["syntheticProbes"][0]["checkedAt"] = "2026-09-13T08:56:00Z"
        probe_hash = hashlib.sha256(b"public-monitor-readiness").hexdigest()[:12]
        for key, expected in (
            ("host:cpuPercent", NOW_TEXT), ("http-slow:monitor", NOW_TEXT),
            ("tcp:retransmission", "2026-09-13T08:59:30Z"),
            ("clock:sync", "2026-09-13T08:59:30Z"),
            ("container:123:state", "2026-09-13T08:59:40Z"),
            ("collection:container", "2026-09-13T08:59:40Z"),
            ("collection:synthetic", "2026-09-13T08:59:50Z"),
            (f"synthetic:{probe_hash}:latency", "2026-09-13T08:56:00Z"),
            ("synthetic:missing:latency", None),
        ):
            self.assertEqual(signals.sample_timestamp(key, current), expected)
        current["syntheticProbes"][0]["checkedAt"] = None
        self.assertIsNone(signals.sample_timestamp(f"synthetic:{probe_hash}:latency", current))

    def test_five_minute_synthetic_sample_remains_available_without_changing_identity(self):
        current = snapshot()
        current["syntheticProbes"][0]["latencyMilliseconds"] = 4000
        key = self.only_signal(current, "warning")["key"]
        for elapsed in (240, 300, 600):
            now = NOW + dt.timedelta(seconds=elapsed)
            current["generatedAt"] = now.isoformat().replace("+00:00", "Z")
            rows = signals.operational_signals(current, now)
            self.assertEqual([row["key"] for row in rows], [key])
            self.assertTrue(signals.observable(key, current))
            self.assertEqual(signals.sample_timestamp(key, current), NOW_TEXT)
        current["generatedAt"] = (NOW + dt.timedelta(seconds=601)).isoformat().replace("+00:00", "Z")
        self.assertFalse(signals.observable(key, current))

    def test_failed_fast_synthetic_probe_is_not_a_latency_recovery_sample(self):
        current = snapshot()
        current["syntheticProbes"][0]["latencyMilliseconds"] = 4000
        key = self.only_signal(current, "warning")["key"]
        current["syntheticProbes"][0].update({"status": "tls", "latencyMilliseconds": 5})
        self.assertFalse(signals.observable(key, current))
        rows = signals.operational_signals(current, NOW)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["key"].endswith(":status"))

    def test_repeating_qualified_tcp_window_keeps_observation_without_adding_counts(self):
        state = None
        for index in range(4):
            projected, state = self.tcp_project(index * 60, index * 1000, index * 50, state)
        before = copy.deepcopy(state)
        current = self.tcp_current(180, 3000, 150)
        repeated, next_state = signals.prepare_notification_current(current, NOW + dt.timedelta(seconds=181), state)
        self.assertEqual(next_state, before)
        self.assertEqual(repeated["linux"]["tcp"]["notificationWindow"], projected["linux"]["tcp"]["notificationWindow"])
        self.assertEqual(signals.sample_timestamp("tcp:retransmission", repeated), current["linux"]["collectedAt"])


if __name__ == "__main__":
    unittest.main()
