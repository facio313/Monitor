import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import notification_reports as reports
from ops import notification_visuals as visuals


NOW = dt.datetime(2026, 9, 14, 0, 10, tzinfo=dt.timezone.utc)
NOW_TEXT = "2026-09-14T00:10:00Z"


def snapshot():
    return {"generatedAt": NOW_TEXT, "latest": {"timestamp": NOW_TEXT, "cpuPercent": 0,
             "memoryPercent": 25, "temperatureC": 65},
            "disks": [{"mount": "/", "usedPercent": 30}],
            "linux": {"collectedAt": NOW_TEXT, "tcp": {"status": "supported", "rateStatus": "ok", "retransmissionPercent": 0,
                       "notificationWindow": {"outboundSegmentsDelta": 1000, "retransmittedSegmentsDelta": 0,
                                              "windowSeconds": 180, "sampleCount": 3}}},
            "syntheticProbeCollection": {"status": "fresh", "observedAt": NOW_TEXT},
            "syntheticProbes": [{"id": "public-monitor", "checkedAt": NOW_TEXT, "status": "ok", "latencyMilliseconds": 0}],
            "system": {"reboot": {"status": "ok", "required": False, "observedAt": NOW_TEXT, "packages": []}}}


def health():
    return [{"source": key, "status": "fresh", "observedAt": NOW_TEXT, "detail": "정상"}
            for key in ("snapshot", "rules", "ssh", "http")]


def evaluation():
    return {"status": "ok", "evaluatedAt": NOW_TEXT, "states": {}}


class NotificationVisualsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, rows):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text("\n".join(json.dumps(row) for row in rows))
        path.chmod(0o600)
        return path

    def test_hour_crosses_utc_midnight_maxima_zero_and_null_gaps(self):
        self.write("history/2026-09-13.jsonl", [
            {"timestamp": "2026-09-13T23:09:59Z", "cpuPercent": 100, "memoryPercent": 100},
            {"timestamp": "2026-09-13T23:11:00Z", "cpuPercent": 20, "memoryPercent": 25},
            {"timestamp": "2026-09-13T23:11:30Z", "cpuPercent": 95, "memoryPercent": 50},
            {"timestamp": "2026-09-13T23:12:30Z", "cpuPercent": None, "memoryPercent": float("nan")},
            {"timestamp": "2026-09-13T23:13:00Z", "cpuPercent": 100, "service": "wgang"},
        ])
        self.write("history/2026-09-14.jsonl", [
            {"timestamp": "2026-09-14T00:09:00Z", "cpuPercent": 0, "memoryPercent": 0},
            {"timestamp": "2026-09-14T00:10:01Z", "cpuPercent": 100, "memoryPercent": 100},
        ])
        trend = visuals.build_hour_trend(self.root, NOW)
        self.assertEqual(trend["from"], "2026-09-13T23:10:00Z")
        self.assertEqual(trend["to"], NOW_TEXT)
        self.assertEqual(len(trend["cpu"]), 30)
        self.assertEqual(trend["cpu"][0], 95)
        self.assertEqual(trend["memory"][0], 50)
        self.assertIsNone(trend["cpu"][1])
        self.assertIsNone(trend["memory"][1])
        self.assertEqual(trend["cpu"][-1], 0)
        self.assertEqual(trend["memory"][-1], 0)
        self.assertEqual(trend["tcp"], [None] * 30)

    def test_tcp_weighted_buckets_duplicate_timestamp_and_zero_denominator(self):
        row = {"observedAt": "2026-09-13T23:11:00Z", "tcp": {
            "status": "fresh", "retransmittedSegments": 10, "outboundSegments": 10}}
        self.write("network-diagnostics/2026-09-13.jsonl", [row, row,
            {"observedAt": "2026-09-13T23:11:30Z", "tcp": {"status": "fresh", "retransmittedSegments": 0, "outboundSegments": 990}},
            {"observedAt": "2026-09-13T23:13:00Z", "tcp": {"status": "fresh", "retransmittedSegments": 0, "outboundSegments": 0}},
            {"observedAt": "2026-09-13T23:15:00Z", "tcp": {"status": "no_data", "retransmittedSegments": 10, "outboundSegments": 10}},
            {"observedAt": "2026-09-13T23:17:00Z", "tcp": {"status": "fresh", "retransmittedSegments": True, "outboundSegments": 10}},
        ])
        tcp = visuals.build_hour_trend(self.root, NOW)["tcp"]
        self.assertEqual(tcp[0], 1)
        self.assertEqual(tcp[1:], [None] * 29)

    def test_trend_reader_only_visits_needed_days_and_rejects_symlinks(self):
        with mock.patch.object(visuals, "_rows", return_value=[]) as reader:
            visuals.build_hour_trend(self.root, NOW)
        paths = {str(call.args[0].relative_to(self.root)) for call in reader.call_args_list}
        self.assertEqual(paths, {"history/2026-09-13.jsonl", "history/2026-09-14.jsonl",
                                 "network-diagnostics/2026-09-13.jsonl", "network-diagnostics/2026-09-14.jsonl"})
        actual = self.write("unrelated.jsonl", [{"timestamp": "2026-09-13T23:11:00Z", "cpuPercent": 99}])
        (self.root / "history").mkdir(mode=0o700)
        (self.root / "history/2026-09-13.jsonl").symlink_to(actual)
        self.assertEqual(visuals.build_hour_trend(self.root, NOW)["cpu"], [None] * 30)

    def test_fresh_cards_keep_zero_and_stale_cards_never_claim_current_values(self):
        current = snapshot()
        visual = visuals.build_hourly_visual(None, current, evaluation(), health(), {}, NOW)
        self.assertEqual(visual["status"], "ok")
        self.assertEqual(visual["cards"][0]["value"], "0")
        self.assertEqual(visual["cards"][4]["value"], "0")
        self.assertEqual(visual["cards"][5]["value"], "0")
        current["generatedAt"] = "2026-09-13T23:00:00Z"
        stale = visuals.build_hourly_visual(None, current, evaluation(), health(), {}, NOW)
        self.assertEqual(stale["status"], "unknown")
        self.assertTrue(all(card["tone"] == "unknown" for card in stale["cards"]))
        self.assertTrue(all(card["value"] == "관측 없음" for card in stale["cards"]))

    def test_hourly_reboot_highlight_safe_fields_and_bound(self):
        current = snapshot()
        current["system"]["reboot"].update(required=True, packages=["libc6", "wgang-lib", "https://unsafe.example"])
        current["disks"].append({"mount": "/wgang", "usedPercent": 99})
        active = {str(index): {"status": "active", "severity": "warning", "reportSeverity": "warning", "evidence": "경고 " * 160} for index in range(20)}
        visual = visuals.build_hourly_visual(self.root, current, evaluation(), health(), active, NOW)
        self.assertEqual(visual["status"], "warning")
        self.assertIn("libc6", visual["highlights"][0])
        serialized = json.dumps(visual, ensure_ascii=False, separators=(",", ":"))
        self.assertLessEqual(len(serialized.encode()), 4096)
        self.assertNotIn("wgang", serialized)
        self.assertNotIn("https://", serialized)
        self.assertLessEqual(len(visual["cards"]), 6)
        self.assertLessEqual(len(visual["highlights"]), 4)
        self.assertTrue(all(len(text) <= 160 for text in visual["highlights"]))
        self.assertIn("확정 신호 20", visual["subtitle"])

    def test_missing_essential_values_never_claim_stability(self):
        for field in ("cpuPercent", "memoryPercent", "temperatureC", "syntheticProbes"):
            with self.subTest(field=field):
                current = snapshot()
                if field == "syntheticProbes":
                    current[field] = []
                else:
                    current["latest"][field] = None
                visual = visuals.build_hourly_visual(None, current, evaluation(), health(), {}, NOW)
                self.assertEqual(visual["status"], "warning")
                self.assertNotIn("안정적", visual["title"])
                self.assertIn("관측 없음은 정상 상태를 뜻하지", " ".join(visual["highlights"]))
                self.assertTrue(any(card["tone"] == "unknown" for card in visual["cards"]))

    def test_raw_high_values_and_unqualified_observations_do_not_create_danger(self):
        current = snapshot()
        current["latest"].update(cpuPercent=95, memoryPercent=98, temperatureC=90)
        current["disks"][0]["usedPercent"] = 99
        current["linux"]["tcp"]["retransmissionPercent"] = 10
        current["syntheticProbes"][0]["latencyMilliseconds"] = 4000
        active = {"host:cpuPercent": {"status": "active", "severity": "critical", "reportSeverity": None,
                                       "evidence": "CPU 95%"},
                  "old-public-id": {"status": "active", "severity": "critical", "evidence": "이전 관측"}}
        assessment = visuals.assess_hourly(current, evaluation(), health(), active, NOW)
        self.assertEqual(assessment["status"], "ok")
        self.assertEqual(assessment["active_rows"], [])
        self.assertEqual(assessment["unconfirmed_count"], 2)
        self.assertTrue(all(card["tone"] == "neutral" for card in assessment["cards"]))
        self.assertEqual(assessment["cards"][4]["value"], "0")
        visual = visuals.build_hourly_visual(None, current, evaluation(), health(), active, NOW, assessment=assessment)
        self.assertEqual(visual["status"], "ok")
        self.assertEqual(visual["title"], "확인된 활성 경고가 없습니다")
        self.assertNotIn("안정적", visual["title"])
        self.assertIn("확정 전 관측 2건", " ".join(visual["highlights"]))

    def test_confirmed_severity_is_not_raw_escalation_and_cleared_rows_are_ignored(self):
        current = snapshot()
        current["latest"]["cpuPercent"] = 95
        active = {"host:cpuPercent": {"status": "active", "severity": "critical", "reportSeverity": "warning", "evidence": "CPU 관측"},
                  "host:memoryPercent": {"status": "resolved", "severity": "critical", "reportSeverity": "critical"}}
        assessment = visuals.assess_hourly(current, evaluation(), health(), active, NOW)
        self.assertEqual(assessment["status"], "warning")
        self.assertEqual(assessment["cards"][0]["tone"], "warning")
        self.assertEqual(len(assessment["active_rows"]), 1)
        active["host:cpuPercent"]["reportSeverity"] = "critical"
        self.assertEqual(visuals.assess_hourly(current, evaluation(), health(), active, NOW)["status"], "critical")

    def test_known_unresolved_critical_survives_source_loss_without_claiming_current_metrics(self):
        current = snapshot()
        current["generatedAt"] = "2026-09-13T23:00:00Z"
        rules = evaluation()
        rules["evaluatedAt"] = "2026-09-13T23:00:00Z"
        active = {"host:cpuPercent": {"status": "active", "reportSeverity": "critical", "evidence": "CPU 95%"}}
        assessment = visuals.assess_hourly(current, rules, health(), active, NOW)
        self.assertEqual(assessment["status"], "critical")
        self.assertTrue(all(card["tone"] == "unknown" for card in assessment["cards"]))
        self.assertIn("관측 손실을 복구로 처리하지", " ".join(assessment["highlights"]))
        self.assertEqual(visuals.assess_hourly(current, rules, health(), {}, NOW)["status"], "unknown")

    def test_warning_observation_caps_card_color_while_critical_downgrade_is_pending(self):
        current = snapshot()
        current["latest"]["memoryPercent"] = 80
        active = {"host:memoryPercent": {"status": "active", "severity": "warning", "reportSeverity": "critical",
                                       "reportDowngradePending": True, "evidence": "메모리 80%"}}
        assessment = visuals.assess_hourly(current, evaluation(), health(), active, NOW)
        self.assertEqual(assessment["status"], "critical")
        self.assertEqual(assessment["cards"][1]["value"], "80")
        self.assertEqual(assessment["cards"][1]["tone"], "warning")
        self.assertIn("위험 해제 확인 중 · 마지막 관측은 주의 범위", " ".join(assessment["highlights"]))
        # The color cap also applies to a qualified rule whose threshold differs
        # from the observation card policy; it cannot turn this observation red.
        rules = evaluation()
        rules["states"] = {"TemperatureHigh:host/node": {"ruleId": "TemperatureHigh", "phase": "firing",
                                                         "reportReady": True, "reportSeverity": "critical"}}
        current["latest"]["temperatureC"] = 80
        assessment = visuals.assess_hourly(current, rules, health(), {}, NOW)
        self.assertEqual(assessment["status"], "critical")
        self.assertEqual(assessment["cards"][2]["tone"], "warning")

    def test_current_normal_observation_during_recovery_does_not_show_red_metric(self):
        current = snapshot()
        current["latest"]["cpuPercent"] = 10
        active = {"host:cpuPercent": {"status": "active", "reportSeverity": "critical", "reportRecoveryPending": True,
                                       "evidence": "CPU 95%"}}
        assessment = visuals.assess_hourly(current, evaluation(), health(), active, NOW)
        self.assertEqual(assessment["status"], "critical")
        self.assertEqual(assessment["cards"][0]["value"], "10")
        self.assertEqual(assessment["cards"][0]["tone"], "neutral")
        self.assertIn("복구 확인 중 · 직전 확정 사건", " ".join(assessment["highlights"]))

    def test_rules_require_notification_authority_and_ignore_resolved_or_muted_rows(self):
        rules = evaluation()
        rules["states"] = {"CpuUsageHigh:host/node": {"ruleId": "CpuUsageHigh", "phase": "firing", "severity": "critical"}}
        assessment = visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)
        self.assertEqual(assessment["status"], "warning")
        self.assertEqual(assessment["rule_rows"], [])
        self.assertEqual(assessment["unconfirmed_rule_count"], 1)
        row = rules["states"]["CpuUsageHigh:host/node"]
        for state in ("suppressed", "silenced", "inhibited", "pending"):
            with self.subTest(state=state):
                row["notificationState"] = state
                self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "ok")
        row["notificationState"] = "ready"
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "critical")
        row["reportReady"] = False
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "ok")
        row.update(reportReady=True, reportSeverity="warning")
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "warning")
        row["phase"] = "inactive"
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "ok")

    def test_stale_rules_need_explicit_retained_authority(self):
        rules = evaluation()
        rules["evaluatedAt"] = "2026-09-13T23:00:00Z"
        row = {"ruleId": "CpuUsageHigh", "phase": "recovering", "severity": "critical", "notificationState": "ready"}
        rules["states"] = {"CpuUsageHigh:host/node": row}
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "unknown")
        row.update(reportReady=True, reportSeverity="critical")
        self.assertEqual(visuals.assess_hourly(snapshot(), rules, health(), {}, NOW)["status"], "critical")

    def test_tcp_never_falls_back_to_raw_or_insufficient_count_ratio(self):
        for replacement in (None, {}, {"outboundSegmentsDelta": 10, "retransmittedSegmentsDelta": 1,
                                      "windowSeconds": 180, "sampleCount": 3},
                            {"outboundSegmentsDelta": 1000, "retransmittedSegmentsDelta": 100,
                             "windowSeconds": 60, "sampleCount": 1}):
            with self.subTest(window=replacement):
                current = snapshot()
                current["linux"]["tcp"].update(retransmissionPercent=10, notificationWindow=replacement)
                assessment = visuals.assess_hourly(current, evaluation(), health(), {}, NOW)
                self.assertEqual(assessment["status"], "warning")
                self.assertEqual(assessment["cards"][4]["tone"], "unknown")
                self.assertEqual(assessment["cards"][4]["value"], "관측 없음")

    def test_weighted_tcp_high_is_observation_until_confirmed(self):
        current = snapshot()
        current["linux"]["tcp"]["notificationWindow"]["retransmittedSegmentsDelta"] = 100
        assessment = visuals.assess_hourly(current, evaluation(), health(), {}, NOW)
        self.assertEqual(assessment["status"], "ok")
        self.assertEqual(assessment["cards"][4]["value"], "10")
        self.assertEqual(assessment["cards"][4]["tone"], "neutral")
        active = {"tcp:retransmission": {"status": "active", "reportSeverity": "critical", "evidence": "TCP 합산 10%"}}
        self.assertEqual(visuals.assess_hourly(current, evaluation(), health(), active, NOW)["status"], "critical")

    def test_http_single_failed_check_is_observation_not_confirmed_emergency(self):
        current = snapshot()
        current["syntheticProbes"][0].update(status="timeout", latencyMilliseconds=None)
        assessment = visuals.assess_hourly(current, evaluation(), health(), {}, NOW)
        self.assertEqual(assessment["status"], "ok")
        self.assertEqual(assessment["cards"][5]["value"], "검사 실패")
        self.assertEqual(assessment["cards"][5]["tone"], "neutral")

    def test_excluded_keys_never_contribute_even_with_confirmed_severity(self):
        active = {"container:wgang:health": {"status": "active", "reportSeverity": "critical", "evidence": "제외 항목"}}
        rules = evaluation()
        rules["states"] = {"ContainerDown:container/wgang": {"ruleId": "ContainerDown", "phase": "firing", "severity": "critical", "reportReady": True}}
        assessment = visuals.assess_hourly(snapshot(), rules, health(), active, NOW)
        self.assertEqual(assessment["status"], "ok")
        self.assertEqual(assessment["active_rows"], [])
        self.assertEqual(assessment["rule_rows"], [])
        self.assertNotIn("wgang", str(assessment))

    def test_rendering_shared_assessment_does_not_mutate_it_or_reassess(self):
        assessment = visuals.assess_hourly(snapshot(), evaluation(), health(), {}, NOW)
        before = json.loads(json.dumps(assessment))
        with mock.patch.object(visuals, "assess_hourly", side_effect=AssertionError("must reuse verdict")):
            visual = visuals.build_hourly_visual(self.root, {}, {}, [], {}, NOW, assessment=assessment)
        self.assertEqual(visual["status"], assessment["status"])
        self.assertEqual(assessment, before)

    def test_card_integer_format_keeps_trailing_zero_digits(self):
        for value in (0, 10, 100, 1000):
            with self.subTest(value=value):
                card = visuals._card("검사", value, "ms", 1000, 3000, True, decimals=0)
                self.assertEqual(card["value"], str(value))

    def test_reboot_highlight_deduplicates_detected_evidence(self):
        current = snapshot()
        current["system"]["reboot"].update(required=True, packages=["libc6"])
        active = {"reboot": {"status": "active", "severity": "warning",
                              "evidence": "운영체제가 재부팅 필요 상태입니다. 유지보수 시간을 정해 적용해야 합니다."}}
        visual = visuals.build_hourly_visual(None, current, evaluation(), health(), active, NOW)
        self.assertEqual(sum("재부팅 필요" in item for item in visual["highlights"]), 1)
        self.assertTrue(any("작업을 저장" in item for item in visual["highlights"]))

    def test_built_visuals_validate_and_invalid_optional_visual_falls_back(self):
        hourly = visuals.build_hourly_visual(self.root, snapshot(), evaluation(), health(), {}, NOW)
        self.assertEqual(reports.delivery.email_visuals.normalize_visual(hourly), hourly)
        event = {"ruleId": "OperationalCaution", "severity": "warning", "transition": "firing",
                 "observedAt": NOW_TEXT, "openedAt": NOW_TEXT}
        incident = visuals.build_incident_visual(event, "재부팅 필요 상태입니다.")
        self.assertEqual(reports.delivery.email_visuals.normalize_visual(incident), incident)
        with mock.patch.object(visuals, "build_incident_visual", return_value={"invalid": True}):
            presentation = reports._immediate_presentation(event, "재부팅 필요 상태입니다.")
        self.assertNotIn("visual", presentation)
        self.assertIn("재부팅 필요 상태입니다.", presentation["body"])
        with mock.patch.object(visuals, "build_hourly_visual", return_value={"invalid": True}):
            presentation = reports._digest(snapshot(), evaluation(), health(), {}, [], NOW, self.root)
        self.assertNotIn("visual", presentation)
        self.assertIn("CPU · 관측: 0%", presentation["body"])

    def test_incident_reboot_and_recovery_truth(self):
        event = {"ruleId": "OperationalCaution", "severity": "warning", "transition": "firing",
                 "observedAt": NOW_TEXT, "openedAt": "2026-09-14T00:00:00Z"}
        visual = visuals.build_incident_visual(event, "운영체제가 재부팅 필요 상태입니다.")
        self.assertEqual(visual["title"], "서버 재부팅이 필요합니다")
        self.assertEqual(visual["cards"][1]["tone"], "neutral")
        self.assertIsNone(visual["trend"])
        self.assertTrue(any("작업을 저장" in item for item in visual["highlights"]))
        event["transition"] = "resolved"
        text = reports._recovery_evidence("TCP 재전송률 8.696%. 최신 관측 기준입니다.")
        visual = visuals.build_incident_visual(event, text)
        self.assertEqual(visual["status"], "resolved")
        self.assertIn("해소 전", " ".join(visual["highlights"]))
        self.assertNotIn("최신 관측 기준", str(visual))
        event["openedAt"] = None
        self.assertEqual(visuals.build_incident_visual(event, text)["cards"][1]["tone"], "unknown")

    def test_preview_is_read_only_and_preserves_plain_text(self):
        self.write("current.json", [snapshot()])
        self.write("rule-evaluation.json", [evaluation()])
        self.write("notification-reports.json", [{"observedAt": NOW_TEXT, "sourceHealth": health(), "detections": []}])
        self.write("generic-log-sources.json", [{"generatedAt": NOW_TEXT, "sources": [
            {"sourceId": "journal:ssh", "status": "no_data", "observedAt": NOW_TEXT}]}])
        before = {str(path): path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        with mock.patch.object(reports.delivery, "DeliveryOutbox", side_effect=AssertionError("no queue")):
            presentation = reports.build_hourly_presentation(self.root, NOW)
        self.assertIn("CPU · 관측: 0%", presentation["body"])
        self.assertEqual(presentation["visual"]["kind"], "hourly")
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.iterdir() if path.is_file()})
        self.assertFalse((self.root / ".state").exists())


if __name__ == "__main__":
    unittest.main()
