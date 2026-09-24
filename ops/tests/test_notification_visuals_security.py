import unittest

from ops import notification_reports as reports
from ops import notification_visuals as visuals


NOW = "2026-09-24T12:00:00Z"


def _event(signal_kind: str, evidence: str):
    return reports._event(
        "SecurityPattern" if signal_kind.startswith("ssh-") else "OperationalCaution",
        f"test-{signal_kind}",
        "warning",
        NOW,
        NOW,
        evidence,
        signal_kind=signal_kind,
    )


class NotificationVisualSecurityTests(unittest.TestCase):
    def test_event_exposes_only_allowlisted_signal_kind(self):
        accepted = _event("ssh-auth-success", "SSH 인증 성공 관측")
        rejected = reports._event(
            "SecurityPattern", "test-unknown", "warning", NOW, NOW,
            "분류되지 않은 관측", signal_kind="invented-kind",
        )

        self.assertEqual(accepted["labels"]["signal_kind"], "ssh-auth-success")
        self.assertNotIn("signal_kind", rejected["labels"])

    def test_untrusted_auth_success_does_not_claim_failure_or_intrusion(self):
        visual = visuals.build_incident_visual(
            _event("ssh-auth-success", "신뢰 목록 밖 SSH 인증 성공 1건"),
            "신뢰 목록 밖 SSH 인증 성공 1건",
        )

        self.assertEqual(visual["title"], "신뢰 목록 밖 SSH 인증 성공이 감지됐습니다")
        text = " ".join(visual["highlights"])
        self.assertIn("인증은 성공", text)
        self.assertIn("침해 여부는 확인되지", text)
        self.assertNotIn("인증 실패", text)

    def test_failed_attempt_and_burst_keep_failure_wording(self):
        for signal_kind in ("ssh-auth-attempt", "ssh-auth-burst"):
            with self.subTest(signal_kind=signal_kind):
                visual = visuals.build_incident_visual(
                    _event(signal_kind, "SSH 인증 실패 관측"),
                    "SSH 인증 실패 관측",
                )
                self.assertEqual(visual["title"], "SSH 접근 시도가 감지됐습니다")
                self.assertIn("거부 또는 인증 실패", " ".join(visual["highlights"]))

    def test_source_gap_with_ssh_in_evidence_is_not_reclassified_as_attempt(self):
        evidence = "SSH 로그 수집 상태를 확인할 수 없습니다"
        visual = visuals.build_incident_visual(
            _event("source-unavailable", evidence),
            evidence,
        )

        self.assertEqual(visual["title"], "서버에 확인할 사항이 있습니다")
        self.assertNotIn("인증 실패", " ".join(visual["highlights"]))


if __name__ == "__main__":
    unittest.main()
