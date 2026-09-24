import unittest

from ops import notification_policy as policy
from ops import notification_reports as reports
from ops import security_signals as signals


class IoPressurePolicyTests(unittest.TestCase):
    def test_some_and_full_are_one_warning_episode(self):
        for some, full in ((20, 0), (0, 8), (25, 10)):
            with self.subTest(some=some, full=full):
                rows = signals.operational_signals({
                    "latest": {
                        "ioPressureSomeAvg10": some,
                        "ioPressureFullAvg10": full,
                    },
                })
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["key"], policy.IO_PRESSURE_SIGNAL_KEY)
                self.assertEqual(rows[0]["severity"], "warning")
                self.assertIn(f"PSI some {some:g}%, full {full:g}%", rows[0]["evidence"])
                self.assertIn("디스크 고장 자체의 증거는 아닙니다", rows[0]["evidence"])

    def test_complete_pair_is_required_and_both_recovery_bands_must_clear(self):
        retained = {"status": "active", "severity": "warning", "qualifiedSeverity": "warning"}
        for some, full, expected in ((5.01, 1, "warning"), (5, 1.01, "warning"),
                                     (5, 1, None), (0, 0, None)):
            with self.subTest(some=some, full=full):
                current = {"latest": {
                    "ioPressureSomeAvg10": some,
                    "ioPressureFullAvg10": full,
                }}
                value = policy.resource_value(policy.IO_PRESSURE_SIGNAL_KEY, current)
                self.assertEqual(
                    policy.severity_for_value(policy.IO_PRESSURE_POLICY, value, "warning"),
                    expected,
                )
        incomplete = {"latest": {"ioPressureSomeAvg10": 0}}
        self.assertEqual(policy.resource_value(policy.IO_PRESSURE_SIGNAL_KEY, incomplete), 0)
        self.assertFalse(signals.observable(policy.IO_PRESSURE_SIGNAL_KEY, incomplete))
        self.assertEqual(reports._resource_hysteresis(
            [], {policy.IO_PRESSURE_SIGNAL_KEY: retained}, incomplete,
        ), [])

    def test_one_observed_entry_breach_opens_but_cannot_prove_recovery(self):
        for latest in ({"ioPressureSomeAvg10": 25}, {"ioPressureFullAvg10": 9}):
            with self.subTest(latest=latest):
                current = {"latest": latest}
                rows = signals.operational_signals(current)
                self.assertEqual([row["key"] for row in rows], [policy.IO_PRESSURE_SIGNAL_KEY])
                self.assertEqual(rows[0]["severity"], "warning")
                self.assertIn("관측 없음", rows[0]["evidence"])
                self.assertFalse(signals.observable(policy.IO_PRESSURE_SIGNAL_KEY, current))

    def test_legacy_individual_states_are_administratively_retired(self):
        self.assertIsNotNone(reports._retired_signal_reason("host:ioPressureSomeAvg10"))
        self.assertIsNotNone(reports._retired_signal_reason("host:ioPressureFullAvg10"))


if __name__ == "__main__":
    unittest.main()
