import datetime as dt
import unittest

from ops import notification_reports as reports
from ops import security_signals as signals


NOW = dt.datetime(2026, 9, 24, 12, 0, tzinfo=dt.timezone.utc)


def row(offset: int, message: str) -> dict:
    observed = NOW - dt.timedelta(seconds=offset)
    return {
        "timestamp": observed.isoformat().replace("+00:00", "Z"),
        "sourceId": "journal:ssh",
        "redactionVersion": "monitor-log-redaction-v2",
        "message": message,
    }


class SshMailThresholdTests(unittest.TestCase):
    def test_five_distinct_rows_across_failure_categories_qualify(self):
        rows = [
            row(1, "Failed password for user from [REDACTED_IP] port 1 ssh2"),
            row(2, "Failed publickey for user from [REDACTED_IP] port 2 ssh2"),
            row(3, "Failed keyboard-interactive for user from [REDACTED_IP] port 3 ssh2"),
            row(4, "Invalid user guest-a from [REDACTED_IP] port 4"),
            row(5, "Invalid user guest-b from [REDACTED_IP] port 5"),
        ]

        result = signals.ssh_signals(rows, NOW)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["key"], "ssh-auth")
        self.assertEqual(result[0]["count"], 5)
        self.assertEqual(result[0]["kind"], "ssh-auth-attempt")
        self.assertEqual(reports._mail_requirements(result[0]), (1, 0))

    def test_duplicate_row_does_not_reach_the_threshold(self):
        duplicate = row(1, "Failed password for user from [REDACTED_IP] port 1 ssh2")
        result = signals.ssh_signals([duplicate] * 5, NOW)
        self.assertEqual(result[0]["count"], 1)
        self.assertEqual(reports._mail_requirements(result[0]), (1000000, 0))


if __name__ == "__main__":
    unittest.main()
