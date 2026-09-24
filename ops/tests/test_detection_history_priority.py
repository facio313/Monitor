import unittest

from ops import notification_reports as reports


def detection(identifier: int, status: str, observed_at: str) -> dict:
    return {
        "id": f"{identifier:064x}",
        "kind": "operational-caution",
        "severity": "warning",
        "status": status,
        "openedAt": observed_at,
        "observedAt": observed_at,
        "count": 1,
        "windowSeconds": 300,
        "evidence": "bounded test evidence",
    }


class DetectionHistoryPriorityTests(unittest.TestCase):
    def test_older_active_incident_is_not_displaced_by_resolved_history(self):
        active = detection(999, "active", "2026-09-20T00:00:00Z")
        resolved = [
            detection(index, "resolved", f"2026-09-24T00:{index:02d}:00Z")
            for index in range(40)
        ]

        bounded = reports._bounded_recent({"host:test": active}, resolved)

        self.assertEqual(len(bounded), reports.MAX_DETECTIONS)
        self.assertEqual(bounded[0]["id"], active["id"])
        self.assertEqual(bounded[0]["status"], "active")
        self.assertEqual(sum(row["status"] == "active" for row in bounded), 1)


if __name__ == "__main__":
    unittest.main()
