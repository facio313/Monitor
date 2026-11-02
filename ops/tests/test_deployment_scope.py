import unittest

from ops.deployment_scope import HOST_NOTIFICATION_FILES, requires_runtime_deployment


class DeploymentScopeTests(unittest.TestCase):
    def test_complete_host_notification_change_skips_only_runtime_cutover(self):
        self.assertFalse(requires_runtime_deployment("push", "parent", "parent",
                                                    list(HOST_NOTIFICATION_FILES)))

    def test_any_runtime_change_keeps_existing_deployment(self):
        for path in ("src/App.tsx", "server/app.ts", "Dockerfile", "package-lock.json",
                     "docker-compose.yml", "ops/unknown.py"):
            with self.subTest(path=path):
                self.assertTrue(requires_runtime_deployment(
                    "push", "parent", "parent", ["ops/notification_reports.py", path]))

    def test_manual_or_unproven_push_keeps_deployment(self):
        for event, before, parent, changed in (
            ("workflow_dispatch", "parent", "parent", ["ops/notification_reports.py"]),
            ("push", "earlier-commit", "parent", ["ops/notification_reports.py"]),
            ("push", "", "parent", ["ops/notification_reports.py"]),
            ("push", "parent", "parent", []),
        ):
            self.assertTrue(requires_runtime_deployment(event, before, parent, changed))


if __name__ == "__main__":
    unittest.main()
