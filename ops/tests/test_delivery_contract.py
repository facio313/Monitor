import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DeliveryContractTests(unittest.TestCase):
    def test_release_workflow_pins_actions_and_builds_both_linux_architectures(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
        action_refs = re.findall(r"^\s*uses:\s*[^\s@]+@([^\s#]+)", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(action_refs), 7)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs))
        self.assertIn("platforms: linux/amd64,linux/arm64", workflow)
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn('["linux/amd64", "linux/arm64"]', workflow)
        self.assertEqual(workflow.count("TRIVY_PLATFORM: linux/arm64"), 1)
        self.assertEqual(workflow.count("TRIVY_PLATFORM: linux/amd64"), 1)
        self.assertIn("npm audit --audit-level=critical", workflow)
        self.assertLess(
            workflow.index("docker/setup-qemu-action@"),
            workflow.index("docker/setup-buildx-action@"),
        )
        self.assertLess(
            workflow.index("docker/setup-buildx-action@"),
            workflow.index("docker/build-push-action@"),
        )

    def test_image_build_runs_type_and_test_gates_before_production_stage(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        build_gate = (
            "&& npm run typecheck \\\n"
            "    && npm test \\\n"
            "    && npm run build"
        )
        self.assertIn(build_gate, dockerfile)
        production_stage = dockerfile.index(" AS production-dependencies")
        self.assertLess(dockerfile.index("npm run typecheck"), production_stage)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn("/readyz", dockerfile)


if __name__ == "__main__":
    unittest.main()
