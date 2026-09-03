from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SDK_COMMIT = "a083d0462012160a8ce5a4cc5b7b0fe077840200"
FORK_GUARD = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false"


class PhaseZeroCorrectionContract(unittest.TestCase):
    def test_sdk_commit_is_consistent_and_real_sha_shaped(self) -> None:
        lock = json.loads(
            (ROOT / "services/policy-decision/contracts/upstream.lock.json").read_text(
                encoding="utf-8"
            )
        )
        handler = (ROOT / "ci/handlers/prefetch.py").read_text(encoding="utf-8")
        self.assertRegex(SDK_COMMIT, r"^[0-9a-f]{40}$")
        self.assertEqual(lock["sdk"]["commit"], SDK_COMMIT)
        self.assertEqual(handler.count(SDK_COMMIT), 1)
        self.assertNotIn("a083d04fb2c0f32a1ce8373a6251e703226380c8", handler)

    def test_public_fork_guard_precedes_self_hosted_runner_selection(self) -> None:
        workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count(FORK_GUARD), 1)
        guard_offset = workflow.index(FORK_GUARD)
        runner_offset = workflow.index(
            "runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]"
        )
        self.assertLess(guard_offset, runner_offset)
        self.assertNotRegex(workflow, re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE))
        self.assertNotIn("HARNESS_TASK_PACKET:", workflow)


if __name__ == "__main__":
    unittest.main()
