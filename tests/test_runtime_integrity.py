import unittest
from unittest.mock import patch

from guard.hook import native_dual_decision, verified_native_comparison


class RuntimeIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.action = {"command": "git status", "cwd": "/tmp"}
        self.python_decision = {"verdict": "allow", "rule_id": "allow_git_status", "reason": "Read-only repository inspection"}
        self.expected = "a" * 64

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_valid_binary_allows_native_comparison(self, integrity, compare):
        integrity.return_value = {"status": "pass"}
        compare.return_value = {"status": "match", "native_decision": self.python_decision}
        result = verified_native_comparison(self.action, self.python_decision, "/tmp/AgentGuardGate", "/tmp/policy.json", self.expected)
        self.assertEqual(result["status"], "match")
        integrity.assert_called_once_with("/tmp/AgentGuardGate", self.expected)
        compare.assert_called_once()

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_tampered_binary_is_not_executed(self, integrity, compare):
        integrity.return_value = {"status": "failed"}
        result = verified_native_comparison(self.action, self.python_decision, "/tmp/AgentGuardGate", "/tmp/policy.json", self.expected)
        self.assertEqual(result["status"], "error")
        compare.assert_not_called()
        self.assertEqual(native_dual_decision(self.python_decision, result)["verdict"], "deny")

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_missing_pinned_hash_fails_closed(self, integrity, compare):
        result = verified_native_comparison(self.action, self.python_decision, "/tmp/AgentGuardGate", "/tmp/policy.json", None)
        self.assertEqual(result["status"], "error")
        integrity.assert_not_called()
        compare.assert_not_called()

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_missing_native_gate_fails_closed(self, integrity, compare):
        result = verified_native_comparison(self.action, self.python_decision, None, "/tmp/policy.json", self.expected)
        self.assertEqual(result["status"], "error")
        integrity.assert_not_called()
        compare.assert_not_called()

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_wrong_hash_blocks_before_execution(self, integrity, compare):
        integrity.return_value = {"status": "failed", "checks": {"pinned_sha256": "fail"}}
        result = verified_native_comparison(self.action, self.python_decision, "/tmp/AgentGuardGate", "/tmp/policy.json", "0" * 64)
        self.assertEqual(result["reason"], "Native binary integrity verification failed")
        compare.assert_not_called()

    @patch("guard.hook.compare_native")
    @patch("guard.hook.inspect_binary")
    def test_native_mismatch_still_denies(self, integrity, compare):
        integrity.return_value = {"status": "pass"}
        compare.return_value = {"status": "mismatch", "native_decision": {"verdict": "deny", "rule_id": "default", "reason": "No matching policy rule"}}
        result = verified_native_comparison(self.action, self.python_decision, "/tmp/AgentGuardGate", "/tmp/policy.json", self.expected)
        self.assertEqual(native_dual_decision(self.python_decision, result)["rule_id"], "native_parity_failure")


if __name__ == "__main__":
    unittest.main()
