import json
import pathlib
import tempfile
import unittest

from guard.cli import receipt
from guard.posture import build_report, check_hook, check_policy, check_receipts


class PostureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "guard").mkdir()
        (self.root / "examples").mkdir()
        (self.root / ".claude").mkdir()
        (self.root / "guard" / "hook.py").write_text("", encoding="utf-8")
        self.policy_path = self.root / "examples" / "policy.json"
        self.settings_path = self.root / ".claude" / "settings.local.json"
        self.receipts_path = self.root / "receipts.jsonl"
        self.policy_path.write_text(json.dumps({"default_verdict": "deny", "rules": [{"id": "allow_pwd", "executables": ["pwd"], "verdict": "allow", "reason": "Inspection"}]}), encoding="utf-8")
        self.settings_path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 " + str(self.root / "guard" / "hook.py")}]}]}}), encoding="utf-8")
        self.record = receipt({"command": "pwd", "cwd": "/tmp"}, {"verdict": "allow", "rule_id": "allow_pwd", "reason": "Inspection"}, "test-key")
        self.receipts_path.write_text(json.dumps(self.record) + "\n", encoding="utf-8")

    def test_valid_policy(self):
        result = check_policy(self.policy_path)
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["rule_count"], 1)

    def test_default_allow_warning(self):
        policy = json.loads(self.policy_path.read_text())
        policy["default_verdict"] = "allow"
        self.policy_path.write_text(json.dumps(policy))
        self.assertEqual(check_policy(self.policy_path)["status"], "warning")

    def test_duplicate_rule_fails(self):
        policy = json.loads(self.policy_path.read_text())
        policy["rules"].append(policy["rules"][0])
        self.policy_path.write_text(json.dumps(policy))
        self.assertEqual(check_policy(self.policy_path)["status"], "failed")

    def test_missing_policy_fails(self):
        self.policy_path.unlink()
        self.assertEqual(check_policy(self.policy_path)["status"], "failed")

    def test_matching_hook(self):
        self.assertEqual(check_hook(self.settings_path, self.root / "guard" / "hook.py")["status"], "healthy")

    def test_missing_hook(self):
        self.settings_path.unlink()
        self.assertEqual(check_hook(self.settings_path, self.root / "guard" / "hook.py")["status"], "failed")

    def test_unrelated_hook_fails(self):
        self.settings_path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 /tmp/other.py"}]}]}}))
        self.assertEqual(check_hook(self.settings_path, self.root / "guard" / "hook.py")["status"], "failed")

    def test_authenticated_receipts(self):
        result = check_receipts(self.receipts_path, "test-key")
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["counts"]["authenticated"], 1)

    def test_missing_key_warning(self):
        self.assertEqual(check_receipts(self.receipts_path, None)["status"], "warning")

    def test_tampered_receipt_fails(self):
        changed = dict(self.record)
        changed["timestamp"] = "tampered"
        self.receipts_path.write_text(json.dumps(changed) + "\n")
        self.assertEqual(check_receipts(self.receipts_path, "test-key")["status"], "failed")

    def test_missing_receipt_file_fails(self):
        self.receipts_path.unlink()
        self.assertEqual(check_receipts(self.receipts_path, "test-key")["status"], "failed")

    def test_full_report(self):
        report = build_report(self.root, self.receipts_path, "test-key")
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["scope"], "local_project")
        self.assertEqual(set(report["checks"]), {"policy", "hook", "receipts"})

    def test_report_warning_on_missing_key(self):
        self.assertEqual(build_report(self.root, self.receipts_path)["status"], "warning")


if __name__ == "__main__":
    unittest.main()
