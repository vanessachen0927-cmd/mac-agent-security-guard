import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class NativeDualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.receipts = self.root / "receipts.jsonl"
        self.shadow = self.root / "shadow.jsonl"
        self.native = self.root / "native_gate.py"
        self.native.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "action = json.load(sys.stdin)\n"
            "mode = os.environ.get('FAKE_NATIVE_MODE', 'match')\n"
            "if mode == 'crash': sys.exit(7)\n"
            "if mode == 'malformed': print('bad json'); sys.exit(0)\n"
            "allow = action['command'] == 'git status'\n"
            "if mode == 'mismatch': allow = not allow\n"
            "decision = {'verdict': 'allow' if allow else 'deny', 'rule_id': 'allow_git_status' if allow else 'deny_delete', 'reason': 'Read-only repository inspection' if allow else 'Destructive file removal requires manual review'}\n"
            "print(json.dumps(decision))\n"
            "sys.exit(0 if allow else 2)\n",
            encoding="utf-8"
        )
        self.native.chmod(0o700)

    def run_hook(self, command="git status", mode="native_dual", executable=True, native_behavior="match", shadow_path=None):
        env = os.environ.copy()
        env.pop("AGENT_GUARD_NATIVE_SHADOW", None)
        env.pop("AGENT_GUARD_NATIVE_GATE", None)
        env["AGENT_GUARD_MODE"] = mode
        env["AGENT_GUARD_LOG"] = str(self.receipts)
        env["AGENT_GUARD_SHADOW_LOG"] = str(shadow_path or self.shadow)
        env["FAKE_NATIVE_MODE"] = native_behavior
        if executable:
            env["AGENT_GUARD_NATIVE_GATE"] = str(self.native)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp"}
        result = subprocess.run(
            [sys.executable, str(ROOT / "guard" / "hook.py")],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT
        )
        records = [json.loads(line) for line in self.receipts.read_text(encoding="utf-8").splitlines()] if self.receipts.exists() else []
        comparisons = [json.loads(line) for line in self.shadow.read_text(encoding="utf-8").splitlines()] if self.shadow.exists() else []
        return result, records, comparisons

    def test_dual_allows_matching_allow(self):
        result, records, comparisons = self.run_hook()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(records[-1]["decision"]["rule_id"], "allow_git_status")
        self.assertEqual(comparisons[-1]["status"], "match")

    def test_dual_denies_matching_deny(self):
        result, records, comparisons = self.run_hook(command="rm -rf /tmp/example")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "deny_delete")
        self.assertEqual(comparisons[-1]["status"], "match")

    def test_dual_denies_mismatched_allow(self):
        result, records, comparisons = self.run_hook(native_behavior="mismatch")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "native_parity_failure")
        self.assertEqual(comparisons[-1]["status"], "mismatch")

    def test_dual_denies_mismatched_deny(self):
        result, records, comparisons = self.run_hook(command="rm -rf /tmp/example", native_behavior="mismatch")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "native_parity_failure")
        self.assertEqual(comparisons[-1]["status"], "mismatch")

    def test_dual_denies_missing_executable(self):
        result, records, comparisons = self.run_hook(executable=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "native_parity_failure")
        self.assertEqual(comparisons[-1]["status"], "error")

    def test_dual_denies_crashed_executable(self):
        result, records, comparisons = self.run_hook(native_behavior="crash")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "native_parity_failure")
        self.assertEqual(comparisons[-1]["status"], "error")

    def test_dual_denies_malformed_native_response(self):
        result, records, comparisons = self.run_hook(native_behavior="malformed")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records[-1]["decision"]["rule_id"], "native_parity_failure")
        self.assertEqual(comparisons[-1]["status"], "error")

    def test_dual_denies_when_comparison_cannot_be_logged(self):
        blocked_path = self.root / "directory"
        blocked_path.mkdir()
        result, records, _ = self.run_hook(shadow_path=blocked_path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records, [])

    def test_invalid_mode_fails_closed(self):
        result, records, _ = self.run_hook(mode="unknown")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(records, [])

    def test_default_python_does_not_require_native(self):
        result, records, comparisons = self.run_hook(mode="python", executable=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(records[-1]["decision"]["verdict"], "allow")
        self.assertEqual(comparisons, [])


if __name__ == "__main__":
    unittest.main()
