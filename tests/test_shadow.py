import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from guard.shadow import compare_native

ROOT = pathlib.Path(__file__).resolve().parent.parent


class ShadowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.receipts = self.root / "receipts.jsonl"
        self.shadow = self.root / "shadow.jsonl"
        self.executable = self.root / "fake_gate.py"
        self.executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "action = json.load(sys.stdin)\n"
            "verdict = 'allow' if action['command'] == 'git status' else 'deny'\n"
            "rule = 'allow_git_status' if verdict == 'allow' else 'deny_delete'\n"
            "reason = 'Read-only repository inspection' if verdict == 'allow' else 'Destructive file removal requires manual review'\n"
            "print(json.dumps({'verdict': verdict, 'rule_id': rule, 'reason': reason}))\n"
            "sys.exit(0 if verdict == 'allow' else 2)\n",
            encoding="utf-8"
        )
        self.executable.chmod(0o700)

    def run_hook(self, command, executable=None):
        env = os.environ.copy()
        env.update({
            "AGENT_GUARD_LOG": str(self.receipts),
            "AGENT_GUARD_SHADOW_LOG": str(self.shadow),
            "AGENT_GUARD_NATIVE_SHADOW": str(executable or self.executable)
        })
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp"}
        return subprocess.run(
            [sys.executable, str(ROOT / "guard" / "hook.py")],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT
        )

    def shadow_status(self):
        return json.loads(self.shadow.read_text(encoding="utf-8").splitlines()[-1])["status"]

    def test_allow_comparison_matches(self):
        run = self.run_hook("git status")
        self.assertEqual(run.returncode, 0)
        self.assertEqual(self.shadow_status(), "match")
        self.assertEqual(json.loads(self.receipts.read_text().splitlines()[0])["decision"]["verdict"], "allow")

    def test_deny_comparison_matches(self):
        run = self.run_hook("rm -rf /tmp/example")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.shadow_status(), "match")

    def test_shadow_failure_does_not_override_python(self):
        run = self.run_hook("git status", self.root / "missing")
        self.assertEqual(run.returncode, 0)
        self.assertEqual(self.shadow_status(), "error")

    def test_shadow_mismatch_does_not_override_python(self):
        run = self.run_hook("pwd")
        self.assertEqual(run.returncode, 0)
        self.assertEqual(self.shadow_status(), "mismatch")

    def test_shadow_not_enabled_does_not_create_log(self):
        env = os.environ.copy()
        env.pop("AGENT_GUARD_NATIVE_SHADOW", None)
        env["AGENT_GUARD_LOG"] = str(self.receipts)
        env["AGENT_GUARD_SHADOW_LOG"] = str(self.shadow)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "/tmp"}
        run = subprocess.run([sys.executable, str(ROOT / "guard" / "hook.py")], input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=ROOT)
        self.assertEqual(run.returncode, 0)
        self.assertFalse(self.shadow.exists())


if __name__ == "__main__":
    unittest.main()
