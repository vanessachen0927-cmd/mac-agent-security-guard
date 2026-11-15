import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from guard.hook import process
from guard.policy import load_policy

ROOT = pathlib.Path(__file__).resolve().parent.parent


class HookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy()

    def payload(self, command):
        return {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': '/tmp/example'}

    def run_hook(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'receipts.jsonl'
            env = dict(os.environ, AGENT_GUARD_LOG=str(path))
            run = subprocess.run([sys.executable, str(ROOT / 'guard' / 'hook.py')], input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=ROOT)
            records = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            return run, records

    def test_safe_command_exits_zero(self):
        run, records = self.run_hook(self.payload('git status'))
        self.assertEqual(run.returncode, 0)
        self.assertEqual(records[0]['decision']['verdict'], 'allow')

    def test_delete_exits_two(self):
        run, records = self.run_hook(self.payload('rm -rf /tmp/example'))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(records[0]['decision']['rule_id'], 'deny_delete')

    def test_credential_access_exits_two(self):
        run, records = self.run_hook(self.payload('cat /Users/me/.ssh/id_rsa'))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(records[0]['decision']['rule_id'], 'deny_credential_access')

    def test_compound_command_fails_closed(self):
        run, _ = self.run_hook(self.payload('git status; rm -rf /tmp/example'))
        self.assertEqual(run.returncode, 2)

    def test_shell_substitution_fails_closed(self):
        run, _ = self.run_hook(self.payload('ls $(echo /tmp)'))
        self.assertEqual(run.returncode, 2)

    def test_unknown_command_fails_closed(self):
        run, _ = self.run_hook(self.payload('python3 -c pass'))
        self.assertEqual(run.returncode, 2)

    def test_malformed_event_fails_closed(self):
        run, _ = self.run_hook({'tool_name': 'Bash'})
        self.assertEqual(run.returncode, 2)

    def test_invalid_json_fails_closed(self):
        run = subprocess.run([sys.executable, str(ROOT / 'guard' / 'hook.py')], input='{broken', capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(run.returncode, 2)

    def test_non_bash_fails_closed(self):
        decision, _ = process({'hook_event_name': 'PreToolUse', 'tool_name': 'Write'}, self.policy)
        self.assertEqual(decision['verdict'], 'deny')


if __name__ == '__main__':
    unittest.main()
