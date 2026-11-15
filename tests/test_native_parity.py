import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from guard.policy import evaluate, load_policy


ROOT = pathlib.Path(__file__).resolve().parent.parent


class NativeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("swiftc"):
            raise unittest.SkipTest("Swift compiler is not installed")
        cls.directory = tempfile.TemporaryDirectory()
        cls.executable = pathlib.Path(cls.directory.name) / "AgentGuardGate"
        subprocess.run(
            ["swiftc", str(ROOT / "native-gate" / "AgentGuardGate.swift"), "-o", str(cls.executable)],
            check=True,
            capture_output=True,
            text=True
        )
        cls.policy = load_policy()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "directory"):
            cls.directory.cleanup()

    def test_reference_policy_parity(self):
        commands = [
            "git status",
            "pwd",
            "ls -la",
            "rm -rf /tmp/example",
            "shred /tmp/item",
            "cat ~/.ssh/id_rsa",
            "cat /Users/test/.env",
            "head /Users/test/.aws/credentials",
            "git push",
            "unknown example",
            "git 'status'",
            'git "status"',
            "git status;pwd",
            "git status && pwd",
            "git status | cat",
            "git status\n",
            "git 'status",
            "",
            " ",
            "ls > /tmp/output",
            "git status\\ x"
        ]
        for command in commands:
            with self.subTest(command=command):
                action = {"command": command, "cwd": "/tmp"}
                expected = evaluate(action, self.policy)
                proc = subprocess.run(
                    [str(self.executable), "--policy", str(ROOT / "examples" / "policy.json")],
                    input=json.dumps(action),
                    capture_output=True,
                    text=True
                )
                actual = json.loads(proc.stdout)
                self.assertEqual(actual, expected)
                self.assertEqual(proc.returncode, 0 if expected["verdict"] == "allow" else 2)

    def test_invalid_actions_fail_closed(self):
        for action in [{"command": None, "cwd": "/tmp"}, {"command": "pwd"}, {"command": 5, "cwd": "/tmp"}]:
            with self.subTest(action=action):
                proc = subprocess.run(
                    [str(self.executable), "--policy", str(ROOT / "examples" / "policy.json")],
                    input=json.dumps(action),
                    capture_output=True,
                    text=True
                )
                self.assertEqual(json.loads(proc.stdout)["verdict"], "deny")
                self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
