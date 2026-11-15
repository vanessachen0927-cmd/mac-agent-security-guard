import unittest
from guard.policy import evaluate, load_policy
from guard.cli import receipt


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy()

    def decide(self, command, cwd="/tmp/project"):
        return evaluate({"command": command, "cwd": cwd}, self.policy)

    def test_delete_is_denied(self):
        self.assertEqual(self.decide("rm -rf /tmp/project")["verdict"], "deny")

    def test_shred_is_denied(self):
        self.assertEqual(self.decide("shred token.txt")["verdict"], "deny")

    def test_credential_ssh_is_denied(self):
        self.assertEqual(self.decide("cat /Users/test/.ssh/id_rsa")["verdict"], "deny")

    def test_credential_env_is_denied(self):
        self.assertEqual(self.decide("cat secrets.env")["verdict"], "deny")

    def test_git_status_is_allowed(self):
        self.assertEqual(self.decide("git status")["verdict"], "allow")

    def test_pwd_is_allowed(self):
        self.assertEqual(self.decide("pwd")["verdict"], "allow")

    def test_ls_is_allowed(self):
        self.assertEqual(self.decide("ls -la")["verdict"], "allow")

    def test_unknown_command_fails_closed(self):
        self.assertEqual(self.decide("curl https://example.com")["verdict"], "deny")

    def test_parse_error_fails_closed(self):
        self.assertEqual(self.decide("cat '")["verdict"], "deny")

    def test_same_action_same_decision(self):
        action = {"command": "rm -rf build", "cwd": "/tmp/project"}
        self.assertEqual(evaluate(action, self.policy), evaluate(action, self.policy))

    def test_receipt_has_digest(self):
        record = receipt({"command": "pwd"}, {"verdict": "allow"}, None)
        self.assertEqual(len(record["sha256"]), 64)

    def test_receipt_has_hmac(self):
        record = receipt({"command": "pwd"}, {"verdict": "allow"}, "demo-key")
        self.assertEqual(len(record["hmac_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
