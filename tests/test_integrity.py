import hashlib
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from guard.integrity import inspect, sha256_file


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name) / "AgentGuardGate"
        self.path.write_bytes(b"native gate test fixture")
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.metadata = "Executable=/tmp/AgentGuardGate\nSignature=adhoc\nTeamIdentifier=not set\n"
        self.verify_ok = subprocess.CompletedProcess([], 0, "", "")
        self.metadata_ok = subprocess.CompletedProcess([], 0, "", self.metadata)

    def test_sha256_is_stable(self):
        self.assertEqual(sha256_file(self.path), self.digest)

    @patch("guard.integrity.subprocess.run")
    def test_ad_hoc_signature_is_accepted_for_local_integrity(self, runner):
        runner.side_effect = [self.verify_ok, self.metadata_ok]
        report = inspect(self.path, self.digest)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["signature_kind"], "ad_hoc")
        self.assertIsNone(report["team_identifier"])

    @patch("guard.integrity.subprocess.run")
    def test_wrong_pinned_hash_fails(self, runner):
        runner.side_effect = [self.verify_ok, self.metadata_ok]
        self.assertEqual(inspect(self.path, "0" * 64)["status"], "failed")

    @patch("guard.integrity.subprocess.run")
    def test_invalid_expected_hash_fails(self, runner):
        runner.side_effect = [self.verify_ok, self.metadata_ok]
        self.assertEqual(inspect(self.path, "invalid")["status"], "failed")

    @patch("guard.integrity.subprocess.run")
    def test_signature_failure_fails(self, runner):
        runner.side_effect = [
            subprocess.CompletedProcess([], 1, "", "invalid signature"),
            self.metadata_ok
        ]
        self.assertEqual(inspect(self.path, self.digest)["status"], "failed")

    @patch("guard.integrity.subprocess.run")
    def test_ad_hoc_is_not_developer_id(self, runner):
        runner.side_effect = [self.verify_ok, self.metadata_ok]
        report = inspect(self.path, self.digest, require_developer_id=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["checks"]["developer_id"], "fail")

    @patch("guard.integrity.subprocess.run")
    def test_developer_id_with_team_metadata(self, runner):
        metadata = "Executable=/tmp/AgentGuardGate\nAuthority=Developer ID Application: Example Company (ABCDE12345)\nTeamIdentifier=ABCDE12345\n"
        runner.side_effect = [
            self.verify_ok,
            subprocess.CompletedProcess([], 0, "", metadata)
        ]
        report = inspect(self.path, self.digest, require_developer_id=True)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["checks"]["developer_id"], "pass")

    def test_missing_executable_fails(self):
        self.assertEqual(inspect(self.path.with_name("missing"))["status"], "failed")


if __name__ == "__main__":
    unittest.main()
