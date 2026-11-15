import copy
import json
import pathlib
import tempfile
import unittest

from guard.cli import receipt
from guard.verify import verify_file, verify_record


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.record = receipt({'command': 'git status', 'cwd': '/tmp/example'}, {'verdict': 'allow', 'rule_id': 'allow_git_status', 'reason': 'Read-only repository inspection'}, None)

    def test_digest_only(self):
        self.assertEqual(verify_record(self.record)[0], 'digest_only')

    def test_modified_command_fails(self):
        modified = copy.deepcopy(self.record)
        modified['action']['command'] = 'rm -rf /tmp/example'
        self.assertEqual(verify_record(modified)[0], 'invalid')

    def test_modified_verdict_fails(self):
        modified = copy.deepcopy(self.record)
        modified['decision']['verdict'] = 'deny'
        self.assertEqual(verify_record(modified)[0], 'invalid')

    def test_removed_digest_fails(self):
        modified = copy.deepcopy(self.record)
        del modified['sha256']
        self.assertEqual(verify_record(modified)[0], 'invalid')

    def test_authenticated_hmac(self):
        signed = receipt({'command': 'pwd'}, {'verdict': 'allow'}, 'sample-test-key')
        self.assertEqual(verify_record(signed, 'sample-test-key')[0], 'authenticated')

    def test_hmac_requires_key(self):
        signed = receipt({'command': 'pwd'}, {'verdict': 'allow'}, 'sample-test-key')
        self.assertEqual(verify_record(signed)[0], 'key_required')

    def test_wrong_hmac_key_fails(self):
        signed = receipt({'command': 'pwd'}, {'verdict': 'allow'}, 'sample-test-key')
        self.assertEqual(verify_record(signed, 'wrong-key')[0], 'invalid')

    def test_extra_field_fails(self):
        modified = copy.deepcopy(self.record)
        modified['new_field'] = 'ignored'
        self.assertEqual(verify_record(modified)[0], 'invalid')

    def test_malformed_json_line_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'receipts.jsonl'
            path.write_text(json.dumps(self.record) + '\nnot-json\n', encoding='utf-8')
            rows = verify_file(path)
            self.assertEqual([r['status'] for r in rows], ['digest_only', 'invalid'])


if __name__ == '__main__':
    unittest.main()
