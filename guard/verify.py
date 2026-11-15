import argparse
import hashlib
import hmac
import json
import pathlib
import sys


def canonical_body(record):
    body = {key: value for key, value in record.items() if key not in ('sha256', 'hmac_sha256')}
    if set(body) != {'action', 'decision', 'timestamp'}:
        raise ValueError('Unexpected receipt fields')
    if not isinstance(body['action'], dict) or not isinstance(body['decision'], dict) or not isinstance(body['timestamp'], str):
        raise ValueError('Invalid receipt body')
    return json.dumps(body, sort_keys=True, separators=(',', ':')).encode()


def verify_record(record, key=None):
    if not isinstance(record, dict):
        return 'invalid', 'Receipt is not a JSON object'
    try:
        canonical = canonical_body(record)
    except (TypeError, ValueError) as error:
        return 'invalid', str(error)
    digest = record.get('sha256')
    expected_digest = hashlib.sha256(canonical).hexdigest()
    if not isinstance(digest, str) or not hmac.compare_digest(expected_digest, digest):
        return 'invalid', 'SHA-256 digest mismatch'
    signature = record.get('hmac_sha256')
    if signature is None:
        return 'digest_only', 'Digest matches, but this receipt is not authenticated'
    if not isinstance(signature, str):
        return 'invalid', 'Invalid HMAC encoding'
    if key is None:
        return 'key_required', 'Digest matches; an HMAC key is required to authenticate'
    expected = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return 'invalid', 'HMAC authentication failed'
    return 'authenticated', 'Digest and HMAC both verify'


def verify_file(path, key=None):
    rows = []
    with pathlib.Path(path).expanduser().open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                status, reason = verify_record(record, key)
            except (ValueError, UnicodeError) as error:
                status, reason = 'invalid', str(error)
            rows.append({'line': number, 'status': status, 'reason': reason})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    parser.add_argument('--key-env', default='GUARD_RECEIPT_KEY')
    args = parser.parse_args(argv)
    import os
    try:
        rows = verify_file(args.path, os.getenv(args.key_env))
    except OSError as error:
        print(json.dumps({'error': str(error)}))
        return 2
    summary = {status: sum(row['status'] == status for row in rows) for status in ('authenticated', 'digest_only', 'key_required', 'invalid')}
    print(json.dumps({'summary': summary, 'records': rows}, indent=2))
    return 2 if summary['invalid'] else 0


if __name__ == '__main__':
    sys.exit(main())
