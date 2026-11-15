import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from guard.cli import receipt
from guard.integrity import inspect as inspect_binary
from guard.policy import evaluate, load_policy, DEFAULT_POLICY
from guard.shadow import compare_native, shadow_record


def process(payload, policy):
    if not isinstance(payload, dict) or payload.get('hook_event_name') != 'PreToolUse' or payload.get('tool_name') != 'Bash':
        return {'verdict': 'deny', 'rule_id': 'invalid_hook', 'reason': 'Expected a PreToolUse Bash event'}, {}
    tool_input = payload.get('tool_input')
    if not isinstance(tool_input, dict):
        return {'verdict': 'deny', 'rule_id': 'invalid_hook', 'reason': 'Missing tool input'}, {}
    action = {'command': tool_input.get('command'), 'cwd': payload.get('cwd')}
    if not isinstance(action['command'], str) or not isinstance(action['cwd'], str):
        return {'verdict': 'deny', 'rule_id': 'invalid_hook', 'reason': 'Malformed command or working directory'}, action
    return evaluate(action, policy), action


def append_receipt(record, path):
    path = pathlib.Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


def native_dual_decision(python_decision, comparison):
    if comparison.get('status') == 'match':
        native = comparison.get('native_decision')
        if isinstance(native, dict) and native == python_decision and native.get('verdict') in ('allow', 'deny'):
            return native
    return {
        'verdict': 'deny',
        'rule_id': 'native_parity_failure',
        'reason': 'Native policy check failed or disagreed with Python'
    }


def verified_native_comparison(action, python_decision, executable, policy_path, expected_sha256):
    if not executable:
        return {'status': 'error', 'reason': 'Native executable not configured'}
    if not expected_sha256:
        return {'status': 'error', 'reason': 'Expected native SHA-256 not configured'}
    integrity = inspect_binary(executable, expected_sha256)
    if integrity.get('status') != 'pass':
        return {'status': 'error', 'reason': 'Native binary integrity verification failed'}
    return compare_native(action, python_decision, executable, policy_path)


def main():
    try:
        payload = json.load(sys.stdin)
        policy_path = pathlib.Path(os.environ['AGENT_GUARD_POLICY']) if os.getenv('AGENT_GUARD_POLICY') else DEFAULT_POLICY
        policy = load_policy(policy_path)
        python_decision, action = process(payload, policy)
        mode = os.getenv('AGENT_GUARD_MODE', 'python')
        if mode not in ('python', 'native_dual', 'native_verified'):
            raise ValueError('Invalid guard mode')
        final_decision = python_decision
        executable = os.getenv('AGENT_GUARD_NATIVE_GATE') if mode in ('native_dual', 'native_verified') else os.getenv('AGENT_GUARD_NATIVE_SHADOW')
        if mode in ('native_dual', 'native_verified') or executable:
            if mode == 'native_verified':
                comparison = verified_native_comparison(action, python_decision, executable, policy_path, os.getenv('AGENT_GUARD_NATIVE_EXPECTED_SHA256'))
            else:
                comparison = compare_native(action, python_decision, executable, policy_path) if executable else {'status': 'error', 'reason': 'Native executable not configured'}
            if mode in ('native_dual', 'native_verified'):
                final_decision = native_dual_decision(python_decision, comparison)
            try:
                append_receipt(shadow_record(action, comparison), os.getenv('AGENT_GUARD_SHADOW_LOG', '~/.mac-agent-security-guard/shadow.jsonl'))
            except (OSError, ValueError, TypeError) as error:
                if mode in ('native_dual', 'native_verified'):
                    raise
                print('Mac Agent Security Guard shadow comparison unavailable: ' + type(error).__name__, file=sys.stderr)
        record = receipt(action, final_decision, os.getenv('GUARD_RECEIPT_KEY'))
        append_receipt(record, os.getenv('AGENT_GUARD_LOG', '~/.mac-agent-security-guard/receipts.jsonl'))
        if final_decision['verdict'] == 'allow':
            return 0
        print('Mac Agent Security Guard blocked Bash: ' + final_decision['reason'] + ' (' + final_decision['rule_id'] + ')', file=sys.stderr)
        return 2
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        print('Mac Agent Security Guard blocked Bash: hook validation or logging failed: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
