import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from guard.cli import receipt
from guard.policy import evaluate, load_policy


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


def main():
    try:
        payload = json.load(sys.stdin)
        policy = load_policy(os.environ['AGENT_GUARD_POLICY']) if os.getenv('AGENT_GUARD_POLICY') else load_policy()
        decision, action = process(payload, policy)
        record = receipt(action, decision, os.getenv('GUARD_RECEIPT_KEY'))
        append_receipt(record, os.getenv('AGENT_GUARD_LOG', '~/.mac-agent-security-guard/receipts.jsonl'))
        if decision['verdict'] == 'allow':
            return 0
        print('Mac Agent Security Guard blocked Bash: ' + decision['reason'] + ' (' + decision['rule_id'] + ')', file=sys.stderr)
        return 2
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        print('Mac Agent Security Guard blocked Bash: hook validation or logging failed: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
