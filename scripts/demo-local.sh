set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
log="$work/receipts.jsonl"
shadow="$work/shadow.jsonl"
export GUARD_RECEIPT_KEY="disposable-demo-key"
export AGENT_GUARD_LOG="$log"
export AGENT_GUARD_SHADOW_LOG="$shadow"
export AGENT_GUARD_MODE=native_verified
export AGENT_GUARD_NATIVE_GATE="$root/build/AgentGuardGate"
export AGENT_GUARD_NATIVE_EXPECTED_SHA256="$(cat "$root/build/AgentGuardGate.sha256")"

python3 -m guard.integrity "$AGENT_GUARD_NATIVE_GATE" --expected-sha256 "$AGENT_GUARD_NATIVE_EXPECTED_SHA256"

set +e
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | python3 guard/hook.py
allowed=$?
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/guard-demo-do-not-create"},"cwd":"/tmp"}' | python3 guard/hook.py
blocked=$?
set -e

test "$allowed" -eq 0
test "$blocked" -eq 2
python3 -m guard.verify "$log"
python3 - "$shadow" <<'PY'
import json
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
comparisons = [json.loads(line) for line in lines]
assert len(comparisons) == 2
assert all(entry["status"] == "match" for entry in comparisons)
print(json.dumps({"allow_exit": 0, "deny_exit": 2, "shadow_matches": len(comparisons)}, indent=2))
PY
printf 'Disposable demonstration successful; all temporary receipts and keys will be deleted.\n'
