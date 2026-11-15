# Native shadow-mode comparison

This experimental mode compares the native Swift gate to the Python reference decision while preserving Python as the sole enforcement authority.

Compile the native evaluator on macOS:

```bash
mkdir -p build
swiftc native-gate/AgentGuardGate.swift -o build/AgentGuardGate
```

Run a hook comparison without Claude Code:

```bash
AGENT_GUARD_NATIVE_SHADOW="$PWD/build/AgentGuardGate" python3 -m unittest discover -s tests -p test_shadow.py -v
```

To exercise a real proposed hook event:

```bash
export AGENT_GUARD_NATIVE_SHADOW="$PWD/build/AgentGuardGate"
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | python3 guard/hook.py
cat ~/.mac-agent-security-guard/shadow.jsonl
```

Each shadow record provides the evaluation status (`match`, `mismatch`, `error`, or `skipped`), an action digest, and native and Python decision metadata where available. It does not include the raw command but may still include sensitive rule names. The normal receipts log still records raw command text; use disposable test actions only.

Native comparison failures or mismatches do not change the Python hook's allow/deny result. This mode runs the Swift binary for each eligible evaluation and can increase hook latency. The native evaluator does not execute the requested command.

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

This does not demonstrate native enforcement, signed binary delivery, system-wide protection, or compatibility with all shell constructs. The live Claude Code integration still requires a supported Claude Code login and a manual end-to-end check.
