# Opt-in native dual-consensus enforcement

This stage introduces a conservative experimental hook mode that requires the native Swift gate and Python policy engine to agree exactly before allowing a command.

Default behavior remains Python-only. Do not enable this mode for important real workflows without first verifying it on disposable commands.

On macOS, from the repository root:

```bash
mkdir -p build
swiftc native-gate/AgentGuardGate.swift -o build/AgentGuardGate
python3 -m unittest discover -s tests -v
```

Try native dual mode with a safe simulated hook event:

```bash
export AGENT_GUARD_MODE=native_dual
export AGENT_GUARD_NATIVE_GATE="$PWD/build/AgentGuardGate"
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | python3 guard/hook.py
```

The native Swift evaluator and Python policy engine both evaluate the proposed command without executing it.

The hook permits an action only if native and Python return exactly identical allow decisions. It denies if either evaluator denies, the decisions disagree, the native executable is missing, the native executable fails or times out, the response is malformed, or the comparison cannot be written to its separate log.

The original decision receipt continues to use the established SHA-256 and optional HMAC format. The shadow comparison record contains the action digest and decisions, but not the original command.

To return to the established Python-only enforcement mode:

```bash
unset AGENT_GUARD_MODE AGENT_GUARD_NATIVE_GATE
```

This is not signed code, notarized native enforcement, an OS-level control, or a guarantee against bypassing user-configurable hooks. The native Swift gate is still launched by a Python hook, and both engines consume mutable local policy data. Code signing, authenticated policy deployment, broader adversarial parity testing, and live Claude Code testing are future work.
