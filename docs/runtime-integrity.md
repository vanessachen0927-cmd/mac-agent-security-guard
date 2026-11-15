# Runtime native binary integrity

This stage adds an opt-in `native_verified` mode to the Python hook.

Before asking the native gate to evaluate a proposed action, the hook checks:

- The native executable exists and can be hashed.
- Its actual SHA-256 matches a digest supplied through `AGENT_GUARD_NATIVE_EXPECTED_SHA256`.
- The macOS `codesign --verify --strict` integrity check succeeds.
- The native and Python decisions agree exactly before allowing.

A missing expected digest, missing executable, checksum mismatch, invalid code signature, runtime error, or decision disagreement results in a denial. The default `python` mode and existing `native_dual` mode remain available.

On your Mac, check out this feature branch and run:

```bash
python3 -m unittest discover -s tests -v
bash scripts/build-local-signed.sh
```

Try one disposable simulated hook event with an explicit local digest:

```bash
export AGENT_GUARD_MODE=native_verified
export AGENT_GUARD_NATIVE_GATE="$PWD/build/AgentGuardGate"
export AGENT_GUARD_NATIVE_EXPECTED_SHA256="$(cat build/AgentGuardGate.sha256)"
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | python3 guard/hook.py
echo $?
```

Expected result: exit 0 if both engines agree that `git status` is allowed and local signature and hash checks succeed.

Check a deliberate hash mismatch without changing the executable:

```bash
export AGENT_GUARD_NATIVE_EXPECTED_SHA256="$(printf '0%.0s' {1..64})"
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | python3 guard/hook.py
echo $?
```

Expected result: exit 2. Restore the correct digest before further testing:

```bash
export AGENT_GUARD_NATIVE_EXPECTED_SHA256="$(cat build/AgentGuardGate.sha256)"
```

Disable the experimental mode:

```bash
unset AGENT_GUARD_MODE AGENT_GUARD_NATIVE_GATE AGENT_GUARD_NATIVE_EXPECTED_SHA256
```

Security limitations:

- The expected hash comes from a local environment variable and file in this example. A user or attacker who can replace both the native binary and expected digest can bypass this trust check. This is not an independently authenticated release manifest or protected configuration.
- The integrity check and execution are separate filesystem operations. An attacker able to replace the executable between verification and execution may exploit this time-of-check/time-of-use gap. This design does not eliminate that race.
- Ad-hoc code signatures do not identify the developer. A local attacker able to re-sign a replacement may produce another valid ad-hoc signature, so the independent digest is essential and must be protected.
- This hook remains a project-local user-controlled integration, not a macOS Endpoint Security extension or system-wide enforcement boundary.
- The new checks run inside Python before the Swift process starts. They do not make the enforcement engine independent of Python.

The next hardening milestone is protected trust configuration, signed release identity, and a launch design that avoids mutable-path verification races.
