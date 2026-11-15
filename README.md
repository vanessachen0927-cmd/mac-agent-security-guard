# Mac Agent Security Guard

Local, deterministic AI-agent command policy evaluator with JSONL decision receipts and a SwiftUI receipt viewer prototype.

## Run

```bash
python3 -m unittest discover -s tests -v
python3 -m guard.cli --command 'git status' --log receipts.jsonl
python3 -m guard.cli --command 'rm -rf /tmp/example' --log receipts.jsonl
```

The second command is denied and exits with status 2; commands are **never executed** by this tool.

To authenticate receipts with a local secret, set `GUARD_RECEIPT_KEY` before running the CLI. The receipt includes a SHA-256 digest of canonical JSON and an HMAC-SHA256 when a key is set. The HMAC does not provide independent, asymmetric countersigning.

## macOS viewer

Create a macOS SwiftUI app target in Xcode, replace the generated application source with `macos/AgentGuardApp.swift`, build, and select the receipt log via the app. The Swift source is provided but has not been compiled or signed in this environment.

## Security scope and limitations

This is a policy-engine prototype, **not an enforcement hook**, endpoint protection agent, notarized application, sandbox, signed binary, or Jamf/MDM deployment. It evaluates a single command string without executing it. It does not expand shells, resolve symlinks, inspect scripts, enforce OS filesystem restrictions, prevent bypasses, or fully identify secrets embedded in command arguments. `git` rule matching is intentionally simple and must not be trusted against malicious adversaries. Deploying this as a security boundary requires a trusted agent interception point, path normalization, policy authentication, fail-closed operations, platform controls, and independent security review.

## Claude Code PreToolUse integration

The project now includes a project-local Claude Code Bash `PreToolUse` hook. Run from this repository:

```bash
python3 -m unittest discover -s tests -v
python3 -m guard.install_hook
```

After accepting or verifying the generated `.claude/settings.local.json`, restart Claude Code within this repository. The hook runs `guard/hook.py` before Claude Code's Bash tool. A denied action exits with code 2 and a readable reason; permitted actions exit with code 0, which leaves normal Claude Code permissions in effect. The hook never executes the requested command itself.

Test the hook without Claude Code:

```bash
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp/example"}' | python3 guard/hook.py
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/example"},"cwd":"/tmp/example"}' | python3 guard/hook.py
```

The second test exits with code 2 and **does not execute the command**. Receipts are stored in `~/.mac-agent-security-guard/receipts.jsonl`, with restrictive permissions for newly created files. Because receipts record raw command text, do not test with real secrets. The generated Claude settings are local to this repository and are not meant for production installation.

This hook covers **only Claude Code Bash calls within this repository**. It does not intercept Claude Code's Write/Edit tools, other agents, other apps, direct Terminal commands, shell scripts launched indirectly, or actions taken outside the hook. Shell syntax screening is intentionally conservative but is not a secure shell parser. A hook can be disabled or bypassed by users or tools with sufficient access. Never treat it as a system-wide security boundary.
