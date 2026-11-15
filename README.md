# Mac Agent Security Guard

Mac Agent Security Guard is an experimental macOS portfolio project for evaluating AI coding agent Bash tool proposals. It includes a Python policy and Claude Code hook, a native Swift deterministic evaluator, Python–Swift decision parity checks, SHA-256/HMAC audit receipts, native integrity verification, and a SwiftUI viewer for receipts and machine-health reports.

**Security scope:** A project-local hook prototype, not a production endpoint security application, macOS Endpoint Security extension, system-wide command sandbox, or notarized product.

## Repository

- `guard/`: policy evaluation, Claude Code hook, cryptographic receipts, health reporting, and native integrity checks
- `native-gate/AgentGuardGate.swift`: native Swift command evaluation CLI
- `MacAgentSecurityGuard/`: macOS SwiftUI app with Decision Receipts and Machine Health views
- `examples/policy.json`: five representative allow/deny rules
- `tests/`: Python security, parity, and failure-case tests
- `scripts/`: local ad-hoc signing, release packaging, and disposable demo
- `docs/release-demo.md`: release validation and 90-second demonstration guide

## Test and demonstrate

```bash
python3 -m unittest discover -s tests -v
bash scripts/build-local-signed.sh
bash scripts/demo-local.sh
```

The test hook evaluates the supplied Bash command text, and **does not execute it**. The demo uses only disposable logs and a test HMAC key. A legitimate Claude Code session is not required for the simulated tests.

To generate a current machine-health report for the SwiftUI viewer:

```bash
python3 -m guard.posture > /tmp/mac-agent-health.json
```

## Package a local development release

On Apple Silicon macOS with Xcode installed:

```bash
bash scripts/package-macos-dev.sh
```

If Xcode builds successfully, the script creates an unsigned macOS application and ad-hoc-signed Swift CLI in a ZIP under `build/releases/`. This is **not a notarized or Developer ID signed release**. It is a local development build intended for demonstrations.

See [the release and demo guide](docs/release-demo.md) for use, verification, limitations, and rollback.

## Claude Code integration

A project-local Bash PreToolUse hook can be configured with:

```bash
python3 -m guard.install_hook
```

Review the generated `.claude/settings.local.json` before launching Claude Code. By default, the hook uses the Python evaluator. An opt-in native dual-consensus mode compares Python and Swift decisions, and `native_verified` additionally checks a configured native binary digest and macOS code signature before native evaluation. The native executable does not independently intercept tool calls.

The hook only applies to relevant Claude Code Bash events when configured in this project; it does not cover Write/Edit, other agents, Terminal commands, or arbitrary shell execution. User-editable hooks can be bypassed, and the simplistic command-string policy is not a trusted shell parser.

## Security boundaries

Audit receipts may contain raw proposed commands, so avoid using actual secrets in demonstrations. An HMAC receipt is authenticated only when verified using a separately held secret key. Local ad-hoc signatures do not authenticate developer identity. A hash next to a binary is not a protected trust root, and the native integrity check does not eliminate check-to-execution races.

No live Claude Code authentication test, independent native security extension, Apple Developer ID signing, notarization, or fleet-management deployment is claimed.
