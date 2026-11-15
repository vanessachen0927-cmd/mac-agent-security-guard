# Mac Agent Security Guard — v1.0 development release and demo

This is a portfolio-ready development-release candidate, not a notarized endpoint protection product.

## Build the application and package

From the repository root on an Apple Silicon Mac with Xcode:

```bash
git switch release/v1-portfolio-candidate
python3 -m unittest discover -s tests -v
bash scripts/package-macos-dev.sh
```

The release script compiles and ad-hoc signs the native Swift command evaluator, verifies its signature and SHA-256, builds the macOS SwiftUI app with Xcode, stages the app, policy, Python hook, native gate, and documents, then creates a ZIP in `build/releases`.

The app is built with `CODE_SIGNING_ALLOWED=NO`. It is not Developer ID signed or notarized. This release is for local development and demonstration on your own Mac. The ZIP SHA-256 beside the archive provides an untrusted checksum for transfer verification, not an independently authenticated release.

If Xcode reports a build failure, do not distribute the bundle; resolve the native build before attempting the demo.

## Demonstration using disposable commands

Before running the disposable demo, build the gate:

```bash
bash scripts/build-local-signed.sh
bash scripts/demo-local.sh
```

The demo operates on temporary receipt logs and a disposable HMAC key. It invokes the hook with one permitted read-only command and one denied destructive command. The proposed commands are never executed. It verifies both receipts and checks for two successful Python–Swift comparisons.

Expected evidence:

- The `git status` proposal returns 0 and is allowed.
- The `rm -rf /tmp/guard-demo-do-not-create` proposal returns 2 and is blocked.
- Receipt verifier reports two authenticated records, zero invalid.
- The shadow-comparison log reports two matches.
- The executable passes the local ad-hoc signature and pinned SHA-256 checks.

## Native app demonstration

Generate the actual machine-health JSON report using your existing local receipt log:

```bash
python3 -m guard.posture > /tmp/mac-agent-health.json
```

Open `MacAgentSecurityGuard/MacAgentSecurityGuard.xcodeproj` in Xcode and run on My Mac. Select the Machine Health tab, choose Open Health Report, and import `/tmp/mac-agent-health.json` using the file picker. It should show the actual local policy and hook checks and the authentication status of your existing receipts. The JSON report is a snapshot: regenerate it before refreshing to show current evidence.

Select Decision Receipts and open `~/.mac-agent-security-guard/receipts.jsonl` to display allowed and blocked decisions. If the receipts were created with a secret, enter the matching HMAC key in the app for authentication verification. Do not display actual secrets or sensitive command contents during recording.

## Suggested 90-second Dryx demonstration

**0–15 seconds:** Introduce the macOS project and explain that the Python and Swift policy engines evaluate proposed AI-agent Bash commands without running them.

**15–35 seconds:** Show a read-only command being permitted and a destructive command being denied, with terminal exit codes 0 and 2.

**35–55 seconds:** Show the matched Python–Swift decisions and cryptographic audit receipt verification. Explain that HMAC authentication requires a separate key, unlike a plain hash.

**55–75 seconds:** Switch to the SwiftUI app, show Decision Receipts and Machine Health, and point out the real policy and audit results.

**75–90 seconds:** Show that a modified native executable fails signature and SHA-256 checks. State that this is a local proof of concept, not a macOS Endpoint Security extension or notarized agent.

## Local rollback

This repository only installs a project-local Claude Code hook when you explicitly execute `python3 -m guard.install_hook`. Inspect `.claude/settings.local.json` before running Claude Code. To disable experimental modes in your shell:

```bash
unset AGENT_GUARD_MODE AGENT_GUARD_NATIVE_GATE AGENT_GUARD_NATIVE_SHADOW AGENT_GUARD_NATIVE_EXPECTED_SHA256
```

Do not delete a shared Claude Code settings file to remove this hook. Remove only this project's hook entry, preserving other users' or tools' settings.

## Limits and future work

A normal user can edit or bypass project-local Claude Code hooks. The Python hook remains the controlling interception point. The native evaluator uses simple command-string rules, so it does not safely parse arbitrary shell commands. Ad-hoc signing proves no developer identity. A locally controlled digest is not a protected trust anchor. Runtime verification has a verification-to-execution race. Real Claude Code behavior still requires an end-to-end test under an authenticated Claude Code session. Hardened runtime, Apple Developer ID signing and notarization are not included.
