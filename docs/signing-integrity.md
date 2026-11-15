# Native binary integrity and signing

The user's Apple Silicon macOS environment reported an arm64 Mach-O executable with an embedded ad-hoc linker signature, no TeamIdentifier, and zero valid developer signing identities.

This stage adds a repeatable local build that explicitly applies an ad-hoc signature and checks the finished executable with macOS codesign plus a SHA-256 digest.

From the repository root:

```bash
bash scripts/build-local-signed.sh
```

The build produces `build/AgentGuardGate` and `build/AgentGuardGate.sha256`. Both are local build outputs; do not commit them. To verify the same artifact later:

```bash
python3 -m guard.integrity build/AgentGuardGate --expected-sha256 "$(cat build/AgentGuardGate.sha256)"
```

Expected local results include `codesign_integrity: pass`, `pinned_sha256: pass`, and `signature_kind: ad_hoc`.

To exercise detection of binary modifications without modifying the working executable:

```bash
cp build/AgentGuardGate build/AgentGuardGate.tampered
printf 'x' >> build/AgentGuardGate.tampered
python3 -m guard.integrity build/AgentGuardGate.tampered --expected-sha256 "$(cat build/AgentGuardGate.sha256)"
```

The modified copy must report `status: failed` and exit 2. The pinned hash mismatch demonstrates that the copy is different from the original. The code-signature verification result may depend on where and how a binary is modified, so only report it based on actual output.

Developer ID inspection:

```bash
security find-identity -v -p codesigning
python3 -m guard.integrity build/AgentGuardGate --require-developer-id
```

The Developer ID check should fail in an environment without an installed Developer ID Application signing identity. It checks displayed signing metadata but does not independently validate an Apple certificate chain, notarization ticket, or trusted deployment policy.

Important boundaries:

- Ad-hoc signing has no authenticated developer identity; local users with sufficient privileges can replace and re-sign binaries.
- A SHA-256 file stored beside an executable is not a trusted manifest. Attackers who can change both files can defeat this check. A future release needs a signed manifest or independently trusted expected digest.
- The current Claude Code hook does not invoke `guard.integrity` before the native binary runs. This phase is an inspection and release-preparation workflow, not runtime enforcement hardening.
- Signed and notarized third-party distribution requires the appropriate Apple Developer ID identity, hardened runtime, and Apple's notarization process.
- The native policy gate is still a command-string prototype and does not provide OS-level protection.

Run the full test suite:

```bash
python3 -m unittest discover -s tests -v
```
