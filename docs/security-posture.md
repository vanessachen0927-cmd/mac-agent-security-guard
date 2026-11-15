# Security posture report

Generate a read-only project-local health report:

```bash
python3 -m guard.posture
```

To authenticate receipts generated using an HMAC key:

```bash
GUARD_RECEIPT_KEY="your-test-key" python3 -m guard.posture --receipts /tmp/guard-auth-test.jsonl
```

The command prints JSON with a top-level status of `healthy`, `warning`, or `failed`. It inspects:

- The configured policy file, including its default verdict, rule count, and rule identifiers
- The project-local Claude Code Bash `PreToolUse` hook registration
- Receipt digests and optional HMAC authentication

A `healthy` report means these local checks passed. It does not prove that Claude Code has actually invoked the hook, that another tool cannot bypass the hook, that an untrusted user cannot alter the configuration, or that a signed macOS enforcement extension is present.

The report contains no full command payloads or HMAC secrets, but it does include rule names and verification counts. Review it before sharing.

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The machine-health report is designed to be displayed by a native macOS client or consumed by a separate management system after additional integration and security review.
