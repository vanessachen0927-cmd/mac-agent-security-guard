# Native Swift policy parity

This phase adds a standalone native Swift command-line evaluator and keeps the Python evaluator as the reference.

The native executable reads one action JSON object from standard input and writes a deterministic decision JSON object. It never executes the proposed shell command.

Compile on macOS:

```bash
mkdir -p build
swiftc native-gate/AgentGuardGate.swift -o build/AgentGuardGate
```

Try an allowed command:

```bash
printf '%s\n' '{"command":"git status","cwd":"/tmp"}' | build/AgentGuardGate --policy examples/policy.json
```

Try a denied command:

```bash
printf '%s\n' '{"command":"rm -rf /tmp/test-folder","cwd":"/tmp"}' | build/AgentGuardGate --policy examples/policy.json
```

The CLI returns exit code 0 for allow and 2 for deny, and it never executes either command.

Run the reference parity checks:

```bash
python3 -m unittest discover -s tests -p test_native_parity.py -v
```

This gate is a deliberately limited command evaluator, not a secure shell interpreter, an OS security boundary, or a replacement for the installed Claude Code hook. The lexical policy can be bypassed in adversarial environments. Swift and Python parity is tested on a representative set, not all possible commands or Unicode and shell edge cases.

The next milestone is a controlled hook integration that compares native and Python decisions in shadow mode before any enforcement handover. Code signing and notarization have not been completed.
