# Native Machine Health dashboard

The macOS application includes two tabs: Decision Receipts and Machine Health.

The Machine Health tab reads an exported JSON report from the Python posture checker. It does not launch Python, change policy settings, or perform security enforcement.

From the repository root, export a current report:

```bash
python3 -m guard.posture > /tmp/mac-agent-health.json
```

If you have authenticated receipts and want HMAC verification, provide the matching key through `GUARD_RECEIPT_KEY` in your local shell, without checking it into source control.

Open the Xcode project in `MacAgentSecurityGuard/MacAgentSecurityGuard.xcodeproj`, select My Mac, and run the application. Choose the Machine Health tab, select Open Health Report, and use Command-Shift-G to open `/tmp/mac-agent-health.json`.

The tab displays the real policy rule list, hook registration status, receipt verification counts, overall report status, and limitations. It reads the selected report snapshot and refreshes it when requested. To update machine data, regenerate the report in Terminal and press Refresh.

Run the native tests on your Mac with Xcode's Product > Test command. The Python tests can be run with:

```bash
python3 -m unittest discover -s tests -v
```

A healthy status means the read-only configuration and receipt checks succeeded, not that macOS prevents bypassing the hook. The current app is a local engineering prototype, not a notarized endpoint security agent.
