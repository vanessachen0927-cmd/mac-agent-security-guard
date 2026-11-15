import argparse
import json
import os
import pathlib
import shlex
import sys
from datetime import datetime, timezone

from guard.policy import load_policy
from guard.verify import verify_file


def check_policy(path):
    try:
        policy = load_policy(path)
        rules = policy["rules"]
        identifiers = [rule["id"] for rule in rules]
        if not rules or len(identifiers) != len(set(identifiers)):
            raise ValueError("Policy has no rules or duplicate identifiers")
        for rule in rules:
            if not isinstance(rule.get("executables"), list) or rule.get("verdict") not in ("allow", "deny"):
                raise ValueError("Invalid rule definition")
        if policy.get("default_verdict") != "deny":
            return {"status": "warning", "rule_count": len(rules), "reason": "Default verdict is not deny"}
        return {"status": "healthy", "rule_count": len(rules), "rules": [{"id": rule["id"], "verdict": rule["verdict"]} for rule in rules]}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        return {"status": "failed", "reason": type(error).__name__ + ": " + str(error)}


def check_hook(path, expected_script):
    try:
        settings = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        candidates = settings.get("hooks", {}).get("PreToolUse", [])
        for candidate in candidates:
            if not isinstance(candidate, dict) or candidate.get("matcher") != "Bash":
                continue
            for hook in candidate.get("hooks", []):
                if not isinstance(hook, dict) or hook.get("type") != "command":
                    continue
                try:
                    arguments = shlex.split(hook.get("command", ""))
                except ValueError:
                    continue
                if len(arguments) >= 2 and pathlib.Path(arguments[1]).resolve() == pathlib.Path(expected_script).resolve():
                    return {"status": "healthy", "scope": "project-local", "reason": "Matching Bash PreToolUse hook is configured"}
        return {"status": "failed", "reason": "Expected Bash PreToolUse hook not found"}
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as error:
        return {"status": "failed", "reason": type(error).__name__ + ": " + str(error)}


def check_receipts(path, key):
    try:
        rows = verify_file(path, key)
        counts = {status: sum(row["status"] == status for row in rows) for status in ("authenticated", "digest_only", "key_required", "invalid")}
        if not rows:
            return {"status": "warning", "reason": "No receipts found", "counts": counts}
        if counts["invalid"]:
            return {"status": "failed", "reason": "Invalid receipts detected", "counts": counts}
        if counts["digest_only"] or counts["key_required"]:
            return {"status": "warning", "reason": "Some receipts are not authenticated", "counts": counts}
        return {"status": "healthy", "counts": counts}
    except (OSError, UnicodeError, ValueError) as error:
        return {"status": "failed", "reason": type(error).__name__ + ": " + str(error)}


def build_report(root, receipt_path, key=None):
    root = pathlib.Path(root).resolve()
    checks = {
        "policy": check_policy(root / "examples" / "policy.json"),
        "hook": check_hook(root / ".claude" / "settings.local.json", root / "guard" / "hook.py"),
        "receipts": check_receipts(receipt_path, key)
    }
    statuses = [item["status"] for item in checks.values()]
    status = "failed" if "failed" in statuses else "warning" if "warning" in statuses else "healthy"
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "local_project",
        "status": status,
        "checks": checks,
        "limitations": ["Reports configuration and receipt validity only", "Does not prove a hook ran or prevent hook bypass", "Does not establish system-wide enforcement"]
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    parser.add_argument("--receipts", default="~/.mac-agent-security-guard/receipts.jsonl")
    parser.add_argument("--key-env", default="GUARD_RECEIPT_KEY")
    args = parser.parse_args(argv)
    report = build_report(args.root, pathlib.Path(args.receipts).expanduser(), os.getenv(args.key_env))
    print(json.dumps(report, indent=2))
    return 2 if report["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
