import hashlib
import json
import pathlib
import subprocess
from datetime import datetime, timezone


def compare_native(action, python_decision, executable, policy_path, timeout=2):
    if not isinstance(action.get("command"), str) or not isinstance(action.get("cwd"), str):
        return {"status": "skipped", "reason": "Malformed action"}
    try:
        result = subprocess.run(
            [str(pathlib.Path(executable).expanduser().resolve()), "--policy", str(policy_path)],
            input=json.dumps(action),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        if result.returncode not in (0, 2):
            raise ValueError("Unexpected native exit code")
        native = json.loads(result.stdout)
        if not isinstance(native, dict) or set(native) != {"verdict", "rule_id", "reason"}:
            raise ValueError("Unexpected native decision format")
        if native["verdict"] not in ("allow", "deny"):
            raise ValueError("Unexpected native verdict")
        if result.returncode != (0 if native["verdict"] == "allow" else 2):
            raise ValueError("Native exit code contradicts verdict")
        status = "match" if native == python_decision else "mismatch"
        return {
            "status": status,
            "python_decision": python_decision,
            "native_decision": native
        }
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        return {"status": "error", "reason": type(error).__name__}


def shadow_record(action, comparison):
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_sha256": hashlib.sha256(canonical).hexdigest(),
        **comparison
    }
