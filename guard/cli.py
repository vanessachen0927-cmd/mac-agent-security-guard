import argparse
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import sys
from .policy import evaluate, load_policy


def receipt(action, decision, key):
    body = {"action": action, "decision": decision, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["sha256"] = hashlib.sha256(canonical).hexdigest()
    if key:
        body["hmac_sha256"] = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    return body


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=None)
    parser.add_argument("--command", required=True)
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("--log", default="receipts.jsonl")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy) if args.policy else load_policy()
        action = {"command": args.command, "cwd": args.cwd}
        result = evaluate(action, policy)
        record = receipt(action, result, os.getenv("GUARD_RECEIPT_KEY"))
        with open(pathlib.Path(args.log), "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        print(json.dumps(record, sort_keys=True))
        return 0 if result["verdict"] == "allow" else 2
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"verdict": "deny", "error": str(error)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
