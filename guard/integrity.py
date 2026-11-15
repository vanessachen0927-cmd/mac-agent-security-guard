import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def inspect(path, expected_sha256=None, require_developer_id=False):
    target = pathlib.Path(path).expanduser().resolve()
    report = {"path": str(target), "status": "failed", "checks": {}}
    try:
        checksum = sha256_file(target)
        report["sha256"] = checksum
        if expected_sha256 is not None:
            pinned = bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256))
            report["checks"]["pinned_sha256"] = "pass" if pinned and checksum == expected_sha256.lower() else "fail"
        else:
            report["checks"]["pinned_sha256"] = "not_checked"
        result = subprocess.run(
            ["codesign", "--verify", "--strict", "--verbose=2", str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        report["checks"]["codesign_integrity"] = "pass" if result.returncode == 0 else "fail"
        metadata = subprocess.run(
            ["codesign", "-dv", "--verbose=4", str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        details = metadata.stderr + metadata.stdout
        adhoc = "Signature=adhoc" in details or "flags=0x20002(adhoc" in details
        team = re.search(r"^TeamIdentifier=(.+)$", details, re.MULTILINE)
        report["signature_kind"] = "ad_hoc" if adhoc else "developer_signed_or_other" if metadata.returncode == 0 else "unknown"
        report["team_identifier"] = team.group(1) if team and team.group(1) != "not set" else None
        if require_developer_id:
            authorities = re.findall(r"^Authority=(.+)$", details, re.MULTILINE)
            valid_id = metadata.returncode == 0 and not adhoc and any(
                authority.startswith("Developer ID Application: ") for authority in authorities
            ) and bool(report["team_identifier"])
            report["checks"]["developer_id"] = "pass" if valid_id else "fail"
        else:
            report["checks"]["developer_id"] = "not_required"
        report["status"] = "pass" if all(value not in ("fail",) for value in report["checks"].values()) else "failed"
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--require-developer-id", action="store_true")
    args = parser.parse_args(argv)
    report = inspect(args.executable, args.expected_sha256, args.require_developer_id)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    sys.exit(main())
