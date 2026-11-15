import fnmatch
import json
import pathlib
import shlex

DEFAULT_POLICY = pathlib.Path(__file__).resolve().parent.parent / "examples" / "policy.json"


def load_policy(path=DEFAULT_POLICY):
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data.get("rules"), list):
        raise ValueError("policy must contain rules")
    return data


def evaluate(action, policy):
    command = action.get("command", "")
    cwd = action.get("cwd", "")
    if not isinstance(command, str) or not isinstance(cwd, str):
        return {"verdict": "deny", "rule_id": "invalid_input", "reason": "Invalid action format"}
    try:
        arguments = shlex.split(command)
    except ValueError:
        return {"verdict": "deny", "rule_id": "parse_error", "reason": "Could not parse command"}
    if not arguments:
        return {"verdict": "deny", "rule_id": "empty_command", "reason": "Empty command"}
    if any(token in command for token in (";", "&&", "||", "|", "`", "$(", "<( ", ">(", "\n", "\r", ">", "<", "&")):
        return {"verdict": "deny", "rule_id": "shell_syntax", "reason": "Compound commands, redirection, and substitution are not supported"}
    executable = pathlib.PurePosixPath(arguments[0]).name
    for rule in policy["rules"]:
        if executable not in rule.get("executables", []):
            continue
        patterns = rule.get("argument_patterns", [])
        if patterns and not any(fnmatch.fnmatch(argument, pattern) for argument in arguments[1:] for pattern in patterns):
            continue
        if rule.get("cwd_patterns") and not any(fnmatch.fnmatch(cwd, pattern) for pattern in rule["cwd_patterns"]):
            continue
        return {"verdict": rule["verdict"], "rule_id": rule["id"], "reason": rule["reason"]}
    return {"verdict": policy.get("default_verdict", "deny"), "rule_id": "default", "reason": "No matching policy rule"}
