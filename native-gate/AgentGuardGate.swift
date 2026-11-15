import Foundation

struct GateError: Error {}

func tokenize(_ command: String) throws -> [String] {
    var arguments: [String] = []
    var current = ""
    var quote: Character?
    var escaping = false
    var active = false
    for character in command {
        if escaping {
            current.append(character)
            escaping = false
            active = true
            continue
        }
        if character == "\\" && quote != "'" {
            escaping = true
            active = true
            continue
        }
        if let delimiter = quote {
            if character == delimiter {
                quote = nil
            } else {
                current.append(character)
            }
            continue
        }
        if character == "'" || character == "\"" {
            quote = character
            active = true
        } else if character.isWhitespace {
            if active {
                arguments.append(current)
                current = ""
                active = false
            }
        } else {
            current.append(character)
            active = true
        }
    }
    if escaping || quote != nil { throw GateError() }
    if active { arguments.append(current) }
    return arguments
}

func wildcardMatch(_ value: String, pattern: String) -> Bool {
    var expression = "^"
    for char in pattern {
        if char == "*" { expression += ".*" }
        else if char == "?" { expression += "." }
        else { expression += NSRegularExpression.escapedPattern(for: String(char)) }
    }
    expression += "$"
    return value.range(of: expression, options: .regularExpression) != nil
}

func decision(_ verdict: String, _ rule: String, _ reason: String) -> [String: String] {
    ["verdict": verdict, "rule_id": rule, "reason": reason]
}

func evaluate(_ action: [String: Any], _ policy: [String: Any]) -> [String: String] {
    guard let command = action["command"] as? String,
          let cwd = action["cwd"] as? String else {
        return decision("deny", "invalid_input", "Invalid action format")
    }
    let args: [String]
    do { args = try tokenize(command) }
    catch { return decision("deny", "parse_error", "Could not parse command") }
    if args.isEmpty { return decision("deny", "empty_command", "Empty command") }
    let unsafe = [";", "&&", "||", "|", "`", "$(", "<( ", ">(", "\n", "\r", ">", "<", "&"]
    if unsafe.contains(where: { command.contains($0) }) {
        return decision("deny", "shell_syntax", "Compound commands, redirection, and substitution are not supported")
    }
    let executable = String(args[0].split(separator: "/").last ?? Substring(args[0]))
    guard let rules = policy["rules"] as? [[String: Any]] else {
        return decision("deny", "invalid_policy", "Invalid policy")
    }
    for rule in rules {
        guard let executables = rule["executables"] as? [String], executables.contains(executable) else { continue }
        if let patterns = rule["argument_patterns"] as? [String], !patterns.isEmpty {
            let matches = args.dropFirst().contains { argument in patterns.contains { wildcardMatch(argument, pattern: $0) } }
            if !matches { continue }
        }
        if let patterns = rule["cwd_patterns"] as? [String], !patterns.isEmpty {
            if !patterns.contains(where: { wildcardMatch(cwd, pattern: $0) }) { continue }
        }
        guard let verdict = rule["verdict"] as? String,
              let identifier = rule["id"] as? String,
              let reason = rule["reason"] as? String else {
            return decision("deny", "invalid_policy", "Invalid policy")
        }
        return decision(verdict, identifier, reason)
    }
    return decision(policy["default_verdict"] as? String ?? "deny", "default", "No matching policy rule")
}

func main() -> Int32 {
    let args = CommandLine.arguments
    guard args.count == 3, args[1] == "--policy" else {
        fputs("Usage: AgentGuardGate --policy path/to/policy.json\n", stderr)
        return 2
    }
    do {
        guard let input = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as? [String: Any],
              let policy = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: args[2]))) as? [String: Any] else {
            throw GateError()
        }
        let result = evaluate(input, policy)
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
        return result["verdict"] == "allow" ? 0 : 2
    } catch {
        let fallback = decision("deny", "invalid_input", "Invalid action or policy")
        if let data = try? JSONSerialization.data(withJSONObject: fallback, options: [.sortedKeys]) {
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data([10]))
        }
        return 2
    }
}

exit(main())
