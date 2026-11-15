import SwiftUI

struct GuardReceipt: Decodable, Identifiable {
    let action: GuardAction
    let decision: GuardDecision
    let timestamp: String
    let sha256: String
    var id: String { sha256 }
}

struct GuardAction: Decodable {
    let command: String
    let cwd: String
}

struct GuardDecision: Decodable {
    let verdict: String
    let rule_id: String
    let reason: String
}

@main
struct AgentGuardApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var receipts: [GuardReceipt] = []
    @State private var message = "Select a JSONL receipt log to inspect local policy decisions."

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Mac Agent Security Guard").font(.title).bold()
            Text("Local deterministic policy receipts").foregroundStyle(.secondary)
            Button("Open Receipt Log") { openLog() }
            Text(message).font(.caption)
            List(receipts) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(entry.decision.verdict.uppercased()).bold()
                            .foregroundStyle(entry.decision.verdict == "allow" ? .green : .red)
                        Spacer()
                        Text(entry.timestamp).font(.caption)
                    }
                    Text(entry.action.command).font(.system(.body, design: .monospaced))
                    Text("\(entry.decision.rule_id): \(entry.decision.reason)").font(.caption)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 420)
    }

    private func openLog() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json, .plainText]
        if panel.runModal() == .OK, let url = panel.url {
            do {
                let content = try String(contentsOf: url, encoding: .utf8)
                receipts = content.split(separator: "\n").compactMap {
                    try? JSONDecoder().decode(GuardReceipt.self, from: Data($0.utf8))
                }
                message = "Loaded \(receipts.count) receipt(s)"
            } catch {
                message = "Unable to read selected file: \(error.localizedDescription)"
            }
        }
    }
}
