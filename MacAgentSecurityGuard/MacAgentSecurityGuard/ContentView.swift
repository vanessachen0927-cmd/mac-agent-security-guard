import SwiftUI
import CryptoKit
import UniformTypeIdentifiers

struct SecurityReceipt: Identifiable, Decodable {
    struct Action: Decodable {
        let command: String
        let cwd: String?
    }

    struct Decision: Decodable {
        let reason: String
        let rule_id: String
        let verdict: String
    }

    let action: Action
    let decision: Decision
    let sha256: String
    let hmac_sha256: String?
    let timestamp: String

    var id: String { sha256 + timestamp }
}

struct VerifiedReceipt: Identifiable {
    let line: Int
    let receipt: SecurityReceipt?
    let status: String
    let detail: String

    var id: Int { line }
}

enum ReceiptVerifier {
    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func bytes(from hex: String) -> Data? {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        var position = hex.startIndex
        while position < hex.endIndex {
            let next = hex.index(position, offsetBy: 2)
            guard let byte = UInt8(hex[position..<next], radix: 16) else { return nil }
            result.append(byte)
            position = next
        }
        return result
    }

    static func verify(_ line: String, number: Int, key: String) -> VerifiedReceipt {
        guard let data = line.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return VerifiedReceipt(line: number, receipt: nil, status: "INVALID", detail: "Malformed JSON")
        }

        let receipt = try? JSONDecoder().decode(SecurityReceipt.self, from: data)
        guard let receipt else {
            return VerifiedReceipt(line: number, receipt: nil, status: "INVALID", detail: "Missing or malformed receipt fields")
        }

        let keys = Set(object.keys)
        guard keys == Set(["action", "decision", "timestamp", "sha256"]) ||
              keys == Set(["action", "decision", "timestamp", "sha256", "hmac_sha256"]) else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "INVALID", detail: "Unexpected receipt fields")
        }

        guard let action = object["action"] as? [String: Any],
              let decision = object["decision"] as? [String: Any],
              let timestamp = object["timestamp"] as? String else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "INVALID", detail: "Invalid receipt body")
        }

        let body: [String: Any] = ["action": action, "decision": decision, "timestamp": timestamp]
        guard let canonical = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes]) else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "INVALID", detail: "Unable to canonicalize receipt")
        }

        let digest = hex(Data(SHA256.hash(data: canonical)))
        guard digest == receipt.sha256 else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "INVALID", detail: "SHA-256 digest mismatch")
        }

        guard let signature = receipt.hmac_sha256 else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "DIGEST ONLY", detail: "Digest matches; receipt is not authenticated")
        }

        guard !key.isEmpty else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "KEY REQUIRED", detail: "Digest matches; enter an HMAC key to authenticate")
        }

        guard let signatureData = bytes(from: signature) else {
            return VerifiedReceipt(line: number, receipt: receipt, status: "INVALID", detail: "Invalid HMAC encoding")
        }

        let secret = SymmetricKey(data: Data(key.utf8))
        let valid = HMAC<SHA256>.isValidAuthenticationCode(signatureData, authenticating: canonical, using: secret)
        return VerifiedReceipt(line: number, receipt: receipt, status: valid ? "AUTHENTICATED" : "INVALID", detail: valid ? "SHA-256 and HMAC verified" : "HMAC authentication failed")
    }
}

struct ContentView: View {
    @State private var entries: [VerifiedReceipt] = []
    @State private var selectedFile: URL?
    @State private var showingFilePicker = false
    @State private var errorMessage: String?
    @State private var hmacKey = ""

    private var allowedCount: Int {
        entries.filter { $0.receipt?.decision.verdict == "allow" }.count
    }

    private var deniedCount: Int {
        entries.filter { $0.receipt?.decision.verdict == "deny" }.count
    }

    private var invalidCount: Int {
        entries.filter { $0.status == "INVALID" }.count
    }

    private var authenticatedCount: Int {
        entries.filter { $0.status == "AUTHENTICATED" }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundStyle(.blue)

                VStack(alignment: .leading) {
                    Text("Mac Agent Security Guard")
                        .font(.title.bold())
                    Text("Local AI Agent Security Verification")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Open Receipt Log") { showingFilePicker = true }
                Button("Refresh") { loadReceipts() }
                    .disabled(selectedFile == nil)
            }

            HStack(spacing: 12) {
                metricCard("Decisions", entries.count, "list.bullet.rectangle")
                metricCard("Allowed", allowedCount, "checkmark.shield")
                metricCard("Blocked", deniedCount, "xmark.shield")
                metricCard("Authenticated", authenticatedCount, "lock.shield")
                metricCard("Invalid", invalidCount, "exclamationmark.shield")
            }

            HStack {
                SecureField("Optional HMAC verification key", text: $hmacKey)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 330)
                    .onSubmit { loadReceipts() }
                Button("Verify Again") { loadReceipts() }
                    .disabled(selectedFile == nil)
                Spacer()
                Text("Keys stay in app memory")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text("Security Decision History")
                .font(.headline)

            if entries.isEmpty {
                ContentUnavailableView("No Receipts Loaded", systemImage: "doc.text.magnifyingglass", description: Text("Open receipts.jsonl to inspect decisions and integrity."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(entries.reversed()) { entry in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: entry.status == "INVALID" ? "exclamationmark.triangle.fill" : entry.receipt?.decision.verdict == "deny" ? "xmark.shield.fill" : "checkmark.shield.fill")
                            .foregroundStyle(entry.status == "INVALID" ? .orange : entry.receipt?.decision.verdict == "deny" ? .red : .green)

                        VStack(alignment: .leading, spacing: 5) {
                            Text(entry.receipt?.action.command ?? "Malformed receipt at line \(entry.line)")
                                .font(.system(.body, design: .monospaced))
                            Text(entry.receipt?.decision.reason ?? entry.detail)
                                .foregroundStyle(.secondary)
                            Text("Line \(entry.line) · Rule: \(entry.receipt?.decision.rule_id ?? "unknown")")
                                .font(.caption)
                            Text(entry.detail)
                                .font(.caption)
                                .foregroundStyle(entry.status == "INVALID" ? .red : .secondary)
                        }

                        Spacer()

                        VStack(alignment: .trailing, spacing: 5) {
                            Text(entry.receipt?.decision.verdict.uppercased() ?? "UNKNOWN")
                                .font(.caption.bold())
                            Text(entry.status)
                                .font(.caption.bold())
                                .foregroundStyle(entry.status == "INVALID" ? .red : entry.status == "AUTHENTICATED" ? .green : .orange)
                        }
                    }
                    .padding(.vertical, 5)
                }
            }

            if let errorMessage {
                Text(errorMessage).foregroundStyle(.red).font(.caption)
            }
        }
        .padding(24)
        .frame(minWidth: 1000, minHeight: 570)
        .fileImporter(isPresented: $showingFilePicker, allowedContentTypes: [.json, .plainText, .data]) { result in
            switch result {
            case .success(let url):
                selectedFile = url
                loadReceipts()
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }

    private func metricCard(_ title: String, _ value: Int, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol)
                .foregroundStyle(.secondary)
            Text("\(value)").font(.system(size: 30, weight: .bold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
    }

    private func loadReceipts() {
        guard let selectedFile else { return }
        let accessGranted = selectedFile.startAccessingSecurityScopedResource()
        defer {
            if accessGranted { selectedFile.stopAccessingSecurityScopedResource() }
        }

        do {
            let contents = try String(contentsOf: selectedFile, encoding: .utf8)
            entries = contents
                .split(whereSeparator: \.isNewline)
                .enumerated()
                .map { index, line in ReceiptVerifier.verify(String(line), number: index + 1, key: hmacKey) }
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

#Preview {
    ContentView()
}
