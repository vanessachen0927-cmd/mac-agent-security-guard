import SwiftUI
import UniformTypeIdentifiers

struct PostureReport: Decodable {
    struct PolicyRule: Identifiable, Decodable {
        let id: String
        let verdict: String
    }

    struct Check: Decodable {
        let status: String
        let reason: String?
        let rule_count: Int?
        let rules: [PolicyRule]?
        let scope: String?
        let counts: [String: Int]?
    }

    let schema_version: Int
    let generated_at: String
    let scope: String
    let status: String
    let checks: [String: Check]
    let limitations: [String]
}

enum PostureReportParser {
    static func parse(_ data: Data) throws -> PostureReport {
        let report = try JSONDecoder().decode(PostureReport.self, from: data)
        guard report.schema_version == 1,
              report.scope == "local_project",
              ["healthy", "warning", "failed"].contains(report.status),
              Set(report.checks.keys) == Set(["policy", "hook", "receipts"]),
              report.checks.values.allSatisfy({ ["healthy", "warning", "failed"].contains($0.status) }) else {
            throw PostureError.invalidSchema
        }
        return report
    }
}

enum PostureError: LocalizedError {
    case invalidSchema

    var errorDescription: String? {
        "The selected file is not a supported local machine-health report."
    }
}

struct PostureReportView: View {
    @State private var report: PostureReport?
    @State private var sourceURL: URL?
    @State private var showingImporter = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("Machine Health", systemImage: "heart.text.square")
                    .font(.title2.bold())
                Spacer()
                Button("Open Health Report") {
                    showingImporter = true
                }
                Button("Refresh") {
                    loadReport()
                }
                .disabled(sourceURL == nil)
            }

            if let report {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack {
                            Text("Overall status")
                                .font(.headline)
                            Spacer()
                            statusLabel(report.status)
                        }
                        Text("Generated: \(report.generated_at)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Scope: \(report.scope)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        ForEach(["policy", "hook", "receipts"], id: \.self) { name in
                            if let check = report.checks[name] {
                                GroupBox {
                                    VStack(alignment: .leading, spacing: 9) {
                                        HStack {
                                            Text(name.capitalized).font(.headline)
                                            Spacer()
                                            statusLabel(check.status)
                                        }

                                        if let reason = check.reason {
                                            Text(reason).font(.caption)
                                        }
                                        if let count = check.rule_count {
                                            Text("Rules configured: \(count)")
                                        }
                                        if let rules = check.rules {
                                            ForEach(rules) { rule in
                                                HStack {
                                                    Text(rule.id).font(.system(.body, design: .monospaced))
                                                    Spacer()
                                                    Text(rule.verdict.uppercased())
                                                        .foregroundStyle(rule.verdict == "deny" ? .red : .green)
                                                }
                                            }
                                        }
                                        if let counts = check.counts {
                                            ForEach(counts.keys.sorted(), id: \.self) { key in
                                                HStack {
                                                    Text(key.replacingOccurrences(of: "_", with: " ").capitalized)
                                                    Spacer()
                                                    Text("\(counts[key] ?? 0)")
                                                }
                                            }
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        }

                        Text("Report Limitations")
                            .font(.headline)
                        ForEach(report.limitations, id: \.self) { limitation in
                            Label(limitation, systemImage: "info.circle")
                                .font(.caption)
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "No Health Report Loaded",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text("Generate a report using python3 -m guard.posture, then open the JSON file here.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            if let errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .font(.caption)
            }
        }
        .padding(22)
        .frame(minWidth: 750, minHeight: 600)
        .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.json, .plainText, .data]) { result in
            switch result {
            case .success(let url):
                sourceURL = url
                loadReport()
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }

    private func statusLabel(_ status: String) -> some View {
        Label(status.uppercased(), systemImage: status == "healthy" ? "checkmark.shield.fill" : status == "warning" ? "exclamationmark.triangle.fill" : "xmark.shield.fill")
            .foregroundStyle(status == "healthy" ? .green : status == "warning" ? .orange : .red)
    }

    private func loadReport() {
        guard let sourceURL else { return }
        let access = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if access { sourceURL.stopAccessingSecurityScopedResource() }
        }
        do {
            report = try PostureReportParser.parse(Data(contentsOf: sourceURL))
            errorMessage = nil
        } catch {
            report = nil
            errorMessage = error.localizedDescription
        }
    }
}
