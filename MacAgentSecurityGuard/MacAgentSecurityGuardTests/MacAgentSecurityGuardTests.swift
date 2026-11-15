import Foundation
import Testing
@testable import MacAgentSecurityGuard

struct MacAgentSecurityGuardTests {
    private func sample(status: String = "warning") -> Data {
        let value: [String: Any] = [
            "schema_version": 1,
            "generated_at": "2026-11-15T01:38:56+00:00",
            "scope": "local_project",
            "status": status,
            "checks": [
                "policy": ["status": "healthy", "rule_count": 1, "rules": [["id": "deny_delete", "verdict": "deny"]]],
                "hook": ["status": "healthy", "scope": "project-local"],
                "receipts": ["status": "warning", "counts": ["authenticated": 0, "digest_only": 2, "key_required": 0, "invalid": 0]]
            ],
            "limitations": ["Configuration reporting only"]
        ]
        return try! JSONSerialization.data(withJSONObject: value)
    }

    @Test func parsesReport() throws {
        let report = try PostureReportParser.parse(sample())
        #expect(report.status == "warning")
        #expect(report.checks["policy"]?.rule_count == 1)
        #expect(report.checks["receipts"]?.counts?["digest_only"] == 2)
    }

    @Test func rejectsUnsupportedSchema() throws {
        var value = try #require(JSONSerialization.jsonObject(with: sample()) as? [String: Any])
        value["schema_version"] = 2
        let data = try JSONSerialization.data(withJSONObject: value)
        #expect(throws: PostureError.self) {
            try PostureReportParser.parse(data)
        }
    }

    @Test func rejectsMissingChecks() throws {
        var value = try #require(JSONSerialization.jsonObject(with: sample()) as? [String: Any])
        value["checks"] = ["policy": ["status": "healthy"]]
        let data = try JSONSerialization.data(withJSONObject: value)
        #expect(throws: PostureError.self) {
            try PostureReportParser.parse(data)
        }
    }

    @Test func rejectsUnexpectedOverallStatus() throws {
        #expect(throws: PostureError.self) {
            try PostureReportParser.parse(sample(status: "secure"))
        }
    }

    @Test func rejectsMalformedJSON() throws {
        let data = Data("{not valid}".utf8)
        #expect(throws: DecodingError.self) {
            try PostureReportParser.parse(data)
        }
    }
}
