import Foundation
import XCTest
@testable import GrantdKit

@MainActor
final class ActivityViewModelTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func entry(_ id: Int, decision: String, reason: String = "", caller: String = "claude-code", argv: [String] = ["ls"],
               secrets: [String] = ["S"], exit: Int? = nil, ms: Int64 = 0, grant: String = "", at: Double? = nil) -> AuditEntry {
        AuditEntry(id: String(id), ts: t0.addingTimeInterval(at ?? Double(id)), caller: caller, cwd: "/p", argv: argv, secrets: secrets,
                   decision: decision, grantID: grant, exitCode: exit, durationMS: ms, reason: reason)
    }

    /// Newest first, like the daemon.
    func log(_ rows: [AuditEntry]) -> FakeActivity {
        let f = FakeActivity()
        f.rows = rows.sorted { Int($0.id)! > Int($1.id)! }
        return f
    }

    func model(_ f: FakeActivity, now: Double = 100) -> ActivityViewModel {
        let m = ActivityViewModel(service: f, now: { self.t0.addingTimeInterval(now) })
        m.connectionChanged(.ready(readyStatus))
        return m
    }

    func testPairsARunIntoOneRowWithExitCodeAndDuration() async {
        let f = log([
            entry(1, decision: "allowed_once", reason: "released", argv: ["php", "artisan"], secrets: ["DB_URL"]),
            entry(2, decision: "completed", argv: ["php", "artisan"], secrets: ["DB_URL"], exit: 0, ms: 1234),
            entry(3, decision: "denied_user", argv: ["rm"], secrets: ["KEY"]),
            entry(4, decision: "refused_policy", argv: ["curl"], secrets: ["KEY"]),
            entry(5, decision: "allowed_once", reason: "set", argv: ["grantd", "set", "NEW"], secrets: ["NEW"], at: 5),
        ])
        let m = model(f)
        await m.refresh()
        XCTAssertEqual(m.events.count, 4, "released + completed is one event")
        let run = m.events.first { $0.kind == .run }!
        XCTAssertEqual(run.resultText, "Exit 0 · 1.2 s")
        XCTAssertEqual(run.tone, .succeeded)
        XCTAssertEqual(run.rowIDs, ["1", "2"])
        let denied = m.events.first { $0.decision == "denied_user" }!
        XCTAssertEqual(denied.tone, .denied)
        XCTAssertEqual(denied.resultText, "Denied")
        let blocked = m.events.first { $0.decision == "refused_policy" }!
        XCTAssertEqual(blocked.tone, .blocked)
        XCTAssertEqual(blocked.resultText, "Blocked")
        XCTAssertEqual(blocked.title, "Blocked by .grantd.yml")
    }

    func testAFailedRunAndAMissingResult() async {
        let f = log([
            entry(1, decision: "allowed_once", reason: "released", argv: ["a"]),
            entry(2, decision: "completed", argv: ["a"], exit: 3, ms: 50),
            entry(3, decision: "allowed_once", reason: "released", argv: ["b"], at: 3),
            entry(4, decision: "allowed_once", reason: "released", argv: ["c"], at: 99_000),
        ])
        let m = model(f, now: 100_000)
        await m.refresh()
        let byCmd = Dictionary(uniqueKeysWithValues: m.events.map { ($0.command, $0) })
        XCTAssertEqual(byCmd["a"]?.tone, .failed)
        XCTAssertEqual(byCmd["a"]?.resultText, "Exit 3 · 50 ms")
        XCTAssertEqual(byCmd["b"]?.resultText, "No result recorded")
        XCTAssertEqual(byCmd["b"]?.tone, .failed)
        XCTAssertEqual(byCmd["c"]?.resultText, "Running…")
    }

    func testFilters() async {
        let f = log([
            entry(1, decision: "allowed_once", reason: "released", argv: ["ls"]),
            entry(2, decision: "completed", argv: ["ls"], exit: 0),
            entry(3, decision: "denied_user", argv: ["rm"]),
            entry(4, decision: "refused_tier", argv: ["x"]),
            entry(5, decision: "error", reason: "boom", argv: ["y"]),
            entry(6, decision: "allowed_once", reason: "delete", argv: ["grantd", "delete", "OLD"], secrets: ["OLD"]),
            entry(7, decision: "allowed_new_grant", reason: "standing", argv: ["php"]),
        ])
        let m = model(f)
        await m.refresh()
        m.filter = .all
        XCTAssertEqual(m.visibleEvents.count, 6)
        m.filter = .runs
        XCTAssertEqual(m.visibleEvents.map(\.kind), [.run])
        m.filter = .denied
        XCTAssertEqual(Set(m.visibleEvents.map(\.decision)), ["denied_user", "refused_tier", "error"])
        m.filter = .changes
        XCTAssertEqual(Set(m.visibleEvents.map(\.kind)), [.change, .standingGrant])
        XCTAssertEqual(ActivityFilter.allCases.map(\.title), ["All", "Runs", "Denied or blocked", "Changes"])
    }

    func testSearchByCommandCallerAndSecret() async {
        let f = log([
            entry(1, decision: "denied_user", caller: "cursor", argv: ["curl", "example.com"], secrets: ["API_KEY"]),
            entry(2, decision: "denied_user", caller: "claude-code", argv: ["ls"], secrets: ["DB_URL"]),
        ])
        let m = model(f)
        await m.refresh()
        m.searchText = "CURL"
        XCTAssertEqual(m.visibleEvents.map(\.id), ["1"])
        m.searchText = "claude"
        XCTAssertEqual(m.visibleEvents.map(\.id), ["2"])
        m.searchText = "db_url"
        XCTAssertEqual(m.visibleEvents.map(\.id), ["2"])
        m.searchText = "nothing"
        XCTAssertTrue(m.visibleEvents.isEmpty)
        m.searchText = "  "
        XCTAssertEqual(m.visibleEvents.count, 2)
    }

    func testLoadMoreAsksForMoreRowsUpToTheMaximum() async {
        let f = log((1...450).map { entry($0, decision: "denied_user") })
        let m = model(f)
        await m.refresh()
        XCTAssertEqual(m.entries.count, 200)
        XCTAssertTrue(m.canLoadMore)
        XCTAssertEqual(f.limits.last!, 200)
        await m.loadMore()
        XCTAssertEqual(m.entries.count, 400)
        await m.loadMore()
        XCTAssertEqual(m.entries.count, 450)
        XCTAssertFalse(m.canLoadMore, "fewer rows than asked for: the log is loaded to its start")
        XCTAssertNil(m.footer)
        XCTAssertTrue(m.windowIsComplete)
    }

    func testTheDaemonMaximumPointsToTheExport() async {
        let f = log((1...1500).map { entry($0, decision: "denied_user") })
        let m = model(f)
        await m.refresh()
        for _ in 0..<4 { await m.loadMore() }
        XCTAssertEqual(m.entries.count, 1000)
        XCTAssertEqual(f.limits.last!, 1000)
        XCTAssertFalse(m.canLoadMore)
        XCTAssertEqual(m.footer, "Older entries are only in the CSV export.")
    }

    func testTruncatedMeansLoadMoreCannotHelp() async {
        let f = log((1...300).map { entry($0, decision: "denied_user") })
        f.truncateAt = 120
        let m = model(f)
        await m.refresh()
        XCTAssertTrue(m.truncated)
        XCTAssertEqual(m.entries.count, 120)
        XCTAssertFalse(m.canLoadMore, "a bigger limit cannot return more than fits in one line")
        XCTAssertEqual(m.footer, "Some older entries did not fit in one page. Export CSV to read them all.")
        XCTAssertFalse(m.windowIsComplete)
    }

    func testRefreshKeepsWhatIsLoaded() async {
        let f = log((1...450).map { entry($0, decision: "denied_user") })
        let m = model(f)
        await m.refresh()
        await m.loadMore()
        await m.refresh()
        XCTAssertEqual(f.limits.last!, 400)
        XCTAssertEqual(m.entries.count, 400)
    }

    func testAResultOutsideTheWindowIsNeutral() async {
        // 250 rows, the completed row of a run whose start is older than the window
        var rows = (1...249).map { entry($0 + 10, decision: "denied_user") }
        rows.append(entry(300, decision: "completed", argv: ["old"], exit: 0, ms: 5))
        let f = log(rows)
        let m = model(f)
        await m.refresh()
        let e = m.events.first { $0.kind == .resultOnly }
        XCTAssertEqual(e?.resultText, "…")
    }

    func testEmptyLog() async {
        let m = model(FakeActivity())
        XCTAssertFalse(m.isEmpty)
        await m.refresh()
        XCTAssertTrue(m.isEmpty)
        XCTAssertNil(m.footer)
    }

    func testDetailPaneHasTheFullCommandAndRows() async {
        let long = String(repeating: "x", count: 9000)
        var released = entry(1, decision: "allowed_grant", reason: "released", argv: ["sh", "-c", long, "a\u{202E}b"], secrets: ["aws/*"], grant: "G1")
        released.expanded = ["aws/key", "aws/secret"]
        let f = log([released, entry(2, decision: "completed", argv: ["sh", "-c", long, "a\u{202E}b"], secrets: ["aws/*"], exit: 2, ms: 2500, grant: "G1")])
        let m = model(f)
        await m.refresh()
        let d = m.detail(for: m.events[0].id)!
        XCTAssertEqual(d.title, "Used a grant")
        XCTAssertEqual(d.cwd, "/p")
        XCTAssertEqual(d.secretsRequested, "aws/*")
        XCTAssertEqual(d.secretsExpanded, "aws/key, aws/secret")
        XCTAssertEqual(d.grantID, "G1")
        XCTAssertEqual(d.result, "Exit 2 · 2.5 s")
        XCTAssertEqual(d.rowIDs, ["1", "2"])
        XCTAssertLessThanOrEqual(d.command.count, DisplayText.detailLimit)
        XCTAssertTrue(d.command.contains("…"))
        XCTAssertFalse(d.command.unicodeScalars.contains { $0.value == 0x202E })
        XCTAssertNil(m.detail(for: "nope"))
    }

    func testHostileTextNeverReachesTheTable() async {
        let f = log([entry(1, decision: "denied_user", caller: "a\u{202E}\u{1B}[31mevil", argv: ["x\u{0}y", String(repeating: "z", count: 5000)])])
        let m = model(f)
        await m.refresh()
        let e = m.events[0]
        for text in [e.caller, e.command, e.summary] {
            XCTAssertFalse(text.unicodeScalars.contains { $0.value == 0x202E || $0.value == 0x1B || $0.value == 0 })
            XCTAssertLessThanOrEqual(text.count, 400)
        }
    }

    // MARK: verify

    func testVerifyOK() async {
        let f = FakeActivity()
        f.verifyResult = FakeActivity.verified(12)
        let m = model(f)
        await m.verifyLog()
        XCTAssertEqual(m.verify, .ok(entries: 12))
        XCTAssertEqual(ActivityViewModel.verifiedText(entries: 12), "Log verified: 12 entries, chain intact.")
        XCTAssertEqual(ActivityViewModel.verifiedText(entries: 1), "Log verified: 1 entry, chain intact.")
        XCTAssertEqual(ActivityViewModel.verifiedCaption, "This detects edits and removals in the middle of the log. It cannot detect the newest entries being deleted.")
        m.dismissVerify()
        XCTAssertEqual(m.verify, .idle)
    }

    func testVerifyBroken() async {
        let f = FakeActivity()
        f.verifyResult = FakeActivity.broken(at: "42")
        let m = model(f)
        await m.verifyLog()
        XCTAssertEqual(m.verify, .broken(firstBadID: "42"))
        XCTAssertEqual(ActivityViewModel.brokenText(firstBadID: "42"),
                       "Log check failed at entry 42. Entries from there on can't be trusted. Someone may have edited the vault file. Export a copy now.")
    }

    func testVerifyFailureUsesTheNormalMapping() async {
        let f = FakeActivity()
        f.verifyFailure = GrantdError.timeout
        let m = model(f)
        await m.verifyLog()
        guard case .failed(let msg) = m.verify else { return XCTFail("\(m.verify)") }
        XCTAssertEqual(msg.headline, "grantd took too long to answer.")
    }

    // MARK: export

    func testExportReturnsTheCSVExactlyAsReceived() async {
        let f = FakeActivity()
        f.exportResult = "id,ts\r\n1,=cmd|' /C calc'!A0\r\n"
        let m = model(f)
        let out = await m.exportCSV()
        guard case .csv(let text, let name) = out else { return XCTFail("\(out)") }
        XCTAssertEqual(text, f.exportResult, "cells are not rewritten")
        XCTAssertTrue(name.hasPrefix("grantd-audit-") && name.hasSuffix(".csv"), name)
    }

    func testExportFileName() {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        XCTAssertEqual(ActivityViewModel.exportFileName(date: Date(timeIntervalSince1970: 1_792_000_000), calendar: cal), "grantd-audit-2026-10-14.csv")
    }

    func testExportTooLarge() async {
        let f = FakeActivity()
        f.exportFailure = daemonError(.failed, .responseTooLarge, "audit log too large to export over the socket")
        let m = model(f)
        let out = await m.exportCSV()
        XCTAssertEqual(out, .failed(UserMessage("The log is over 1 MB and can't be exported in one piece yet. Use Load more and copy what you need.")))
        XCTAssertFalse(m.isExporting)
    }

    func testExportOtherFailure() async {
        let f = FakeActivity()
        f.exportFailure = GrantdError.notRunning
        let out = await model(f).exportCSV()
        guard case .failed(let msg) = out else { return XCTFail("\(out)") }
        XCTAssertEqual(msg.headline, "grantd is not running.")
    }

    func testDisabledReasons() {
        let m = ActivityViewModel(service: FakeActivity())
        XCTAssertEqual(m.disabledReason, "Checking grantd…")
        m.connectionChanged(.notRunning)
        XCTAssertNotNil(m.disabledReason)
        m.connectionChanged(.ready(readyStatus))
        XCTAssertNil(m.disabledReason)
    }
}
