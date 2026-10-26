import Foundation
import XCTest
@testable import GrantdKit

final class AuditPairingTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }

    func released(_ id: String, _ s: Double, caller: String = "claude-code", argv: [String] = ["php", "artisan"],
                  secrets: [String] = ["DB_URL"], grant: String = "", decision: String = "allowed_once") -> AuditEntry {
        AuditEntry(id: id, ts: at(s), caller: caller, cwd: "/p", argv: argv, secrets: secrets, decision: decision, grantID: grant, reason: "released")
    }

    func completed(_ id: String, _ s: Double, caller: String = "claude-code", argv: [String] = ["php", "artisan"],
                   secrets: [String] = ["DB_URL"], grant: String = "", exit: Int = 0, ms: Int64 = 1200, reason: String = "") -> AuditEntry {
        AuditEntry(id: id, ts: at(s), caller: caller, cwd: "/p", argv: argv, secrets: secrets, decision: "completed", grantID: grant,
                   exitCode: exit, durationMS: ms, reason: reason)
    }

    /// Rows as `audit list` returns them: newest first.
    func pair(_ oldestFirst: [AuditEntry], complete: Bool = true, now: Double = 10) -> [AuditEvent] {
        AuditPairing.pair(oldestFirst.reversed(), windowIsComplete: complete, now: at(now))
    }

    func testReleasedAndCompletedBecomeOneEvent() {
        let ev = pair([released("1", 0), completed("2", 2)])
        XCTAssertEqual(ev.count, 1)
        XCTAssertEqual(ev[0].title, "Allowed once")
        XCTAssertEqual(ev[0].kind, .run)
        XCTAssertEqual(ev[0].rowIDs, ["1", "2"])
        XCTAssertEqual(ev[0].id, "2")
        XCTAssertEqual(ev[0].time, at(0))
        XCTAssertEqual(ev[0].result, .finished(exitCode: 0, durationMS: 1200))
        XCTAssertEqual(ev[0].summary, "Ran \"php artisan\" (DB_URL) · exit 0 · 1.2 s")
        XCTAssertEqual(ev[0].command, "php artisan")
    }

    func testInterleavedRunsOfTheSameCallerPairOldestFirst() {
        // two identical commands, released twice, completed twice
        let rows = [released("1", 0), released("2", 1), completed("3", 2, exit: 1), completed("4", 3, exit: 0)]
        let ev = pair(rows)
        XCTAssertEqual(ev.map(\.rowIDs), [["2", "4"], ["1", "3"]])
        XCTAssertEqual(ev[1].result, .finished(exitCode: 1, durationMS: 1200))
        XCTAssertEqual(ev[0].result, .finished(exitCode: 0, durationMS: 1200))
    }

    func testRetryAfterAnOrphanedRunPairsWithTheRetry() {
        // The first run's daemon died after "released"; the retry started 100 s
        // later and finished 2 s after that.
        let rows = [released("1", 0), released("2", 100), completed("3", 102, ms: 2000)]
        let ev = pair(rows, now: 200)
        XCTAssertEqual(ev.map(\.rowIDs), [["2", "3"], ["1"]])
        XCTAssertEqual(ev[0].result, .finished(exitCode: 0, durationMS: 2000))
        XCTAssertEqual(ev[1].result, .running)
        // An hour on, the orphan is shown as never completed.
        XCTAssertEqual(pair(rows, now: 3700)[1].result, .noResultRecorded)
    }

    func testConcurrentIdenticalRunsFinishingOutOfOrderKeepTheirOwnResults() {
        // Run A starts at 0 and takes 10 s; run B starts at 1 and takes 2 s,
        // so B's completed row is written first.
        let rows = [released("A", 0), released("B", 1),
                    completed("cB", 3, exit: 7, ms: 2000), completed("cA", 10, exit: 0, ms: 10_000)]
        let ev = pair(rows, now: 20)
        XCTAssertEqual(ev.map(\.rowIDs), [["B", "cB"], ["A", "cA"]])
        XCTAssertEqual(ev[0].result, .finished(exitCode: 7, durationMS: 2000))
        XCTAssertEqual(ev[1].result, .finished(exitCode: 0, durationMS: 10_000))
    }

    func testCompletedWithNoRowAtOrBeforeItsStartFallsBackToTheNewestOpenRow() {
        // The computed start (0) precedes both open rows by more than the
        // tolerance (a run that failed after the released row, timed from the
        // request): use the newest one.
        let rows = [released("1", 50), released("2", 60), completed("3", 61, ms: 61_000)]
        XCTAssertEqual(pair(rows, now: 100).map(\.rowIDs), [["2", "3"], ["1"]])
    }

    func testMillisecondRoundingBetweenReleasedAndStartIsTolerated() {
        // The completed row says the run started 5 ms before its released row.
        let rows = [released("1", 0), released("2", 10), completed("3", 12, ms: 2005)]
        XCTAssertEqual(pair(rows, now: 20).map(\.rowIDs), [["2", "3"], ["1"]])
    }

    func testDifferentCommandsDoNotPair() {
        let rows = [released("1", 0, argv: ["a"]), released("2", 1, argv: ["b"]), completed("3", 2, argv: ["b"])]
        let ev = pair(rows)
        XCTAssertEqual(ev.map(\.rowIDs), [["2", "3"], ["1"]])
    }

    func testGrantIDSecretsCallerAndCwdMustAllMatch() {
        for (r, c) in [
            (released("1", 0, grant: "g1"), completed("2", 1, grant: "g2")),
            (released("1", 0, secrets: ["A"]), completed("2", 1, secrets: ["B"])),
            (released("1", 0, caller: "x"), completed("2", 1, caller: "y")),
        ] {
            XCTAssertEqual(pair([r, c], complete: true, now: 5).count, 2)
        }
    }

    func testReleasedWithoutResultIsRunningWithinAnHour() {
        let ev = pair([released("1", 0)], now: 600)
        XCTAssertEqual(ev[0].result, .running)
        XCTAssertEqual(ev[0].summary, "Running \"php artisan\" (DB_URL) · Running…")
    }

    func testReleasedWithoutResultIsNoResultRecordedAfterAnHour() {
        let ev = pair([released("1", 0)], now: 3601)
        XCTAssertEqual(ev[0].result, .noResultRecorded)
        XCTAssertEqual(ev[0].summary, "Started \"php artisan\" - no result recorded")
    }

    func testLoneCompletedAtTheWindowEdgeIsNeutral() {
        let ev = pair([completed("5", 0)], complete: false)
        XCTAssertEqual(ev[0].kind, .resultOnly)
        XCTAssertEqual(ev[0].result, .outsideWindow)
        XCTAssertEqual(ev[0].summary, "…")
    }

    func testLoneCompletedInACompleteWindowSaysSo() {
        let ev = pair([completed("5", 0)], complete: true)
        XCTAssertEqual(ev[0].result, .none)
        XCTAssertEqual(ev[0].summary, "Finished \"php artisan\" - no start recorded")
    }

    func testNotesFromTheCompletedRowAppearInTheSummary() {
        let ev = pair([released("1", 0), completed("2", 1, exit: 124, ms: 340, reason: "timeout")])
        XCTAssertEqual(ev[0].summary, "Ran \"php artisan\" (DB_URL) · exit 124 · timeout · 340 ms")
    }

    func testExpandedNamesReplaceGlobsInTheSummary() {
        var r = released("1", 0, secrets: ["aws/*"])
        r.expanded = ["aws/key", "aws/secret"]
        let ev = pair([r, completed("2", 1, secrets: ["aws/*"])])
        XCTAssertEqual(ev[0].summary, "Ran \"php artisan\" (aws/key, aws/secret) · exit 0 · 1.2 s")
    }

    func testLabels() {
        let table: [(String, String, String)] = [
            ("allowed_grant", "released", "Used a grant"),
            ("allowed_once", "released", "Allowed once"),
            ("allowed_new_grant", "released", "Allowed for a while (grant created)"),
            ("allowed_new_grant", "standing", "Standing grant created"),
            ("allowed_once", "set", "Secret saved"),
            ("allowed_once", "delete", "Secret deleted"),
            ("allowed_once", "show", "Secret revealed in a terminal"),
            ("allowed_once", "update", "Secret details changed"),
            ("allowed_once", "update: lower min_tier", "Secret details changed"),
            ("allowed_once", "grants revoke", "Grant revoked"),
            ("allowed_once", "grants revoke_all", "All grants revoked"),
            ("denied_user", "", "You said no"),
            ("refused_policy", "", "Blocked by .grantd.yml"),
            ("refused_tier", "", "Blocked: protection level"),
            ("error", "x", "Error"),
        ]
        for (d, r, label) in table { XCTAssertEqual(AuditPairing.label(decision: d, reason: r), label, "\(d)/\(r)") }
    }

    func testLifecycleRowShowsTheSecretName() {
        let row = AuditEntry(id: "9", ts: at(0), caller: "grantd-app", cwd: "", argv: ["grantd", "set", "aws/key"], secrets: ["aws/key"],
                             decision: "allowed_once", reason: "set")
        let ev = pair([row])
        XCTAssertEqual(ev[0].kind, .change)
        XCTAssertEqual(ev[0].title, "Secret saved")
        XCTAssertEqual(ev[0].command, "aws/key")
        XCTAssertEqual(ev[0].summary, "Secret saved: aws/key")
    }

    func testGrantRevocationRowsAreChangesNotRuns() {
        let one = AuditEntry(id: "1", ts: at(0), caller: "grantd-app", cwd: "/x", argv: ["grantd", "grants", "revoke", "g_1"],
                             decision: "allowed_once", grantID: "g_1", reason: "grants revoke")
        let all = AuditEntry(id: "2", ts: at(1), caller: "grantd-app", cwd: "/x", argv: ["grantd", "grants", "revoke", "--all", "g_2"],
                             decision: "allowed_once", grantID: "g_2", reason: "grants revoke_all")
        let none = AuditEntry(id: "3", ts: at(2), caller: "grantd-app", cwd: "/x", argv: ["grantd", "grants", "revoke", "--all"],
                              decision: "allowed_once", reason: "grants revoke_all")
        let ev = pair([one, all, none])
        XCTAssertEqual(ev.count, 3)
        XCTAssertEqual(ev.map(\.kind), [.change, .change, .change])
        XCTAssertEqual(ev[2].title, "Grant revoked")
        XCTAssertEqual(ev[2].command, "g_1")
        XCTAssertEqual(ev[2].summary, "Grant revoked: g_1")
        XCTAssertEqual(ev[2].caller, "grantd-app")
        XCTAssertEqual(ev[1].title, "All grants revoked")
        XCTAssertEqual(ev[1].summary, "All grants revoked: g_2")
        XCTAssertEqual(ev[0].title, "All grants revoked")
        XCTAssertEqual(ev[0].command, "")
        XCTAssertEqual(ev[0].summary, "All grants revoked: none were active")
    }

    func testDeniedAndErrorRows() {
        let denied = AuditEntry(id: "1", ts: at(0), argv: ["curl", "x"], secrets: ["K"], decision: "denied_user")
        let err = AuditEntry(id: "2", ts: at(1), argv: ["curl", "x"], secrets: ["K"], decision: "error", reason: "vault is locked")
        let ev = pair([denied, err])
        XCTAssertEqual(ev[1].kind, .refused)
        XCTAssertEqual(ev[1].summary, "You said no: curl x")
        XCTAssertEqual(ev[0].summary, "Error: curl x (vault is locked)")
    }

    func testRefusedLowerTierUpdateIsNotAChange() {
        // A lower min_tier update the human refused or that failed carries the
        // "update: lower min_tier" reason but nothing changed.
        let denied = AuditEntry(id: "1", ts: at(0), argv: ["grantd", "update", "API_KEY"], secrets: ["API_KEY"],
                                decision: "denied_user", reason: "update: lower min_tier")
        let err = AuditEntry(id: "2", ts: at(1), argv: ["grantd", "update", "API_KEY"], secrets: ["API_KEY"],
                             decision: "error", reason: "update: lower min_tier: authentication failed")
        let allowed = AuditEntry(id: "3", ts: at(2), argv: ["grantd", "update", "API_KEY"], secrets: ["API_KEY"],
                                 decision: "allowed_once", reason: "update: lower min_tier")
        let ev = pair([denied, err, allowed])
        XCTAssertEqual(ev[2].kind, .refused)
        XCTAssertEqual(ev[2].title, "You said no")
        XCTAssertEqual(ev[2].reason, "update: lower min_tier")
        XCTAssertEqual(ev[1].kind, .refused)
        XCTAssertEqual(ev[1].title, "Error")
        XCTAssertEqual(ev[1].summary, "Error: grantd update API_KEY (update: lower min_tier: authentication failed)")
        // The allowed one is still a change.
        XCTAssertEqual(ev[0].kind, .change)
        XCTAssertEqual(ev[0].title, "Secret details changed")
        XCTAssertEqual(ev[0].command, "API_KEY")
    }

    func testStandingGrantCreated() {
        let row = AuditEntry(id: "1", ts: at(0), argv: ["php"], secrets: ["K"], decision: "allowed_new_grant", reason: "standing")
        XCTAssertEqual(pair([row])[0].kind, .standingGrant)
    }

    func testHostileTextIsSanitisedAndShortened() {
        let evil = "rm\u{202E}fdp\u{1B}[31m" + String(repeating: "x", count: 5000)
        let ev = pair([released("1", 0, caller: "a\u{202E}b", argv: [evil])])
        XCTAssertFalse(ev[0].command.unicodeScalars.contains("\u{202E}"))
        XCTAssertFalse(ev[0].command.unicodeScalars.contains("\u{1B}"))
        XCTAssertLessThanOrEqual(ev[0].command.count, DisplayText.cellLimit)
        XCTAssertTrue(ev[0].command.contains("\u{27E6}U+202E\u{27E7}"))
        XCTAssertFalse(ev[0].caller.unicodeScalars.contains("\u{202E}"))
        XCTAssertFalse(ev[0].summary.unicodeScalars.contains("\u{202E}"))
    }

    func testRecentTakesTheNewestThree() {
        var rows = [AuditEntry]()
        for i in 0..<6 {
            rows.append(AuditEntry(id: "\(i)", ts: at(Double(i)), argv: ["grantd", "set", "S\(i)"], secrets: ["S\(i)"], decision: "allowed_once", reason: "set"))
        }
        let recent = AuditPairing.recent(rows.reversed(), windowIsComplete: true, count: 3, now: at(100))
        XCTAssertEqual(recent.map(\.command), ["S5", "S4", "S3"])
    }

    func testRunCountsAsOneOfTheThree() {
        let rows = [AuditEntry(id: "1", ts: at(0), argv: ["grantd", "set", "A"], secrets: ["A"], decision: "allowed_once", reason: "set"),
                    released("2", 1), completed("3", 2),
                    AuditEntry(id: "4", ts: at(3), argv: ["grantd", "delete", "A"], secrets: ["A"], decision: "allowed_once", reason: "delete")]
        let recent = AuditPairing.recent(rows.reversed(), windowIsComplete: true, now: at(100))
        XCTAssertEqual(recent.map(\.rowIDs), [["4"], ["2", "3"], ["1"]])
    }

    func testDurations() {
        XCTAssertEqual(AuditPairing.duration(milliseconds: 0), "0 ms")
        XCTAssertEqual(AuditPairing.duration(milliseconds: 340), "340 ms")
        XCTAssertEqual(AuditPairing.duration(milliseconds: 1000), "1 s")
        XCTAssertEqual(AuditPairing.duration(milliseconds: 1200), "1.2 s")
        XCTAssertEqual(AuditPairing.duration(milliseconds: 59_940), "59.9 s")
        XCTAssertEqual(AuditPairing.duration(milliseconds: 125_000), "2 min 5 s")
    }
}
