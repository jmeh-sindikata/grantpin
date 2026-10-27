import Foundation
import XCTest
@testable import GrantpinKit

/// The Grants and Activity screens' logic against the real Go dev daemon
/// (INSECURE test backends, `GRANTPIN_DEV_APPROVE=allow`): the standing-grant
/// form's request is accepted, the list shows it with its badges, revoke and
/// revoke all work, a forged grant row shows as tampered, the Activity model
/// pairs a real run, verifies, exports and honours `truncated`.
final class DevDaemonGrantsAuditTests: DevDaemonCase {
    /// Edits the vault file behind the daemon's back, like the Go e2e does.
    func sqlite(_ sql: String) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        p.arguments = [dir + "/vault.db", ".timeout 5000", sql]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, sql)
    }

    func project(_ name: String = "proj") throws -> String {
        let p = dir + "/" + name
        try FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true)
        return p
    }

    @MainActor
    func grantsModel() async throws -> GrantsViewModel {
        let m = GrantsViewModel(service: client)
        m.connectionChanged(.ready(try await client.status()))
        return m
    }

    // MARK: grants

    @MainActor
    func testAddStandingListRevokeAndRevokeAll() async throws {
        try await startDaemon()
        try await put("DB_URL", "postgres://user:password@host/dbname")
        try await put("aws/key", "AKIA-0123456789-abcdef")
        let proj = try project()
        let m = try await grantsModel()
        await m.refresh()
        XCTAssertTrue(m.isEmpty)
        XCTAssertNil(m.revokeAllConfirmation())

        // the form: choices come from the daemon, the request is the form's
        let form = m.makeStandingForm(initialFolder: proj, initialTTL: .days7)
        await form.loadChoices()
        XCTAssertEqual(form.availableSecrets, ["DB_URL", "aws/key"])
        form.forCaller = "cursor"
        form.selectedSecrets = ["DB_URL"]
        form.patternsText = "aws/*"
        form.commandText = "php artisan"
        form.usesText = "3"
        XCTAssertTrue(form.canSubmit)
        XCTAssertEqual(form.folderResolved, realPath(proj))
        await form.submit()
        guard case .created(let toast) = form.phase else { return XCTFail("\(form.phase) \(String(describing: form.error))") }
        XCTAssertTrue(toast.hasPrefix("Standing grant created. cursor can run \"php artisan\" with DB_URL, aws/* in \(realPath(proj)) until "), toast)
        await m.formDidCreate(toast)
        XCTAssertEqual(m.notice, toast)

        XCTAssertEqual(m.rows.count, 1)
        let row = m.rows[0]
        XCTAssertEqual(row.badges, [.standing])
        XCTAssertEqual(row.kind, "Standing")
        XCTAssertEqual(row.caller, "cursor")
        XCTAssertEqual(row.folder, realPath(proj))
        XCTAssertEqual(row.secrets, "DB_URL, aws/*")
        XCTAssertEqual(row.command, "php artisan")
        XCTAssertEqual(row.usesLeft, "3")
        XCTAssertEqual(row.timeLeft, "in 6 d 23 h")
        await assertEqual(try await client.status().activeGrants, 1)

        // the next form knows the caller from the audit log
        let next = m.makeStandingForm()
        await next.loadChoices()
        XCTAssertEqual(next.knownCallers, ["claude-code", "cursor"])

        // a second grant, no use limit and 90 days
        let second = m.makeStandingForm(initialFolder: proj, initialTTL: .days90)
        second.selectedSecrets = ["DB_URL"]
        second.commandText = "node build.js"
        await second.submit()
        guard case .created = second.phase else { return XCTFail("\(String(describing: second.error))") }
        await m.refresh()
        XCTAssertEqual(m.rows.count, 2)
        XCTAssertEqual(m.rows.map(\.usesLeft).sorted(), ["3", "No limit"])

        // revoke one: the confirmation names the scope
        let id = try XCTUnwrap(m.rows.first { $0.caller == "cursor" }?.id)
        let c = try XCTUnwrap(m.revokeConfirmation(for: id))
        XCTAssertEqual(c.title, "Revoke this grant?")
        XCTAssertEqual(c.message, "cursor will have to ask you again before it can use DB_URL, aws/* in \(realPath(proj)). A command that is already running keeps running.")
        let ok = await m.revoke(id: id)
        XCTAssertTrue(ok)
        XCTAssertEqual(m.rows.count, 1)

        // revoking it again says it is gone
        let again = await m.revoke(id: id)
        XCTAssertFalse(again)
        XCTAssertEqual(m.banner?.headline, "That grant is already gone.")

        // revoke all
        XCTAssertEqual(m.revokeAllConfirmation()?.title, "Revoke 1 grant?")
        let all = await m.revokeAll()
        XCTAssertTrue(all)
        XCTAssertTrue(m.isEmpty)
        await assertEqual(try await client.status().activeGrants, 0)
    }

    @MainActor
    func testAForgedGrantRowShowsAsTamperedAndCanBeRemoved() async throws {
        try await startDaemon()
        try await put("API_KEY", "api-key-value-0123456789")
        let proj = try project()
        let m = try await grantsModel()
        let form = m.makeStandingForm(initialFolder: proj, initialTTL: .days7)
        form.selectedSecrets = ["API_KEY"]
        form.commandText = "make deploy"
        await form.submit()
        guard case .created = form.phase else { return XCTFail("\(String(describing: form.error))") }

        // three forged rows (empty, wrong and all-zero MAC), as in the Go e2e
        let far = Int64((Date().timeIntervalSince1970 + 86_400) * 1e9)
        let now = Int64(Date().timeIntervalSince1970 * 1e9)
        let macs = ["X''", "X'666f72676564'", "X'" + String(repeating: "00", count: 32) + "'"]
        for (i, mac) in macs.enumerated() {
            try sqlite("INSERT INTO grants (id, caller, cwd_prefix, secrets, cmd_prefix, created_at, expires_at, uses_remaining, mac) VALUES ('forged\(i)', 'evil\u{202E}', '/etc', '[\"API_KEY\"]', '[\"sh\"]', \(now), \(far), NULL, \(mac))")
        }

        await m.refresh()
        XCTAssertEqual(m.tamperedCount, 3)
        XCTAssertEqual(m.rows.count, 4)
        let bad = m.rows.prefix(3)
        XCTAssertTrue(bad.allSatisfy { $0.tampered && $0.badges == [.tampered] })
        XCTAssertTrue(bad.allSatisfy { $0.tamperedNote == "Failed verification. grantpin ignores it. Remove it." })
        XCTAssertTrue(bad.allSatisfy { $0.caller.isEmpty && $0.folder.isEmpty && $0.command.isEmpty }, "forged fields are never shown")
        XCTAssertEqual(Set(bad.map(\.id)), ["forged0", "forged1", "forged2"])
        XCTAssertEqual(m.rows[3].badges, [.standing], "the genuine grant is next to them")

        // the popover and the icon notice
        let status = try await client.status()
        XCTAssertEqual(status.tamperedGrants, 3)
        XCTAssertEqual(status.activeGrants, 1)
        let line = StatusLine.from(.ready(status))
        XCTAssertEqual(line.button, .review)
        XCTAssertEqual(line.tamperedWarning, "TAMPERED: 3 grants failed verification. Open Grants to review.")
        XCTAssertEqual(MenuBarIcon.from(.ready(status)).badge, .warning)

        // Remove one tampered row; the confirmation is the Remove text
        XCTAssertEqual(m.revokeConfirmation(for: "forged1")?.title, "Remove this grant?")
        let removed = await m.revoke(id: "forged1")
        XCTAssertTrue(removed)
        XCTAssertEqual(m.tamperedCount, 2)
        let all = await m.revokeAll()
        XCTAssertTrue(all)
        XCTAssertTrue(m.isEmpty)
        await assertEqual(try await client.status().tamperedGrants, 0)
    }

    @MainActor
    func testPolicyRefusalAndCeilingAreShownByTheForm() async throws {
        try await startDaemon()
        try await put("DB_URL", "postgres://user:password@host/dbname")
        let proj = try project()
        try "version: 1\nsecrets:\n  - DB_URL\ncommands:\n  - [php, artisan]\nmax_standing_grant_ttl: 1h\n"
            .write(toFile: proj + "/.grantpin.yml", atomically: true, encoding: .utf8)
        let m = try await grantsModel()

        // a command the policy does not list
        let refused = m.makeStandingForm(initialFolder: proj, initialTTL: .hour1)
        refused.selectedSecrets = ["DB_URL"]
        refused.commandText = "curl example.com"
        await refused.submit()
        XCTAssertEqual(refused.phase, .editing)
        XCTAssertEqual(refused.error?.headline, "A .grantpin.yml in that folder does not allow this:")
        XCTAssertFalse(refused.error?.detail?.isEmpty ?? true)

        // a lifetime above the repo's ceiling: the daemon's message, never clamped
        let long = m.makeStandingForm(initialFolder: proj, initialTTL: .days7)
        long.selectedSecrets = ["DB_URL"]
        long.commandText = "php artisan"
        await long.submit()
        XCTAssertEqual(long.phase, .editing)
        let text = try XCTUnwrap(long.error?.headline)
        XCTAssertTrue(text.contains("exceeds the maximum standing grant lifetime of 1h"), text)
        XCTAssertTrue(text.contains("max_standing_grant_ttl in"), text)
        XCTAssertTrue(text.contains(".grantpin.yml"), text)

        // and within the ceiling it works
        long.ttl = .hour1
        await long.submit()
        guard case .created = long.phase else { return XCTFail("\(String(describing: long.error))") }
        await assertEqual(try await client.listGrants().count, 1)
    }

    @MainActor
    func testUnknownSecretAndMissingFolderAreCaughtBeforeOrByTheDaemon() async throws {
        try await startDaemon()
        try await put("DB_URL", "postgres://user:password@host/dbname")
        let proj = try project()
        let m = try await grantsModel()
        let f = m.makeStandingForm(initialFolder: proj, initialTTL: .hour1)
        f.patternsText = "NOPE"
        f.commandText = "php artisan"
        await f.submit()
        XCTAssertEqual(f.error?.headline, "One of those secrets doesn't exist.")
        f.chooseFolder(proj + "/gone")
        XCTAssertFalse(f.canSubmit, "a missing folder is stopped before anything is sent")
        await assertTrue(try await client.listGrants().isEmpty)
    }

    // MARK: activity

    @MainActor
    func activityModel() async throws -> ActivityViewModel {
        let m = ActivityViewModel(service: client)
        m.connectionChanged(.ready(try await client.status()))
        return m
    }

    /// A real run with the allow approver: a released row and a completed row.
    func run(_ argv: [String], secrets: [String], cwd: String? = nil) async throws {
        var r = Request(op: "run")
        r.cwd = cwd ?? realPath(dir)
        r.argv = argv
        r.secrets = secrets
        _ = try await client.call(r, timeout: 30)
    }

    @MainActor
    func testActivityPairsFiltersVerifiesAndExports() async throws {
        try await startDaemon()
        try await put("RUNME", "run-secret-value-0123456789")
        try await put("OTHER", "other-secret-value-012345678")
        try await run(["sh", "-c", "exit 3"], secrets: ["RUNME"])
        try await run(["sh", "-c", "exit 0"], secrets: ["RUNME", "OTHER"])
        try await client.delete("OTHER")
        let m = try await activityModel()
        await m.refresh()

        // 2 sets + 2 runs (2 rows each) + 1 delete = 7 rows, 5 events
        XCTAssertEqual(m.entries.count, 7)
        XCTAssertEqual(m.events.count, 5)
        XCTAssertFalse(m.truncated)
        XCTAssertTrue(m.windowIsComplete)
        let runs = m.events.filter { $0.kind == .run }
        XCTAssertEqual(runs.count, 2)
        XCTAssertEqual(Set(runs.map(\.resultText).map { $0.components(separatedBy: " · ")[0] }), ["Exit 3", "Exit 0"])
        XCTAssertEqual(Set(runs.map(\.tone)), [.succeeded, .failed])
        XCTAssertTrue(runs.allSatisfy { $0.rowIDs.count == 2 })

        m.filter = .runs
        XCTAssertEqual(m.visibleEvents.count, 2)
        m.filter = .changes
        XCTAssertEqual(m.visibleEvents.count, 3)
        m.filter = .denied
        XCTAssertTrue(m.visibleEvents.isEmpty)
        m.filter = .all
        m.searchText = "exit 3"
        XCTAssertEqual(m.visibleEvents.count, 1)
        m.searchText = ""
        let detail = try XCTUnwrap(m.detail(for: try XCTUnwrap(runs.first { $0.tone == .failed }).id))
        XCTAssertEqual(detail.cwd, realPath(dir))
        XCTAssertEqual(detail.command, "sh -c exit 3")
        XCTAssertEqual(detail.secretsRequested, "RUNME")

        // verify
        await m.verifyLog()
        XCTAssertEqual(m.verify, .ok(entries: 7))

        // export: the daemon's CSV, untouched
        let out = await m.exportCSV()
        guard case .csv(let csv, let name) = out else { return XCTFail("\(out)") }
        XCTAssertTrue(name.hasPrefix("grantpin-audit-") && name.hasSuffix(".csv"))
        let rows = try CSV.parse(csv)
        XCTAssertEqual(rows[0], ["id", "ts", "caller", "cwd", "argv", "secrets", "expanded", "decision", "grant_id", "reason", "exit_code", "duration_ms"])
        XCTAssertEqual(rows.count - 1, 7)
        let again = try await client.exportAudit()
        XCTAssertEqual(csv, again)

        // tamper with a row: verify reports where
        try sqlite("DROP TRIGGER audit_no_update; UPDATE audit SET caller = 'evil' WHERE id = 3;")
        await m.verifyLog()
        XCTAssertEqual(m.verify, .broken(firstBadID: "3"))
        m.dismissVerify()
        XCTAssertEqual(m.verify, .idle)
    }

    @MainActor
    func testLoadMoreAndTruncatedWithRealRows() async throws {
        try await startDaemon()
        try await put("BIG", "big-secret-value-0123456789")
        // The daemon caps every audit field (an argv element at 16 KiB, the argv column at
        // 64 KiB), so one row can no longer outgrow a page by itself; many large rows still
        // do. 36 runs with four 16 KiB arguments are 72 rows of ~64 KiB: over one 4 MiB page.
        let big = String(repeating: "x", count: 16_000)
        for _ in 0..<36 { try await run(["sh", "-c", "exit 0", big, big, big, big], secrets: ["BIG"]) }
        let m = try await activityModel()
        await m.refresh()
        XCTAssertTrue(m.truncated, "the page did not fit in one line")
        XCTAssertLessThan(m.entries.count, 73)
        XCTAssertGreaterThan(m.entries.count, 5)
        XCTAssertFalse(m.canLoadMore)
        XCTAssertFalse(m.windowIsComplete)
        XCTAssertEqual(m.footer, "Some older entries did not fit in one page. Export CSV to read them all.")
        // every cell is cut for display, whatever the command line
        XCTAssertTrue(m.events.allSatisfy { $0.command.count <= DisplayText.cellLimit })
        // the export does not fit either, and says so
        let out = await m.exportCSV()
        XCTAssertEqual(out, .failed(UserMessage(ActivityViewModel.tooLargeText)))
        // the chain still verifies (1 set + 72 run rows)
        await m.verifyLog()
        XCTAssertEqual(m.verify, .ok(entries: 73))
    }

    @MainActor
    func testLoadMorePagesThroughTheRealLog() async throws {
        try await startDaemon()
        for i in 0..<30 { try await put("n/\(i)", "value-number-\(i)-0123456789") }
        let m = try await activityModel()
        await m.refresh()
        XCTAssertEqual(m.entries.count, 30)
        XCTAssertFalse(m.canLoadMore, "30 rows are fewer than a page: the log is loaded to its start")
        XCTAssertTrue(m.windowIsComplete)
        XCTAssertNil(m.footer)
    }
}

/// With no approver mode the dev daemon denies every prompt.
final class DevDaemonDeniedScreenTests: DevDaemonCase {
    override var approveMode: String? { nil }

    @MainActor
    func testADeniedRunIsDistinctInActivityAndTheStandingFormSaysNotCreated() async throws {
        try await startDaemon()
        try await put("KEY", "key-secret-value-0123456789")
        var r = Request(op: "run")
        r.cwd = realPath(dir)
        r.argv = ["ls"]
        r.secrets = ["KEY"]
        let e = await expectGrantpinError(try await client.call(r, timeout: 20))
        XCTAssertEqual(e?.reason, .userDenied)

        let activity = ActivityViewModel(service: client)
        activity.connectionChanged(.ready(try await client.status()))
        await activity.refresh()
        let denied = try XCTUnwrap(activity.events.first { $0.decision == "denied_user" })
        XCTAssertEqual(denied.title, "You said no")
        XCTAssertEqual(denied.tone, .denied)
        XCTAssertEqual(denied.resultText, "Denied")
        activity.filter = .denied
        XCTAssertEqual(activity.visibleEvents.map(\.id), [denied.id])

        let grants = GrantsViewModel(service: client)
        grants.connectionChanged(.ready(try await client.status()))
        let form = grants.makeStandingForm(initialFolder: dir, initialTTL: .hour1)
        form.selectedSecrets = ["KEY"]
        form.commandText = "ls"
        await form.submit()
        XCTAssertEqual(form.phase, .editing)
        XCTAssertEqual(form.error?.headline, "Not created. You cancelled the confirmation.")
        await grants.refresh()
        XCTAssertTrue(grants.isEmpty, "nothing is stored when the human does not approve")
    }
}

/// `allow-no-standing` allows runs but never a standing grant.
final class DevDaemonNoStandingScreenTests: DevDaemonCase {
    override var approveMode: String? { "allow-no-standing" }

    @MainActor
    func testTheDaemonCanRefuseWhileTheFormStaysHonest() async throws {
        try await startDaemon()
        try await put("KEY", "key-secret-value-0123456789")
        let form = GrantsViewModel(service: client).makeStandingForm(initialFolder: dir, initialTTL: .hour1)
        form.selectedSecrets = ["KEY"]
        form.commandText = "ls"
        await form.submit()
        XCTAssertEqual(form.error?.headline, "Not created. You cancelled the confirmation.")
        await assertTrue(try await client.listGrants().isEmpty)
    }
}
