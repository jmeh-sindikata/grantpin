import Foundation
import XCTest
@testable import GrantpinKit

/// Every op the app uses, against the real Go daemon (`-tags grantpin_dev`,
/// `GRANTPIN_DEV_APPROVE=allow`). `vault_locked` cannot be produced with the dev
/// keystore; its mapping is unit-tested in ClientTests.
final class DevDaemonOpsTests: DevDaemonCase {
    // MARK: status

    func testStatusBeforeAndAfterInit() async throws {
        try await startDaemon(initVault: false)
        var s = try await client.status()
        XCTAssertFalse(s.vaultInitialized)
        XCTAssertFalse(s.vaultLocked)
        XCTAssertEqual(s.protoV, 1)
        XCTAssertEqual(s.socket, socket)
        XCTAssertEqual(ConnectionState.from(s), .notInitialized)
        // every other op fails with vault_not_initialized
        for e in [
            await expectGrantpinError(try await client.list()),
            await expectGrantpinError(try await client.exists("a")),
            await expectGrantpinError(try await client.masked("a")),
            await expectGrantpinError(try await client.delete("a")),
            await expectGrantpinError(try await client.listGrants()),
            await expectGrantpinError(try await client.listAudit()),
        ] {
            XCTAssertEqual(e?.isVaultNotInitialized, true, "\(String(describing: e))")
            XCTAssertEqual(e?.category, .failed)
        }

        try initVault()
        s = try await client.status()
        XCTAssertTrue(s.vaultInitialized)
        XCTAssertEqual(s.inFlightRuns, 0, "this daemon reports its runs in flight, and nothing runs")
        XCTAssertEqual(s.keystoreTier, "none")  // the insecure dev backend
        XCTAssertEqual(s.approverTier, "none")
        XCTAssertEqual(s.secrets, 0)
        XCTAssertEqual(s.activeGrants, 0)
        XCTAssertEqual(s.tamperedGrants, 0)
        XCTAssertGreaterThan(s.pid, 0)
        XCTAssertFalse(s.version.isEmpty)
        XCTAssertNotNil(s.startedAt)
        XCTAssertEqual(ConnectionState.from(s), .ready(s))
    }

    // MARK: the secret lifecycle, in the order the app uses it

    func testSetListMaskedUpdateExistsDelete() async throws {
        try await startDaemon()
        let c = client

        // set -> list
        var value = Data("0123456789abcdef-WXYZ".utf8)
        let exp = Date().addingTimeInterval(30 * 86_400)
        let auditID = try await c.set(name: "aws/key", value: &value, tags: ["b", "a", "b"], url: "https://console.aws.amazon.com",
                                      notes: "prod key", expires: exp, minTier: .dialog)
        XCTAssertFalse(auditID.isEmpty)
        XCTAssertEqual(value, Data(repeating: 0, count: value.count), "the caller's buffer was not wiped")
        try await put("b/second", "short")
        try await put("a/first", "another-value-0123456789")

        var items = try await c.list()
        XCTAssertEqual(items.map(\.name), ["a/first", "aws/key", "b/second"])  // sorted by name
        let aws = try XCTUnwrap(items.first { $0.name == "aws/key" })
        XCTAssertEqual(aws.tags, ["a", "b"])  // de-duplicated and sorted
        XCTAssertEqual(aws.url, "https://console.aws.amazon.com")
        XCTAssertEqual(aws.notes, "prod key")
        XCTAssertEqual(aws.minTier, .dialog)
        XCTAssertEqual(try XCTUnwrap(aws.expiresAt).timeIntervalSince(exp), 0, accuracy: 1.0)

        // a list response never carries a value
        let raw = try await c.call(Request(op: "list"))
        let rawText = String(decoding: raw.line, as: UTF8.self)
        for v in ["0123456789abcdef-WXYZ", "another-value-0123456789"] { XCTAssertFalse(rawText.contains(v)) }
        await assertEqual(try await c.list(tag: "a").map(\.name), ["aws/key"])

        // masked: 12+ characters show the last four, shorter ones nothing
        await assertEqual(try await c.masked("aws/key"), "****WXYZ")
        await assertEqual(try await c.masked("b/second"), "********")
        var e = await expectGrantpinError(try await c.masked("nope"))
        XCTAssertEqual(e?.category, .notFound)
        XCTAssertEqual(e?.reason, .secretNotFound)

        // update: tags, url, notes, expiry; the value stays
        let later = Date().addingTimeInterval(90 * 86_400)
        try await c.update(name: "aws/key", tags: ["z", "y"], url: "https://example.org", notes: "rotated", expires: later)
        items = try await c.list()
        var u = try XCTUnwrap(items.first { $0.name == "aws/key" })
        XCTAssertEqual(u.tags, ["y", "z"])
        XCTAssertEqual(u.url, "https://example.org")
        XCTAssertEqual(u.notes, "rotated")
        XCTAssertEqual(try XCTUnwrap(u.expiresAt).timeIntervalSince(later), 0, accuracy: 1.0)
        XCTAssertEqual(u.minTier, .dialog)  // not touched
        XCTAssertEqual(u.createdAt, aws.createdAt)
        await assertEqual(try await c.masked("aws/key"), "****WXYZ")  // value untouched

        // update: only one field leaves the others alone
        try await c.update(name: "aws/key", notes: "only notes")
        u = try await unwrap(try await c.list().first { $0.name == "aws/key" })
        XCTAssertEqual(u.notes, "only notes")
        XCTAssertEqual(u.tags, ["y", "z"])

        // update: clear (the `clear` list, not clear_expires)
        try await c.update(name: "aws/key", clear: [.expires, .url, .notes, .tags])
        u = try await unwrap(try await c.list().first { $0.name == "aws/key" })
        XCTAssertNil(u.expiresAt)
        XCTAssertEqual(u.url, "")
        XCTAssertEqual(u.notes, "")
        XCTAssertEqual(u.tags, [])
        await assertEqual(try await c.masked("aws/key"), "****WXYZ")

        // update errors
        e = await expectGrantpinError(try await c.update(name: "nope", notes: "x"))
        XCTAssertEqual(e?.reason, .secretNotFound)
        XCTAssertEqual(e?.isNotFound, true)
        e = await expectGrantpinError(try await c.update(name: "aws/key"))  // nothing to change
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.update(name: "aws/key", expires: later, clear: [.expires]))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.update(name: "aws/key", expires: Date().addingTimeInterval(-60)))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.update(name: "aws/key", minTier: Tier(rawValue: "bogus")))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.update(name: "aws/key", tags: ["no spaces"]))
        XCTAssertEqual(e?.isBadRequest, true)

        // exists
        await assertTrue(try await c.exists("aws/key"))
        await assertFalse(try await c.exists("nope"))
        e = await expectGrantpinError(try await c.exists("a//b"))
        XCTAssertEqual(e?.category, .badRequest)

        // delete, then again
        try await c.delete("aws/key")
        await assertFalse(try await c.exists("aws/key"))
        e = await expectGrantpinError(try await c.delete("aws/key"))
        XCTAssertEqual(e?.category, .notFound)
        XCTAssertEqual(e?.reason, .secretNotFound)
        await assertEqual(try await c.list().map(\.name), ["a/first", "b/second"])
        await assertEqual(try await c.status().secrets, 2)
    }

    func testSetRules() async throws {
        try await startDaemon()
        let c = client

        try await put("dup/key", "first-value-0123456789", tags: ["old"])
        var v = Data("second-value-0123456789".utf8)
        var e = await expectGrantpinError(try await c.set(name: "dup/key", value: &v))
        XCTAssertEqual(e?.category, .badRequest)
        XCTAssertEqual(e?.reason, .secretExists)
        XCTAssertEqual(v, Data(repeating: 0, count: v.count), "wiped on failure too")
        await assertEqual(try await c.masked("dup/key"), "****6789")  // the first value is still there

        let before = try await unwrap(try await c.list().first)
        v = Data("second-value-0123456780".utf8)
        try await c.set(name: "dup/key", value: &v, notes: "new", overwrite: true)
        let after = try await unwrap(try await c.list().first)
        XCTAssertEqual(after.createdAt, before.createdAt)  // created_at is kept
        XCTAssertEqual(after.tags, [])                     // the old metadata is replaced, not merged
        XCTAssertEqual(after.notes, "new")
        await assertEqual(try await c.masked("dup/key"), "****6780")

        v = Data()
        e = await expectGrantpinError(try await c.set(name: "empty", value: &v))
        XCTAssertEqual(e?.isBadRequest, true)
        v = Data("a-value-0123456789".utf8)
        e = await expectGrantpinError(try await c.set(name: "past", value: &v, expires: Date().addingTimeInterval(-3600)))
        XCTAssertEqual(e?.isBadRequest, true)
        v = Data("a-value-0123456789".utf8)
        e = await expectGrantpinError(try await c.set(name: "tier", value: &v, minTier: Tier(rawValue: "bogus")))
        XCTAssertEqual(e?.isBadRequest, true)
        v = Data("a-value-0123456789".utf8)
        e = await expectGrantpinError(try await c.set(name: "bad//name", value: &v))
        XCTAssertEqual(e?.isBadRequest, true)
        v = Data("a-value-0123456789".utf8)
        e = await expectGrantpinError(try await c.set(name: "badtag", value: &v, tags: ["has space"]))
        XCTAssertEqual(e?.isBadRequest, true)

        // 1 MiB is the daemon's limit
        v = Data(repeating: 0x61, count: 1 << 20)
        try await c.set(name: "big/ok", value: &v)
        await assertEqual(try await c.masked("big/ok"), "****aaaa")
        v = Data(repeating: 0x61, count: (1 << 20) + 1)
        e = await expectGrantpinError(try await c.set(name: "big/over", value: &v))
        XCTAssertEqual(e?.isBadRequest, true)
        await assertFalse(try await c.exists("big/over"))

        // a value of control characters escapes to over 4 MiB: refused here, never sent
        v = Data(repeating: 0x07, count: 1 << 20)
        e = await expectGrantpinError(try await c.set(name: "ctl", value: &v))
        XCTAssertEqual(e, .requestTooLarge)

        // a value that is not UTF-8 is not sent
        v = Data([0xFF, 0xFE, 0x41])
        e = await expectGrantpinError(try await c.set(name: "bin", value: &v))
        guard case .invalidRequest? = e else { return XCTFail("\(String(describing: e))") }

        // awkward but valid values round-trip through the daemon unchanged
        v = Data("line1\nline2\t\"quoted\" \\ back \u{00E9}\u{1F511} end-1234".utf8)
        try await c.set(name: "odd/value", value: &v)
        await assertEqual(try await c.masked("odd/value"), "****1234")
    }

    // MARK: tier changes

    func testLoweringAMinimumTierAsksTheApproverAndRaisingDoesNot() async throws {
        try await startDaemon()
        let c = client
        var v = Data("tier-test-value-0123456789".utf8)
        try await c.set(name: "tier/key", value: &v, minTier: .hardware)

        // hardware -> dialog is a lowering: the dev approver (allow) records and allows it
        try await c.update(name: "tier/key", minTier: .dialog)
        await assertEqual(try await c.list().first?.minTier, .dialog)
        var newest = try await unwrap(try await c.listAudit(limit: 1).entries.first)
        XCTAssertEqual(newest.decision, "allowed_once")
        XCTAssertEqual(newest.reason, "update: lower min_tier")
        XCTAssertEqual(newest.argv, ["grantpin", "update", "tier/key"])

        // dialog -> hardware raises it: a plain update
        try await c.update(name: "tier/key", minTier: .hardware)
        await assertEqual(try await c.list().first?.minTier, .hardware)
        newest = try await unwrap(try await c.listAudit(limit: 1).entries.first)
        XCTAssertEqual(newest.reason, "update")

        // an unchanged tier and a metadata-only update are plain too
        try await c.update(name: "tier/key", notes: "same", minTier: .hardware)
        await assertEqual(try await c.listAudit(limit: 1).entries.first?.reason, "update")
        await assertEqual(try await c.masked("tier/key"), "****6789")  // the value survived every re-encryption
    }

    // MARK: grants

    func testStandingGrantAddListRevoke() async throws {
        try await startDaemon()
        let c = client
        try await put("DB_URL", "postgres://user:password@host/dbname")
        await assertTrue(try await c.listGrants().isEmpty)

        let resolved = realPath(dir)  // /tmp is /private/tmp; URL.resolvingSymlinksInPath() would strip the /private
        let started = Date()
        // The dev approver answers at once; a real daemon waits for the human.
        let g = try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: dir, secrets: ["DB_URL"], argv: ["php", "artisan"], ttlSeconds: 3600, uses: 2))
        XCTAssertTrue(g.standing)
        XCTAssertFalse(g.tampered)
        XCTAssertEqual(g.caller, "claude-code")
        XCTAssertEqual(g.cmdPrefix, ["php", "artisan"])
        XCTAssertEqual(g.secrets, ["DB_URL"])
        XCTAssertEqual(g.cwdPrefix, resolved)  // the daemon resolves symlinks (/tmp is /private/tmp)
        XCTAssertEqual(g.usesRemaining, 2)
        XCTAssertEqual(g.expiresAt.timeIntervalSince(started), 3600, accuracy: 30)

        let listed = try await c.listGrants()
        XCTAssertEqual(listed.map(\.id), [g.id])
        await assertEqual(try await c.status().activeGrants, 1)
        let audit = try await unwrap(try await c.listAudit(limit: 1).entries.first)
        XCTAssertEqual(audit.decision, "allowed_new_grant")
        XCTAssertEqual(audit.reason, "standing")
        XCTAssertEqual(audit.grantID, g.id)
        XCTAssertEqual(audit.caller, "claude-code")  // the grant's label

        try await c.revokeGrant(id: g.id)
        await assertTrue(try await c.listGrants().isEmpty)
        var e = await expectGrantpinError(try await c.revokeGrant(id: g.id))
        XCTAssertEqual(e?.category, .notFound)
        XCTAssertEqual(e?.reason, .grantNotFound)

        // no use limit; revoke all
        let a = try await c.addStandingGrant(StandingGrantRequest(forCaller: "claude-code", cwd: dir, secrets: ["DB_*"], argv: ["sh"], ttlSeconds: 60))
        XCTAssertNil(a.usesRemaining)
        _ = try await c.addStandingGrant(StandingGrantRequest(forCaller: "other", cwd: dir, secrets: ["DB_URL"], argv: ["node"], ttlSeconds: 90 * 86_400))
        await assertEqual(try await c.listGrants().count, 2)
        try await c.revokeAllGrants()
        await assertTrue(try await c.listGrants().isEmpty)

        // the daemon validates; nothing is clamped here
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: dir, secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 91 * 86_400)))
        XCTAssertEqual(e?.category, .badRequest)
        XCTAssertTrue(e?.message.contains("90d") == true, e?.message ?? "")
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: dir, secrets: ["NOPE"], argv: ["php"], ttlSeconds: 60)))
        XCTAssertEqual(e?.category, .notFound)
        XCTAssertEqual(e?.reason, .secretNotFound)
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "", cwd: dir, secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 60)))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "x", cwd: dir + "/missing", secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 60)))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "x", cwd: dir, secrets: ["DB_URL"], argv: [], ttlSeconds: 60)))
        XCTAssertEqual(e?.isBadRequest, true)
        e = await expectGrantpinError(try await c.addStandingGrant(StandingGrantRequest(
            forCaller: "x", cwd: dir, secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 0)))
        XCTAssertEqual(e?.isBadRequest, true)
        await assertTrue(try await c.listGrants().isEmpty)
    }

    // MARK: audit

    func testAuditListVerifyAndExport() async throws {
        try await startDaemon()
        let c = client
        try await put("audit/one", "audit-value-0123456789")
        try await put("audit/two", "audit-value-0123456780")
        try await c.update(name: "audit/one", notes: "n")
        try await c.delete("audit/two")

        // list: newest first, the app's own rows
        let list = try await c.listAudit()
        XCTAssertFalse(list.truncated)
        XCTAssertEqual(list.entries.count, 4)
        let ids = list.entries.compactMap { Int($0.id) }
        XCTAssertEqual(ids, ids.sorted(by: >))
        XCTAssertEqual(list.entries.map(\.reason), ["delete", "update", "set", "set"])
        for entry in list.entries {
            XCTAssertEqual(entry.decision, "allowed_once")
            XCTAssertEqual(entry.caller, "grantpin-app")
            XCTAssertEqual(entry.argv.first, "grantpin")
        }
        XCTAssertEqual(list.entries[0].argv, ["grantpin", "delete", "audit/two"])
        XCTAssertEqual(list.entries[0].secrets, ["audit/two"])
        XCTAssertEqual(list.entries[1].argv, ["grantpin", "update", "audit/one"])
        XCTAssertEqual(list.entries[3].argv, ["grantpin", "set", "audit/one"])
        XCTAssertNil(list.entries[0].exitCode)
        // limit is honoured
        await assertEqual(try await c.listAudit(limit: 2).entries.map(\.id), Array(list.entries.prefix(2)).map(\.id))
        // no value anywhere in the raw log
        let raw = try await c.call(Request(op: "audit"))
        XCTAssertFalse(String(decoding: raw.line, as: UTF8.self).contains("audit-value"))

        // verify
        let v = try await c.verifyAudit()
        XCTAssertTrue(v.ok)
        XCTAssertEqual(v.entries, 4)
        XCTAssertNil(v.firstBadID)

        // export: CSV with the documented header, one row per entry, oldest first
        let csv = try await c.exportAudit()
        let rows = try CSV.parse(csv)
        XCTAssertEqual(rows[0], ["id", "ts", "caller", "cwd", "argv", "secrets", "expanded", "decision", "grant_id", "reason", "exit_code", "duration_ms"])
        XCTAssertEqual(rows.count - 1, list.entries.count)
        XCTAssertEqual(rows.dropFirst().map { $0[0] }, list.entries.reversed().map(\.id))
        let argvCell = Data(rows[1][4].utf8)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: argvCell) as? [String], ["grantpin", "set", "audit/one"])
        XCTAssertEqual(rows[1][2], "grantpin-app")
    }

    func testVerifyReportsATamperedLog() async throws {
        try await startDaemon()
        let c = client
        try await put("t/one", "tamper-value-0123456789")
        try await put("t/two", "tamper-value-0123456780")
        try await put("t/three", "tamper-value-0123456781")
        await assertTrue(try await c.verifyAudit().ok)

        // Edit a row behind the daemon's back (the append-only trigger is dropped first).
        let sqlite = Process()
        sqlite.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        sqlite.arguments = [dir + "/vault.db", ".timeout 5000", "DROP TRIGGER audit_no_update; UPDATE audit SET caller = 'evil' WHERE id = 2;"]
        sqlite.standardOutput = FileHandle.nullDevice
        sqlite.standardError = FileHandle.nullDevice
        try sqlite.run()
        sqlite.waitUntilExit()
        XCTAssertEqual(sqlite.terminationStatus, 0)

        let v = try await c.verifyAudit()  // the response is ok; the chain is not
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.firstBadID, "2")
    }

    // MARK: import through the helper

    func testImportThroughTheHelperWithADescriptorOnStdin() async throws {
        try await startDaemon()
        try await put("KEEP", "existing-value-0123456789")
        let env = dir + "/test.env"
        try "# comment\nNEW_ONE=alpha-value-0001\nexport NEW_TWO='beta value 0002'\nKEEP=changed-value-9999\nEMPTY=\n".write(toFile: env, atomically: true, encoding: .utf8)
        let runner = ImportRunner(executable: URL(fileURLWithPath: devBinary), socketPath: socket, environment: environment())

        func run(dry: Bool, _ mode: ImportConflictMode) async throws -> HelperOutput {
            let fh = try FileHandle(forReadingFrom: URL(fileURLWithPath: env))
            defer { try? fh.close() }
            return try await runner.run(from: fh, dryRun: dry, onConflict: mode)
        }

        // dry run, skip: nothing is written
        var out = try await run(dry: true, .skip)
        XCTAssertTrue(out.succeeded, out.stderr)
        var report = try ImportReport.parse(out.stdout)
        XCTAssertTrue(report.dryRun)
        XCTAssertEqual(report.added.sorted(), ["NEW_ONE", "NEW_TWO"])
        XCTAssertEqual(report.skipped, ["KEEP"])
        XCTAssertEqual(report.ignoredEmpty, ["EMPTY"])
        await assertEqual(try await client.list().map(\.name), ["KEEP"])

        // "error" stops when something exists
        out = try await run(dry: true, .error)
        XCTAssertEqual(out.exitCode, 1)
        XCTAssertTrue(out.stderr.contains("KEEP"), out.stderr)
        XCTAssertFalse(out.stdout.contains("alpha-value-0001") || out.stderr.contains("alpha-value-0001"))

        // dry run, overwrite: reports what would be replaced
        out = try await run(dry: true, .overwrite)
        report = try ImportReport.parse(out.stdout)
        XCTAssertEqual(report.overwritten, ["KEEP"])

        // the real import, skip
        out = try await run(dry: false, .skip)
        XCTAssertTrue(out.succeeded, out.stderr)
        report = try ImportReport.parse(out.stdout)
        XCTAssertFalse(report.dryRun)
        XCTAssertEqual(report.added.sorted(), ["NEW_ONE", "NEW_TWO"])
        await assertEqual(try await client.list().map(\.name), ["KEEP", "NEW_ONE", "NEW_TWO"])
        await assertEqual(try await client.masked("KEEP"), "****6789")  // skipped, not overwritten
        await assertEqual(try await client.masked("NEW_TWO"), "****0002")

        // overwrite
        out = try await run(dry: false, .overwrite)
        XCTAssertTrue(out.succeeded, out.stderr)
        await assertEqual(try await client.masked("KEEP"), "****9999")
    }

    func testImportReportsAParseErrorAndAnUnreachableDaemon() async throws {
        try await startDaemon()
        let bad = dir + "/bad.env"
        try "GOOD=value-value-0001\n1BAD KEY=oops\n".write(toFile: bad, atomically: true, encoding: .utf8)
        let runner = ImportRunner(executable: URL(fileURLWithPath: devBinary), socketPath: socket, environment: environment())
        let fh = try FileHandle(forReadingFrom: URL(fileURLWithPath: bad))
        defer { try? fh.close() }
        let out = try await runner.run(from: fh, dryRun: false, onConflict: .skip)
        XCTAssertEqual(out.exitCode, 1)
        XCTAssertFalse(out.succeeded)
        XCTAssertTrue(out.stderr.contains("line 2"), out.stderr)
        await assertEqual(try await client.list().count, 0)

        // a helper that cannot be started is an error, not a crash
        let missing = ImportRunner(executable: URL(fileURLWithPath: "/nonexistent/grantpin"), socketPath: socket)
        let e = await expectGrantpinError(try await missing.run(from: FileHandle.nullDevice, dryRun: true, onConflict: .skip))
        guard case .io? = e else { return XCTFail("\(String(describing: e))") }
    }
}

/// With the default approver (auto-deny) every dialog is refused.
final class DevDaemonDeniedTests: DevDaemonCase {
    override var approveMode: String? { nil }

    func testStandingGrantIsDeniedWithoutApproval() async throws {
        try await startDaemon()
        try await put("DB_URL", "postgres://user:password@host/dbname")
        let e = await expectGrantpinError(try await client.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: dir, secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 60)))
        XCTAssertEqual(e?.category, .denied)
        XCTAssertEqual(e?.reason, .userDenied)
        XCTAssertEqual(e?.isDenied, true)
        await assertTrue(try await client.listGrants().isEmpty)
    }

    func testLoweringATierIsDeniedAndChangesNothing() async throws {
        try await startDaemon()
        var v = Data("tier-test-value-0123456789".utf8)
        try await client.set(name: "tier/key", value: &v, notes: "old", minTier: .hardware)
        let e = await expectGrantpinError(try await client.update(name: "tier/key", notes: "new", minTier: .dialog))
        XCTAssertEqual(e?.category, .denied)
        XCTAssertEqual(e?.reason, .userDenied)
        let after = try await unwrap(try await client.list().first)
        XCTAssertEqual(after.minTier, .hardware)
        XCTAssertEqual(after.notes, "old")  // the rest of the request did not apply either
        let row = try await unwrap(try await client.listAudit(limit: 1).entries.first)
        XCTAssertEqual(row.decision, "denied_user")
        XCTAssertTrue(row.reason.hasPrefix("update: lower min_tier"), row.reason)
        // raising or metadata-only still works without an approver
        try await client.update(name: "tier/key", notes: "new")
    }
}

/// `allow-no-standing` allows everything except standing grants.
final class DevDaemonNoStandingTests: DevDaemonCase {
    override var approveMode: String? { "allow-no-standing" }

    func testStandingGrantIsDeniedButOtherDialogsAreAllowed() async throws {
        try await startDaemon()
        try await put("DB_URL", "postgres://user:password@host/dbname")
        let e = await expectGrantpinError(try await client.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: dir, secrets: ["DB_URL"], argv: ["php"], ttlSeconds: 60)))
        XCTAssertEqual(e?.reason, .userDenied)
        var v = Data("x-value-0123456789".utf8)
        try await client.set(name: "k", value: &v, minTier: .dialog)
        try await client.update(name: "k", minTier: .vaultDefault)  // a lowering, allowed here
    }
}

/// realpath(3): what the daemon resolves a folder to.
func realPath(_ path: String) -> String {
    guard let p = realpath(path, nil) else { return path }
    defer { free(p) }
    return String(cString: p)
}

/// A minimal RFC 4180 parser for the export test.
enum CSV {
    static func parse(_ text: String) throws -> [[String]] {
        var rows = [[String]](), row = [String](), field = ""
        var inQuotes = false
        let chars = Array(text.unicodeScalars)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < chars.count, chars[i + 1] == "\"" { field.unicodeScalars.append("\""); i += 1 } else { inQuotes = false }
                } else { field.unicodeScalars.append(c) }
            } else if c == "\"" { inQuotes = true }
            else if c == "," { row.append(field); field = "" }
            else if c == "\r" { /* followed by \n */ }
            else if c == "\n" { row.append(field); field = ""; rows.append(row); row = [] }
            else { field.unicodeScalars.append(c) }
            i += 1
        }
        if !field.isEmpty || !row.isEmpty { row.append(field); rows.append(row) }
        guard !inQuotes else { throw GrantpinError.malformedResponse("unterminated quote") }
        return rows
    }
}
