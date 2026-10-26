import Foundation
import XCTest
@testable import GrantpinKit

/// The screens' logic against the real Go dev daemon (INSECURE test backends,
/// `GRANTPIN_DEV_APPROVE=allow`): the validators agree with the daemon, the
/// expiry parser agrees with the CLI, the Secrets view model drives the whole
/// add / list / update / replace / delete path, the import view model drives a
/// real `.env` import through the dev binary, and the popover's last events
/// are the daemon's own audit rows.
final class DevDaemonScreenTests: DevDaemonCase {
    // MARK: validators vs the daemon

    static let nameCorpus: [String] = [
        "a", "A_b", "aws/prod/key", "x.y-z", ".hidden", "trail.", "-lead", "9", "a/b/c/d", String(repeating: "n", count: 256),
        "", String(repeating: "n", count: 257), "has space", "tab\there", "new\nline", "a*b", "a?b", "a[b]", "a{b}", "a\\b", "a:b",
        "é", "日本", "a@b", "$HOME", "a=b", "a,b", "/a", "a/", "/", "a//b", "..", "a..b", "a/../b", "../a", ".", "./a", "a/.", "a/./b",
        "a b/c", "semi;colon", "quote\"d", "back`tick", "pipe|x", "a\u{0}b",
    ]

    func testNameValidatorAgreesWithTheDaemon() async throws {
        try await startDaemon()
        for n in Self.nameCorpus {
            var accepted = false
            do { _ = try await client.exists(n); accepted = true } catch let e as GrantpinError {
                XCTAssertTrue(e.isBadRequest, "\(n.prefix(12).debugDescription): \(e)")
            }
            XCTAssertEqual(Validators.nameIssue(n) == nil, accepted, "name \(n.prefix(12).debugDescription)")
        }
    }

    static let tagCorpus: [String] = [
        "a", "prod", "team:x", "v1.2", "a_b", "a-b", ":", String(repeating: "x", count: 64),
        String(repeating: "x", count: 65), "a/b", "a b", "a*", "é", "a,b", "#t", "a;b", "a=b", "a@b", "UPPER", "0",
    ]

    func testTagValidatorAgreesWithTheDaemon() async throws {
        try await startDaemon()
        for t in Self.tagCorpus {
            var v = Data("tag-test-value-0123".utf8)
            var accepted = false
            do { try await client.set(name: "tagtest", value: &v, tags: [t], overwrite: true); accepted = true } catch let e as GrantpinError {
                XCTAssertTrue(e.isBadRequest, "\(e)")
            }
            XCTAssertEqual(Validators.tagIssue(t) == nil, accepted, "tag \(t.prefix(12).debugDescription)")
        }
        // the count limit: 32 pass, 33 fail
        for (n, ok) in [(32, true), (33, false)] {
            var v = Data("tag-test-value-0123".utf8)
            let tags = (0..<n).map { "t\($0)" }
            var accepted = true
            do { try await client.set(name: "tagtest", value: &v, tags: tags, overwrite: true) } catch { accepted = false }
            XCTAssertEqual(accepted, ok, "\(n) tags")
            XCTAssertEqual(Validators.parseTags(tags.joined(separator: ",")).isValid, ok)
        }
    }

    func testURLNotesAndValueLimitsAgreeWithTheDaemon() async throws {
        try await startDaemon()
        for (len, ok) in [(2048, true), (2049, false)] {
            var v = Data("limit-test-value-0123".utf8)
            let s = String(repeating: "u", count: len)
            var urlOK = true, notesOK = true
            do { try await client.set(name: "lim", value: &v, url: s, overwrite: true) } catch { urlOK = false }
            v = Data("limit-test-value-0123".utf8)
            do { try await client.set(name: "lim", value: &v, notes: s, overwrite: true) } catch { notesOK = false }
            XCTAssertEqual(urlOK, ok); XCTAssertEqual(notesOK, ok)
            XCTAssertEqual(Validators.urlIssue(s) == nil, ok); XCTAssertEqual(Validators.notesIssue(s) == nil, ok)
        }
        // multi-byte: 1025 two-byte characters are 2050 bytes
        var v = Data("limit-test-value-0123".utf8)
        let wide = String(repeating: "é", count: 1025)
        do { try await client.set(name: "lim", value: &v, notes: wide, overwrite: true); XCTFail("accepted") } catch {}
        XCTAssertNotNil(Validators.notesIssue(wide))
        // value: exactly 1 MiB is fine, one more byte is not
        for (len, ok) in [(1 << 20, true), ((1 << 20) + 1, false)] {
            var big = Data(repeating: 0x61, count: len)
            var accepted = true
            do { try await client.set(name: "big", value: &big, overwrite: true) } catch { accepted = false }
            XCTAssertEqual(accepted, ok, "\(len) bytes")
            XCTAssertEqual(Validators.valueIssue(String(repeating: "a", count: len)) == nil, ok)
        }
    }

    // MARK: expiry parser vs the CLI

    /// Runs `grantpin-dev set NAME --expires X` with the value on stdin; true if it was accepted.
    /// (An empty `--expires ""` is "no expiry" to the CLI, so it is not in the corpus; the
    /// app's own empty custom field is simply not an expiry.)
    private func cliAccepts(_ expires: String, name: String) throws -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: devBinary)
        p.arguments = ["set", name, "--overwrite", "--expires", expires, "--socket", socket]
        p.environment = environment()
        let stdin = Pipe()
        p.standardInput = stdin
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        stdin.fileHandleForWriting.write(Data("expiry-test-value-0123\n".utf8))
        try stdin.fileHandleForWriting.close()
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    func testExpiryParserAgreesWithTheCLI() async throws {
        try await startDaemon()
        let corpus = ["30d", "2w", "1d", "12h", "90m", "1h30m", "1.5h", "100h", "36500d", "60s", "+5h", ".5h", "  7d ",
                      "abc", "30", "d", "1.5d", "36501d", "0d", "0", "-5h", "1h30", "5H", "3 d", "1x", "--5h", "1e3s"]
        for text in corpus {
            let name = "exp/case"
            let cli = try cliAccepts(text, name: name)
            let app = (try? ExpiryParser.parseDuration(text)) != nil
            XCTAssertEqual(app, cli, "\(text.debugDescription): app \(app), cli \(cli)")
            if cli {
                let stored = try await unwrap(try await client.list().first { $0.name == name }?.expiresAt)
                let expected = try ExpiryParser.parseDuration(text)
                XCTAssertEqual(stored.timeIntervalSinceNow, expected, accuracy: 10, text)
            }
        }
    }

    // MARK: the Secrets window, end to end

    @MainActor
    func testAddListUpdateReplaceDelete() async throws {
        try await startDaemon()
        let model = SecretsViewModel(service: client)
        model.connectionChanged(.ready(try await client.status()))
        await model.refresh()
        XCTAssertEqual(model.emptyState, .noSecrets)

        // add
        let add = model.makeAddForm()
        add.name = "prod/api key"
        XCTAssertEqual(add.nameMessage, "Use letters, numbers, _ . - and / only.")
        add.name = "prod/api-key"
        add.value = "first-value-abcdef-1111"
        add.tagsText = "prod, billing"
        add.url = "https://example.com/console"
        add.notes = "owned by billing"
        add.expiryKind = .days30
        add.tier = .dialog
        var saved = await add.save()
        XCTAssertTrue(saved, "\(String(describing: add.error))")
        XCTAssertEqual(add.value, "")
        await model.formDidSave(name: "prod/api-key")

        // list
        let row = try XCTUnwrap(model.secret(named: "prod/api-key"))
        XCTAssertEqual(row.tags, ["billing", "prod"])
        XCTAssertEqual(row.url, "https://example.com/console")
        XCTAssertEqual(row.notes, "owned by billing")
        XCTAssertEqual(row.minTier, .dialog)
        XCTAssertEqual(ExpiryFormatter.relative(row.expiresAt), "in 29 d")  // 30 d, a moment ago
        XCTAssertEqual(model.selection, ["prod/api-key"])
        await model.checkLastCharacters(of: "prod/api-key")
        XCTAssertEqual(model.masked, .value("****1111"))

        // adding the same name again is a replace, never a silent overwrite
        let dup = model.makeAddForm()
        dup.name = "prod/api-key"; dup.value = "should-not-win-0000"
        XCTAssertEqual(dup.saveTitle, "Replace…")

        // a plain add that races an existing name is refused by the daemon
        let racing = SecretFormModel(service: client, existingNames: [])
        racing.name = "prod/api-key"; racing.value = "should-not-win-0000"
        saved = await racing.save()
        XCTAssertFalse(saved)
        XCTAssertEqual(racing.error?.headline, "A secret with this name already exists.")
        await model.checkLastCharacters(of: "prod/api-key")
        XCTAssertEqual(model.masked, .value("****1111"), "the value is untouched")

        // update: metadata only
        let edit = model.makeEditForm(for: row)
        XCTAssertFalse(edit.canSave)
        edit.tagsText = "prod, billing, rotated"
        edit.notes = ""
        edit.url = ""
        edit.expiryKind = .never
        saved = await edit.save()
        XCTAssertTrue(saved, "\(String(describing: edit.error))")
        await model.formDidSave(name: "prod/api-key")
        let edited = try XCTUnwrap(model.secret(named: "prod/api-key"))
        XCTAssertEqual(edited.tags, ["billing", "prod", "rotated"])
        XCTAssertEqual(edited.notes, "")
        XCTAssertEqual(edited.url, "")
        XCTAssertNil(edited.expiresAt)
        XCTAssertEqual(edited.minTier, .dialog)
        await model.checkLastCharacters(of: "prod/api-key")
        XCTAssertEqual(model.masked, .value("****1111"), "update never touches the value")

        // replace value: set with overwrite, metadata kept from the form
        let replace = model.makeEditForm(for: edited)
        replace.mode = .replaceValue
        XCTAssertFalse(replace.canSave)
        replace.value = "second-value-abcdef-2222\n"
        XCTAssertEqual(replace.replaceConfirmation, Confirmation.replace(name: "prod/api-key"))
        saved = await replace.save()
        XCTAssertTrue(saved, "\(String(describing: replace.error))")
        await model.formDidSave(name: "prod/api-key")
        await model.checkLastCharacters(of: "prod/api-key")
        XCTAssertEqual(model.masked, .value("****2222"))
        XCTAssertEqual(model.secret(named: "prod/api-key")?.tags, ["billing", "prod", "rotated"])
        XCTAssertEqual(model.secret(named: "prod/api-key")?.minTier, .dialog)

        // lowering a tier: the dev approver allows; the update goes through the long path
        var v = Data("hardware-value-abcdef-3333".utf8)
        try await client.set(name: "hw/key", value: &v, minTier: .hardware)
        await model.refresh()
        let hw = model.makeEditForm(for: try XCTUnwrap(model.secret(named: "hw/key")))
        hw.tier = .dialog
        XCTAssertTrue(hw.tierIsLowering)
        saved = await hw.save()
        XCTAssertTrue(saved, "\(String(describing: hw.error))")
        await model.formDidSave(name: "hw/key")
        XCTAssertEqual(model.secret(named: "hw/key")?.minTier, .dialog)

        // delete
        let confirm = await model.deleteConfirmation(for: ["prod/api-key"])
        XCTAssertEqual(confirm.title, "Delete \"prod/api-key\"?")
        let deleted = await model.delete(names: ["prod/api-key", "hw/key"])
        XCTAssertTrue(deleted)
        XCTAssertEqual(model.emptyState, .noSecrets)
        await assertEqual(try await client.list().count, 0)
    }

    @MainActor
    func testGrantsMentioningASecretAreCountedInTheDeleteConfirmation() async throws {
        try await startDaemon()
        try await put("granted", "granted-value-0123456789")
        let cwd = (dir as NSString).resolvingSymlinksInPath
        _ = try await client.addStandingGrant(StandingGrantRequest(forCaller: "claude-code", cwd: cwd, secrets: ["granted"], argv: ["php"], ttlSeconds: 3600))
        let model = SecretsViewModel(service: client)
        model.connectionChanged(.ready(try await client.status()))
        let c = await model.deleteConfirmation(for: ["granted"])
        XCTAssertTrue(c.message.hasSuffix("1 active grant mentions this secret. It stays in place but won't work until you add it again."), c.message)
    }

    // MARK: import, end to end

    @MainActor
    func testImportDryRunThenRealRunWithATempEnvFile() async throws {
        try await startDaemon()
        try await put("EXISTS", "existing-value-0000000000")
        let file = dir + "/.env"
        try "# a comment\nNEW_ONE=alpha-value-1111\nexport NEW_TWO='beta value 2222'\nEXISTS=replacement-value-9999\nEMPTY=\n"
            .write(toFile: file, atomically: true, encoding: .utf8)
        let before = try Data(contentsOf: URL(fileURLWithPath: file))
        let runner = ImportRunner(executable: URL(fileURLWithPath: devBinary), socketPath: socket, environment: environment())
        let secrets = SecretsViewModel(service: client)
        secrets.connectionChanged(.ready(try await client.status()))
        let model = ImportViewModel(service: runner, fileName: ".env",
                                    openFile: { try FileHandle(forReadingFrom: URL(fileURLWithPath: file)) },
                                    onImported: { await secrets.refresh() })

        // dry run with the default, Skip existing: nothing is written
        await model.preview()
        var r = try XCTUnwrap(model.report, "\(model.phase)")
        XCTAssertTrue(r.dryRun)
        XCTAssertEqual([r.addedCount, r.overwrittenCount, r.skippedCount, r.emptyCount], [2, 0, 1, 1])
        XCTAssertEqual(r.added.sorted(), ["NEW_ONE", "NEW_TWO"])
        XCTAssertEqual(r.skipped, ["EXISTS"])
        XCTAssertEqual(r.ignoredEmpty, ["EMPTY"])
        await assertEqual(try await client.list().map(\.name), ["EXISTS"])
        XCTAssertNil(model.overwriteConfirmation)

        // Overwrite re-runs the dry run and needs the confirmation
        await model.setMode(.overwrite)
        r = try XCTUnwrap(model.report)
        XCTAssertEqual(r.overwritten, ["EXISTS"])
        XCTAssertEqual(model.overwriteConfirmation, Confirmation.importOverwrite(names: ["EXISTS"]))
        await assertEqual(try await client.masked("EXISTS"), "****0000")

        // back to Skip, then the real run
        await model.setMode(.skip)
        await model.performImport()
        guard case .done(let done) = model.phase else { return XCTFail("\(model.phase)") }
        XCTAssertFalse(done.dryRun)
        XCTAssertEqual(done.summary, "Added 2, skipped 1, ignored 1 empty. Nothing was overwritten.")
        XCTAssertEqual(secrets.secrets.map(\.name), ["EXISTS", "NEW_ONE", "NEW_TWO"], "the list reloaded after the real run")
        await assertEqual(try await client.masked("EXISTS"), "****0000")
        await assertEqual(try await client.masked("NEW_TWO"), "****2222")
        // the imported rows have default metadata
        let row = try XCTUnwrap(secrets.secret(named: "NEW_ONE"))
        XCTAssertEqual(row.tags, [])
        XCTAssertNil(row.expiresAt)

        // the file is left alone
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file)), before)

        // overwrite for real
        let again = ImportViewModel(service: runner, fileName: ".env", openFile: { try FileHandle(forReadingFrom: URL(fileURLWithPath: file)) })
        await again.setMode(.overwrite)
        XCTAssertEqual(again.report?.overwritten, ["NEW_ONE", "NEW_TWO", "EXISTS"], "all three exist by now")
        await again.performImport()
        guard case .done(let over) = again.phase else { return XCTFail("\(again.phase)") }
        XCTAssertEqual(over.summary, "Overwrote 3, ignored 1 empty.")
        await assertEqual(try await client.masked("EXISTS"), "****9999")
    }

    @MainActor
    func testImportOfABadFileShowsTheLineAndWritesNothing() async throws {
        try await startDaemon()
        let file = dir + "/bad.env"
        try "GOOD=value-value-0001\nthis is not a pair\n".write(toFile: file, atomically: true, encoding: .utf8)
        let runner = ImportRunner(executable: URL(fileURLWithPath: devBinary), socketPath: socket, environment: environment())
        let model = ImportViewModel(service: runner, fileName: "bad.env", openFile: { try FileHandle(forReadingFrom: URL(fileURLWithPath: file)) })
        await model.preview()
        guard case .failed(let f) = model.phase else { return XCTFail("\(model.phase)") }
        XCTAssertEqual(f.headline, "Line 2: expected KEY=value")
        XCTAssertFalse(model.canImport)
        await assertEqual(try await client.list().count, 0)
    }

    @MainActor
    func testStopIfAnyExistListsTheConflicts() async throws {
        try await startDaemon()
        try await put("DUP", "existing-value-0000000000")
        let file = dir + "/c.env"
        try "DUP=x-value-xxxxxxxx\nFRESH=y-value-yyyyyyyy\n".write(toFile: file, atomically: true, encoding: .utf8)
        let runner = ImportRunner(executable: URL(fileURLWithPath: devBinary), socketPath: socket, environment: environment())
        let model = ImportViewModel(service: runner, fileName: "c.env", openFile: { try FileHandle(forReadingFrom: URL(fileURLWithPath: file)) })
        await model.setMode(.error)
        guard case .failed(let f) = model.phase else { return XCTFail("\(model.phase)") }
        XCTAssertEqual(f.conflicts, ["DUP"])
        XCTAssertFalse(model.canImport)
    }

    // MARK: the popover's last events

    @MainActor
    func testPopoverShowsTheLastThreeEventsFromTheRealAuditLog() async throws {
        try await startDaemon()
        try await put("pop/key", "popover-value-0123456789")
        try await client.update(name: "pop/key", notes: "n")
        try await put("RUNME", "run-secret-value-0123456789", overwrite: false)
        // a real run: a released row and a completed row
        var run = Request(op: "run")
        run.cwd = (dir as NSString).resolvingSymlinksInPath
        run.argv = ["sh", "-c", "exit 3"]
        run.secrets = ["RUNME"]
        _ = try await client.call(run, timeout: 20)
        try await client.delete("pop/key")

        let model = PopoverModel(audit: client, actions: nil)
        await model.refreshActivity()
        XCTAssertEqual(model.recent.count, 3)
        XCTAssertEqual(model.recent[0].title, "Secret deleted")
        XCTAssertEqual(model.recent[0].command, "pop/key")
        // the run is ONE event with its exit code, not two rows
        XCTAssertEqual(model.recent[1].kind, .run)
        XCTAssertEqual(model.recent[1].rowIDs.count, 2)
        XCTAssertEqual(model.recent[1].result, .finished(exitCode: 3, durationMS: model.recent[1].resultDuration))
        XCTAssertTrue(model.recent[1].summary.hasPrefix("Ran \"sh -c exit 3\" (RUNME) · exit 3 · "), model.recent[1].summary)
        XCTAssertEqual(model.recent[2].title, "Secret saved")
        XCTAssertEqual(model.recent[2].command, "RUNME")
    }

    // MARK: the status line against the real daemon

    @MainActor
    func testStatusLineFromARealStatus() async throws {
        try await startDaemon()
        try await put("one", "one-value-0123456789")
        let line = StatusLine.from(ConnectionState.from(try await client.status()))
        XCTAssertEqual(line.headline, "grantpin is running")
        XCTAssertEqual(line.countsText, "1 secret · 0 active grants")
        XCTAssertEqual(line.level, .ok)
    }
}

extension AuditEvent {
    var resultDuration: Int64 {
        if case .finished(_, let ms) = result { return ms }
        return -1
    }
}
