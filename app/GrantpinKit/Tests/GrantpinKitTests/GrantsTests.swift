import Foundation
import XCTest
@testable import GrantpinKit

final class GrantRowTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func grant(_ id: String = "g1", in seconds: TimeInterval, standing: Bool = false, uses: Int? = nil) -> GrantInfo {
        GrantInfo(id: id, caller: "claude-code", cwdPrefix: "/Users/me/app", secrets: ["DB_URL", "aws/*"], cmdPrefix: ["php", "artisan"],
                  expiresAt: now.addingTimeInterval(seconds), usesRemaining: uses, standing: standing)
    }

    func testTimeLeftTexts() {
        func t(_ s: TimeInterval) -> String { ExpiryFormatter.timeLeft(now.addingTimeInterval(s), now: now) }
        XCTAssertEqual(t(-1), "expired")
        XCTAssertEqual(t(0), "expired")
        XCTAssertEqual(t(20), "in <1 min")
        XCTAssertEqual(t(23 * 60 + 10), "in 23 min")
        XCTAssertEqual(t(3600), "in 1 h")
        XCTAssertEqual(t(2 * 3600 + 5 * 60), "in 2 h 5 min")
        XCTAssertEqual(t(86_400), "in 1 d")
        XCTAssertEqual(t(29 * 86_400 + 4 * 3600 + 120), "in 29 d 4 h")
        XCTAssertEqual(t(90 * 86_400 - 5), "in 89 d 23 h")
    }

    func testBadges() {
        XCTAssertEqual(GrantRow(grant(in: 3600), now: now).badges, [])
        XCTAssertEqual(GrantRow(grant(in: 3600, standing: true), now: now).badges, [.standing])
        XCTAssertEqual(GrantRow(grant(in: 599), now: now).badges, [.expiringSoon])
        XCTAssertEqual(GrantRow(grant(in: 600), now: now).badges, [])
        XCTAssertEqual(GrantRow(grant(in: 300, standing: true), now: now).badges, [.standing, .expiringSoon])
        XCTAssertEqual(GrantRow(grant(in: -5), now: now).badges, [.expired])
        XCTAssertEqual(GrantRow(grant(in: 0), now: now).badges, [.expired])
    }

    func testColumns() {
        let r = GrantRow(grant(in: 3 * 3600, standing: true, uses: 4), now: now)
        XCTAssertEqual(r.caller, "claude-code")
        XCTAssertEqual(r.folder, "/Users/me/app")
        XCTAssertEqual(r.secrets, "DB_URL, aws/*")
        XCTAssertEqual(r.command, "php artisan")
        XCTAssertEqual(r.kind, "Standing")
        XCTAssertEqual(r.usesLeft, "4")
        XCTAssertEqual(r.timeLeft, "in 3 h")
        XCTAssertEqual(GrantRow(grant(in: 60), now: now).kind, "Session")
        XCTAssertEqual(GrantRow(grant(in: 60), now: now).usesLeft, "No limit")
    }

    func testTamperedRowShowsOnlyTheIDAndTheReviewText() {
        let bad = GrantInfo(id: "forgeda", caller: "evil\u{202E}", cwdPrefix: "/etc", secrets: ["ROOT"], cmdPrefix: ["sh"],
                            expiresAt: now.addingTimeInterval(86_400), standing: true, tampered: true)
        let r = GrantRow(bad, now: now)
        XCTAssertTrue(r.tampered)
        XCTAssertEqual(r.badges, [.tampered])
        XCTAssertEqual(r.id, "forgeda")
        XCTAssertEqual(r.tamperedNote, "Failed verification. grantpin ignores it. Remove it.")
        for field in [r.caller, r.folder, r.secrets, r.command, r.kind, r.timeLeft, r.usesLeft] { XCTAssertEqual(field, "") }
        XCTAssertNil(r.expiresAt)
        XCTAssertFalse(r.standing)
    }

    func testUntrustedTextIsSanitised() {
        let g = GrantInfo(id: "g", caller: "a\u{202E}b", cwdPrefix: "/x\u{1B}[0m", secrets: ["S\u{0}"], cmdPrefix: ["ls", "\u{202E}"], expiresAt: now.addingTimeInterval(60))
        let r = GrantRow(g, now: now)
        for field in [r.caller, r.folder, r.secrets, r.command] {
            XCTAssertFalse(field.unicodeScalars.contains { $0.value == 0x202E || $0.value == 0x1B || $0.value == 0 }, field)
        }
    }
}

final class GrantConfirmationTests: XCTestCase {
    func testRevokeText() {
        let g = GrantInfo(id: "g1", caller: "claude-code", cwdPrefix: "/Users/me/app", secrets: ["DB_URL", "API_KEY"], cmdPrefix: ["ls"])
        let c = Confirmation.revoke(g)
        XCTAssertEqual(c.title, "Revoke this grant?")
        XCTAssertEqual(c.message, "claude-code will have to ask you again before it can use DB_URL, API_KEY in /Users/me/app. A command that is already running keeps running.")
        XCTAssertEqual(c.confirmLabel, "Revoke")
    }

    func testTamperedUsesTheRemoveText() {
        let bad = GrantInfo(id: "x", caller: "evil", tampered: true)
        let c = Confirmation.revoke(bad)
        XCTAssertEqual(c.title, "Remove this grant?")
        XCTAssertEqual(c.message, "grantpin could not verify this grant, so it is ignored and never allows anything. Removing it clears the warning.")
        XCTAssertEqual(c.confirmLabel, "Remove")
        XCTAssertFalse(c.message.contains("evil"))
    }

    func testRevokeAllText() {
        let c = Confirmation.revokeAll(count: 3)
        XCTAssertEqual(c.title, "Revoke all 3 grants?")
        XCTAssertEqual(c.message, "Every agent will have to ask you again, including for standing grants you created on purpose. Commands already running keep running.")
        XCTAssertEqual(c.confirmLabel, "Revoke All")
        XCTAssertEqual(Confirmation.revokeAll(count: 1).title, "Revoke 1 grant?")
    }
}

@MainActor
final class GrantsViewModelTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func g(_ id: String, in s: TimeInterval, tampered: Bool = false, standing: Bool = false) -> GrantInfo {
        GrantInfo(id: id, caller: "claude-code", cwdPrefix: "/p", secrets: ["S"], cmdPrefix: ["ls"], expiresAt: now.addingTimeInterval(s),
                  standing: standing, tampered: tampered)
    }

    func model(_ fake: FakeGrants) -> GrantsViewModel {
        let m = GrantsViewModel(service: fake, now: { self.now })
        m.connectionChanged(.ready(readyStatus))
        return m
    }

    func testSortsTamperedFirstThenBySoonestEnd() async {
        let f = FakeGrants()
        f.grants = [g("late", in: 7200), g("soon", in: 100), g("bad2", in: 0, tampered: true), g("bad1", in: 0, tampered: true), g("mid", in: 3600)]
        let m = model(f)
        await m.refresh()
        XCTAssertEqual(m.rows.map(\.id), ["bad1", "bad2", "soon", "mid", "late"])
        XCTAssertEqual(m.tamperedCount, 2)
        XCTAssertTrue(m.hasLoaded)
    }

    func testEmptyState() async {
        let m = model(FakeGrants())
        XCTAssertFalse(m.isEmpty, "not before the first load")
        await m.refresh()
        XCTAssertTrue(m.isEmpty)
        XCTAssertNil(m.revokeAllConfirmation())
    }

    func testRevokeOneThenRefresh() async {
        let f = FakeGrants()
        f.grants = [g("a", in: 100), g("b", in: 200)]
        let m = model(f)
        await m.refresh()
        m.selection = ["a"]
        XCTAssertEqual(m.revokeConfirmation(for: "a")?.title, "Revoke this grant?")
        let ok = await m.revoke(id: "a")
        XCTAssertTrue(ok)
        XCTAssertEqual(f.revoked, ["a"])
        XCTAssertEqual(m.rows.map(\.id), ["b"])
        XCTAssertTrue(m.selection.isEmpty, "the selection follows the list")
        XCTAssertNil(m.banner)
    }

    func testRevokeAGoneGrantSaysSoAndRefreshes() async {
        let f = FakeGrants()
        f.grants = [g("a", in: 100)]
        let m = model(f)
        await m.refresh()
        f.grants = []  // another client revoked it first
        let ok = await m.revoke(id: "a")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.banner?.headline, "That grant is already gone.")
        XCTAssertTrue(m.rows.isEmpty)
    }

    func testRevokeAll() async {
        let f = FakeGrants()
        f.grants = [g("a", in: 100), g("b", in: 200, tampered: true)]
        let m = model(f)
        await m.refresh()
        XCTAssertEqual(m.revokeAllConfirmation()?.title, "Revoke all 2 grants?")
        let ok = await m.revokeAll()
        XCTAssertTrue(ok)
        XCTAssertEqual(f.revokeAllCalls, 1)
        XCTAssertTrue(m.rows.isEmpty)
    }

    func testRevokeFailureIsABanner() async {
        let f = FakeGrants()
        f.grants = [g("a", in: 100)]
        f.revokeFailure = GrantpinError.timeout
        let m = model(f)
        await m.refresh()
        let ok = await m.revoke(id: "a")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.banner?.headline, "grantpin took too long to answer.")
    }

    func testDisabledWhileTheDaemonIsNotUsable() {
        let m = GrantsViewModel(service: FakeGrants(), now: { self.now })
        XCTAssertFalse(m.isEnabled)
        XCTAssertEqual(m.disabledReason, "Checking grantpin…")
        m.connectionChanged(.notRunning)
        XCTAssertEqual(m.disabledReason, "grantpin is not running. Start it from the menu bar item.")
        m.connectionChanged(.locked(lastError: nil))
        XCTAssertEqual(m.disabledReason, "Unlock your Mac to use grants.")
        m.connectionChanged(.notInitialized)
        XCTAssertNotNil(m.disabledReason)
        m.connectionChanged(.ready(readyStatus))
        XCTAssertNil(m.disabledReason)
    }

    func testListFailureWhileNotRunningIsQuietOtherwiseABanner() async {
        let f = FakeGrants()
        let m = model(f)
        f.listFailure = GrantpinError.notRunning
        await m.refresh()
        XCTAssertNil(m.banner)
        f.listFailure = GrantpinError.malformedResponse("x")
        await m.refresh()
        XCTAssertEqual(m.banner?.headline, "grantpin printed something unexpected.")
        f.listFailure = nil
        await m.refresh()
        XCTAssertNil(m.banner, "a good load clears a load banner")
    }

    func testTickMovesTheRelativeTexts() async {
        let f = FakeGrants()
        f.grants = [g("a", in: 1000)]
        var clock = now
        let m = GrantsViewModel(service: f, now: { clock })
        m.connectionChanged(.ready(readyStatus))
        await m.refresh()
        XCTAssertEqual(m.rows[0].timeLeft, "in 16 min")
        clock = clock.addingTimeInterval(900)
        m.tick()
        XCTAssertEqual(m.rows[0].timeLeft, "in 1 min")
        XCTAssertEqual(m.rows[0].badges, [.expiringSoon])
    }
}

final class CommandTokenizerTests: XCTestCase {
    func tokens(_ s: String) -> [String]? { try? CommandTokenizer.tokenize(s).get() }

    func testPlainAndQuoted() {
        XCTAssertEqual(tokens("php artisan migrate"), ["php", "artisan", "migrate"])
        XCTAssertEqual(tokens("  php   artisan  "), ["php", "artisan"])
        XCTAssertEqual(tokens(#"sh -c "echo hi there""#), ["sh", "-c", "echo hi there"])
        XCTAssertEqual(tokens("sh -c 'a \"b\" c'"), ["sh", "-c", "a \"b\" c"])
        XCTAssertEqual(tokens(#"a\ b c"#), ["a b", "c"])
        XCTAssertEqual(tokens(#""a \"q\" \\ b""#), [#"a "q" \ b"#])
        XCTAssertEqual(tokens("ab'cd'\"ef\""), ["abcdef"])
        XCTAssertEqual(tokens(""), [])
        XCTAssertEqual(tokens("   "), [])
        XCTAssertEqual(tokens("a\tb\nc"), ["a", "b", "c"])
    }

    func testNothingIsExpanded() {
        XCTAssertEqual(tokens("echo $HOME ~ * `x` $(y)"), ["echo", "$HOME", "~", "*", "`x`", "$(y)"])
    }

    func testEmptyQuotesMakeAnEmptyToken() {
        XCTAssertEqual(tokens("a '' b"), ["a", "", "b"])
    }

    func testUnterminatedQuote() {
        XCTAssertThrowsError(try CommandTokenizer.tokenize("a 'b").get())
        XCTAssertThrowsError(try CommandTokenizer.tokenize(#"a "b"#).get())
    }

    func testInterpreterPrefixes() {
        for w in ["sh", "bash", "zsh", "fish", "dash", "ksh", "env", "sudo", "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "npx", "npm", "yarn", "pnpm", "/bin/bash", "/usr/bin/env"] {
            XCTAssertTrue(CommandTokenizer.isInterpreterPrefix([w]), w)
        }
        XCTAssertFalse(CommandTokenizer.isInterpreterPrefix(["php", "artisan"]))
        XCTAssertFalse(CommandTokenizer.isInterpreterPrefix(["./deploy.sh"]))
        XCTAssertFalse(CommandTokenizer.isInterpreterPrefix(["make"]))
        XCTAssertFalse(CommandTokenizer.isInterpreterPrefix([]))
    }
}

final class SecretPatternTests: XCTestCase {
    func testSplit() {
        XCTAssertEqual(SecretPatterns.split("aws/*, DB_URL  api/key\nx"), ["aws/*", "DB_URL", "api/key", "x"])
        XCTAssertEqual(SecretPatterns.split("aws/{a,b},c"), ["aws/{a,b}", "c"])
        XCTAssertEqual(SecretPatterns.split(""), [])
        XCTAssertEqual(SecretPatterns.split(" , ,"), [])
    }

    func testIssues() {
        for ok in ["a", "aws/*", "aws/{a,b}", "db/[ab]?", "A_b.c-d", String(repeating: "x", count: 256)] {
            XCTAssertNil(SecretPatterns.issue(ok), ok)
        }
        for bad in ["", "a b", "a\\b", "é", "a;b", "a$b", "a:b", String(repeating: "x", count: 257), "a\u{0}"] {
            XCTAssertNotNil(SecretPatterns.issue(bad), bad.debugDescription)
        }
        XCTAssertTrue(SecretPatterns.isGlob("a*"))
        XCTAssertTrue(SecretPatterns.isGlob("a{b,c}"))
        XCTAssertFalse(SecretPatterns.isGlob("a/b"))
    }
}

final class StandingTTLTests: XCTestCase {
    func testPresets() {
        XCTAssertEqual(StandingTTL.hour1.seconds, 3600)
        XCTAssertEqual(StandingTTL.day1.seconds, 86_400)
        XCTAssertEqual(StandingTTL.days7.seconds, 7 * 86_400)
        XCTAssertEqual(StandingTTL.days30.seconds, 30 * 86_400)
        XCTAssertEqual(StandingTTL.days90.seconds, 7_776_000)
        XCTAssertEqual(StandingTTL.maxSeconds, 7_776_000)
        XCTAssertNil(StandingTTL.custom.seconds)
    }

    func testCustom() throws {
        XCTAssertEqual(try StandingTTL.parseCustom("7d").get(), 7 * 86_400)
        XCTAssertEqual(try StandingTTL.parseCustom(" 12H ").get(), 12 * 3600)
        XCTAssertEqual(try StandingTTL.parseCustom("90m").get(), 5400)
        XCTAssertEqual(try StandingTTL.parseCustom("1d12h").get(), 36 * 3600)
        XCTAssertEqual(try StandingTTL.parseCustom("90d").get(), StandingTTL.maxSeconds)
        func issue(_ s: String) -> StandingTTL.CustomIssue? {
            if case .failure(let i) = StandingTTL.parseCustom(s) { return i }
            return nil
        }
        XCTAssertEqual(issue(""), .empty)
        XCTAssertEqual(issue("   "), .empty)
        XCTAssertEqual(issue("abc"), .invalid)
        XCTAssertEqual(issue("12"), .invalid)
        XCTAssertEqual(issue("d"), .invalid)
        XCTAssertEqual(issue("1.5h"), .invalid)
        XCTAssertEqual(issue("1w"), .invalid)
        XCTAssertEqual(issue("0h"), .notPositive)
        XCTAssertEqual(issue("91d"), .tooLong)
        XCTAssertEqual(issue("2161h"), .tooLong)
        XCTAssertEqual(issue("99999999999999d"), .tooLong)
        XCTAssertEqual(StandingTTL.CustomIssue.tooLong.message, "A standing grant lasts 90 days at most.")
    }

    func testDurationText() {
        XCTAssertEqual(StandingTTL.durationText(seconds: 3600), "1 hour")
        XCTAssertEqual(StandingTTL.durationText(seconds: 7 * 86_400), "7 days")
        XCTAssertEqual(StandingTTL.durationText(seconds: 86_400 + 12 * 3600), "1 day 12 hours")
        XCTAssertEqual(StandingTTL.durationText(seconds: 2700), "45 minutes")
        XCTAssertEqual(StandingTTL.durationText(seconds: 30), "30 seconds")
    }
}

@MainActor
final class StandingGrantFormTests: XCTestCase {
    var dir = ""

    override func setUp() async throws {
        dir = "/tmp/gdf-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }
    override func tearDown() async throws { try? FileManager.default.removeItem(atPath: dir) }

    func form(_ f: FakeGrants = FakeGrants()) -> StandingGrantFormModel {
        let m = StandingGrantFormModel(service: f)
        m.chooseFolder(dir)
        m.patternsText = "DB_URL"
        m.commandText = "php artisan"
        return m
    }

    func testDefaultsAndRequiredFields() {
        let m = StandingGrantFormModel(service: FakeGrants())
        XCTAssertEqual(m.forCaller, "claude-code")
        XCTAssertEqual(m.ttl, .days30)
        XCTAssertFalse(m.isValid)
        XCTAssertEqual(m.folderMessage, "Choose the folder this grant covers.")
        XCTAssertEqual(m.secretsMessage, "Choose at least one secret, or type a pattern such as aws/*.")
        XCTAssertEqual(m.commandMessage, "Enter the command this grant allows, such as php artisan.")
        XCTAssertFalse(m.canSubmit)
        XCTAssertNil(m.request())
    }

    func testValidFormBuildsTheRequest() {
        let m = form()
        m.selectedSecrets = ["API_KEY"]
        m.ttl = .days7
        m.usesText = "20"
        XCTAssertTrue(m.isValid, "\(String(describing: m.folderMessage)) \(String(describing: m.secretsMessage))")
        let r = m.request()
        XCTAssertEqual(r, StandingGrantRequest(forCaller: "claude-code", cwd: dir, secrets: ["API_KEY", "DB_URL"],
                                               argv: ["php", "artisan"], ttlSeconds: 7 * 86_400, uses: 20))
    }

    func testCallerRules() {
        let m = form()
        for bad in ["", "   ", String(repeating: "x", count: 65), "a\u{7}b", "a\u{202E}b", "a\u{A0}b", "a\nb"] {
            m.forCaller = bad
            XCTAssertNotNil(m.callerMessage, bad.debugDescription)
            XCTAssertFalse(m.isValid)
        }
        for ok in ["claude-code", "cursor", "my tool", "Ünïcode", String(repeating: "x", count: 64)] {
            m.forCaller = ok
            XCTAssertNil(m.callerMessage, ok)
        }
        m.forCaller = "  claude-code  "
        XCTAssertEqual(m.request()?.forCaller, "claude-code", "trimmed")
    }

    func testFolderMustExist() {
        let m = form()
        m.chooseFolder(dir + "/missing")
        XCTAssertEqual(m.folderMessage, "That folder doesn't exist.")
        m.chooseFolder("relative/path")
        XCTAssertEqual(m.folderMessage, "The folder must be an absolute path.")
        let file = dir + "/f.txt"
        FileManager.default.createFile(atPath: file, contents: Data())
        m.chooseFolder(file)
        XCTAssertEqual(m.folderMessage, "That folder doesn't exist.")
        m.chooseFolder(dir)
        XCTAssertNil(m.folderMessage)
        XCTAssertEqual(m.folderResolved, realPath(dir), "the summary shows the symlink-resolved path the daemon will see")
    }

    func testSecretsLimitsAndGlobs() {
        let m = form()
        m.patternsText = "aws/*"
        XCTAssertTrue(m.hasGlob)
        XCTAssertNil(m.secretsMessage)
        m.patternsText = "bad name"
        XCTAssertNil(m.secretsMessage, "split on space: two entries, both valid")
        m.patternsText = "a\\b"
        XCTAssertNotNil(m.secretsMessage)
        m.patternsText = (0..<257).map { "s\($0)" }.joined(separator: ",")
        XCTAssertEqual(m.secretsMessage, "Too many secrets (256 max).")
        m.patternsText = ""
        m.selectedSecrets = []
        XCTAssertNotNil(m.secretsMessage)
    }

    func testChecklistAndPatternsMergeWithoutDuplicates() async {
        let f = FakeGrants()
        f.secrets = [SecretInfo(name: "A"), SecretInfo(name: "B"), SecretInfo(name: "C")]
        let m = form(f)
        await m.loadChoices()
        XCTAssertEqual(m.availableSecrets, ["A", "B", "C"])
        m.selectedSecrets = ["C", "A", "GONE"]
        m.patternsText = "A, aws/*"
        XCTAssertEqual(m.secretEntries, ["A", "C", "GONE", "aws/*"])
    }

    func testCommandRules() {
        let m = form()
        m.commandText = "php 'unterminated"
        XCTAssertEqual(m.commandMessage, "Close the quote.")
        m.commandText = "php ''"
        XCTAssertEqual(m.commandMessage, "The command can't contain an empty part.")
        m.commandText = "php artisan"
        XCTAssertNil(m.commandMessage)
        XCTAssertEqual(m.commandTokens, ["php", "artisan"])
        m.commandText = (0..<4097).map { "a\($0)" }.joined(separator: " ")
        XCTAssertEqual(m.commandMessage, "Too many parts (4,096 max).")
    }

    func testLifetimeRules() {
        let m = form()
        m.ttl = .days90
        XCTAssertEqual(m.ttlSeconds, 7_776_000)
        m.ttl = .custom
        XCTAssertNil(m.ttlSeconds)
        m.customTTL = ""
        XCTAssertNotNil(m.ttlMessage)
        XCTAssertFalse(m.isValid)
        m.customTTL = "91d"
        XCTAssertEqual(m.ttlMessage, "A standing grant lasts 90 days at most.")
        XCTAssertFalse(m.isValid)
        m.customTTL = "36h"
        XCTAssertEqual(m.ttlSeconds, 129_600)
        XCTAssertTrue(m.isValid)
    }

    func testUsesRules() {
        let m = form()
        m.usesText = ""
        XCTAssertNil(m.usesMessage); XCTAssertNil(m.uses)
        m.usesText = "5"
        XCTAssertNil(m.usesMessage); XCTAssertEqual(m.uses, 5)
        for bad in ["0", "-1", "1.5", "abc", "5 runs"] {
            m.usesText = bad
            XCTAssertNotNil(m.usesMessage, bad)
            XCTAssertFalse(m.isValid)
        }
    }

    func testAShellPrefixNeedsTheExtraTick() {
        let m = form()
        m.commandText = "bash"
        XCTAssertTrue(m.isRisky)
        XCTAssertEqual(m.riskText, "This lets claude-code run any code with these secrets")
        XCTAssertFalse(m.isValid)
        XCTAssertFalse(m.canSubmit)
        m.understood = true
        XCTAssertTrue(m.canSubmit)
        m.commandText = "bash deploy.sh"
        XCTAssertFalse(m.isRisky)
    }

    func testSummaryIsPlainLanguage() {
        let m = form()
        m.ttl = .days7
        m.patternsText = "aws/*, DB_URL"
        XCTAssertEqual(m.summary, "claude-code will be able to run \"php artisan …\" with aws/*, DB_URL in \(realPath(dir)) and its subfolders for 7 days, without asking you again.")
        m.usesText = "1"
        XCTAssertTrue(m.summary.hasSuffix(" It stops after 1 run."))
        m.usesText = "3"
        XCTAssertTrue(m.summary.hasSuffix(" It stops after 3 runs."))
    }

    func testKnownCallersFromTheAuditLog() {
        let rows = ["grantpin-app", "cursor", "claude-code", "cli", "cursor", "(invalid)", "windsurf", "a\u{202E}b", ""].enumerated().map {
            AuditEntry(id: "\($0.offset)", caller: $0.element, decision: "allowed_once")
        }
        XCTAssertEqual(StandingGrantFormModel.callers(from: rows), ["claude-code", "cursor", "windsurf"])
    }

    func testSubmitSendsExactlyOneAddAndReportsTheToast() async throws {
        let f = FakeGrants()
        let m = form(f)
        m.ttl = .hour1
        await m.submit()
        XCTAssertEqual(f.adds.count, 1)
        XCTAssertEqual(f.adds[0].ttlSeconds, 3600)
        guard case .created(let msg) = m.phase else { return XCTFail("phase \(m.phase)") }
        XCTAssertTrue(msg.hasPrefix("Standing grant created. claude-code can run \"php artisan\" with DB_URL in \(dir)"), msg)
        XCTAssertTrue(msg.hasSuffix("."))
        XCTAssertNil(m.error)
    }

    func testNothingIsSentWhileInvalid() async {
        let f = FakeGrants()
        let m = StandingGrantFormModel(service: f)
        await m.submit()
        XCTAssertTrue(f.adds.isEmpty)
        XCTAssertEqual(m.phase, .editing)
    }

    func testOnlyOneRequestAtATime() async throws {
        let f = FakeGrants()
        f.addDelay = 0.3
        let m = form(f)
        let first = m.start()
        XCTAssertNotNil(first)
        XCTAssertTrue(m.isWaiting)
        XCTAssertFalse(m.canSubmit)
        let second = m.start()
        await m.submit()  // also ignored while pending: returns the pending task
        await first?.value
        _ = second
        XCTAssertEqual(f.adds.count, 1, "no second add while one is pending")
    }

    func testCancelClosesTheRequestAndCreatesNothing() async throws {
        let f = FakeGrants()
        f.addDelay = 5
        let m = form(f)
        let t = m.start()
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertTrue(m.isWaiting)
        m.cancel()
        await t?.value
        XCTAssertEqual(m.phase, .editing)
        XCTAssertNil(m.error, "cancelling is not an error")
        XCTAssertTrue(f.addCancelled)
        XCTAssertTrue(f.grants.isEmpty)
    }

    func testOutcomeMessages() {
        func msg(_ cat: ErrorCategory, _ reason: ErrorReason, _ text: String = "") -> UserMessage {
            StandingGrantFormModel.message(for: daemonError(cat, reason, text))
        }
        let denied = msg(.denied, .userDenied)
        XCTAssertEqual(denied.headline, "Not created. You cancelled the confirmation.")
        XCTAssertEqual(denied.severity, .info)
        XCTAssertTrue(msg(.denied, .approverUnavailable).headline.hasPrefix("grantpin could not show the confirmation dialog."))
        let policy = msg(.refused, .policyRefused, "command not allowed by /p/.grantpin.yml")
        XCTAssertEqual(policy.headline, "A .grantpin.yml in that folder does not allow this:")
        XCTAssertEqual(policy.detail, "command not allowed by /p/.grantpin.yml")
        XCTAssertEqual(msg(.refused, .tierUnmet, "requires hardware").headline, "This secret needs a stronger protection level than this vault provides.")
        XCTAssertEqual(msg(.refused, .secretExpired).headline, "That secret has expired.")
        let missing = msg(.notFound, .secretNotFound, "secret not found: NOPE")
        XCTAssertEqual(missing.headline, "One of those secrets doesn't exist.")
        XCTAssertEqual(missing.detail, "secret not found: NOPE")
        let cap = msg(.badRequest, .badRequest, "ttl 91d exceeds the maximum standing grant lifetime of 90d (daemon maximum)")
        XCTAssertEqual(cap.headline, "ttl 91d exceeds the maximum standing grant lifetime of 90d (daemon maximum)", "verbatim, never clamped")
        XCTAssertNil(cap.detail)
        XCTAssertEqual(StandingGrantFormModel.message(for: GrantpinError.timeout).headline, "grantpin took too long to answer.")
    }

    func testFailureLeavesTheFormEditableWithTheError() async {
        let f = FakeGrants()
        f.addFailure = daemonError(.denied, .userDenied)
        let m = form(f)
        await m.submit()
        XCTAssertEqual(m.phase, .editing)
        XCTAssertEqual(m.error?.headline, "Not created. You cancelled the confirmation.")
        XCTAssertTrue(m.canSubmit, "the person can change the form and ask again")
    }

    func testPolicyCapErrorIsShownAsIs() async {
        let f = FakeGrants()
        f.addFailure = daemonError(.badRequest, .badRequest, "ttl 60d exceeds the maximum standing grant lifetime of 30d (max_standing_grant_ttl in /p/.grantpin.yml)")
        let m = form(f)
        m.ttl = .days90
        await m.submit()
        XCTAssertEqual(f.adds.last?.ttlSeconds, 7_776_000, "the request is not clamped locally")
        XCTAssertEqual(m.error?.headline, "ttl 60d exceeds the maximum standing grant lifetime of 30d (max_standing_grant_ttl in /p/.grantpin.yml)")
    }

    func testExplanationNamesTheDaemonDialogThenTouchID() {
        XCTAssertEqual(StandingGrantFormModel.explanation, "grantpin shows its own dialog next, then Touch ID. Nothing is created unless you approve both.")
        XCTAssertEqual(StandingGrantFormModel.waitingText, "Waiting for you to confirm in the grantpin dialog, then Touch ID.")
    }

    func testViewModelHandsOutTheFormAndShowsTheToast() async {
        let f = FakeGrants()
        let m = GrantsViewModel(service: f)
        m.connectionChanged(.ready(readyStatus))
        let form = m.makeStandingForm(initialFolder: dir, initialTTL: .days7)
        XCTAssertEqual(form.folder, dir)
        XCTAssertEqual(form.ttl, .days7)
        f.grants = [GrantInfo(id: "n", standing: true)]
        await m.formDidCreate("Standing grant created. x")
        XCTAssertEqual(m.notice, "Standing grant created. x")
        XCTAssertEqual(m.rows.map(\.id), ["n"])
    }
}

final class RememberedTTLTests: XCTestCase {
    func testOnlyPresetsAreRemembered() {
        for ttl in [StandingTTL.hour1, .day1, .days7, .days30, .days90] {
            XCTAssertEqual(StandingTTL.remembered(ttl.rawValue), ttl)
        }
    }

    func testAnythingElseFallsBackToTheDefault() {
        XCTAssertEqual(StandingTTL.defaultPreset, .days30)
        XCTAssertEqual(StandingTTL.remembered(nil), .days30)
        XCTAssertEqual(StandingTTL.remembered(StandingTTL.custom.rawValue), .days30, "a custom lifetime is not remembered")
        XCTAssertEqual(StandingTTL.remembered("days365"), .days30)
        XCTAssertEqual(StandingTTL.remembered(""), .days30)
        XCTAssertEqual(StandingTTL.remembered("7776000"), .days30)
    }
}
