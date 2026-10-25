import Foundation
import XCTest
@testable import GrantdKit

/// An in-memory daemon: enough of `set`, `update`, `delete`, `list`, `masked`
/// and `grants list` to drive the view models. Like the real client it zeroes
/// the value buffer it was given.
final class FakeService: SecretsService, AuditService, @unchecked Sendable {
    struct SetCall: Equatable {
        var name: String; var value: String; var tags: [String]; var url: String?; var notes: String?
        var expires: Date?; var minTier: Tier?; var overwrite: Bool
    }
    struct UpdateCall: Equatable {
        var name: String; var tags: [String]?; var url: String?; var notes: String?
        var expires: Date?; var minTier: Tier?; var clear: Set<ClearField>
    }

    private let lock = NSLock()
    var secrets: [SecretInfo]
    var grants: [GrantInfo] = []
    var audit = AuditList.empty
    private(set) var sets = [SetCall]()
    private(set) var updates = [UpdateCall]()
    private(set) var deletes = [String]()
    private(set) var maskedCalls = [String]()
    /// If set, the next call of that kind throws it.
    var failNext: [String: Error] = [:]
    var listFailure: Error?
    var maskedAnswer = "****abcd"
    var valuesSeen = [String]()

    init(secrets: [SecretInfo] = []) { self.secrets = secrets }

    private func failure(_ op: String) -> Error? { lock.withLock { failNext.removeValue(forKey: op) } }

    func listSecrets() async throws -> [SecretInfo] {
        if let e = lock.withLock({ listFailure }) { throw e }
        return lock.withLock { secrets }
    }
    func masked(_ name: String) async throws -> String {
        lock.withLock { maskedCalls.append(name) }
        if let e = failure("masked") { throw e }
        return maskedAnswer
    }
    func set(name: String, value: inout Data, tags: [String], url: String?, notes: String?, expires: Date?, minTier: Tier?, overwrite: Bool) async throws -> String {
        let text = String(decoding: value, as: UTF8.self)
        value.resetBytes(in: 0..<value.count)
        lock.withLock {
            sets.append(SetCall(name: name, value: text, tags: tags, url: url, notes: notes, expires: expires, minTier: minTier, overwrite: overwrite))
        }
        if let e = failure("set") { throw e }
        try lock.withLock {
            if secrets.contains(where: { $0.name == name }) && !overwrite {
                throw GrantdError.daemon(category: .badRequest, reason: .secretExists, message: "secret already exists (overwrite to replace)")
            }
            secrets.removeAll { $0.name == name }
            secrets.append(SecretInfo(name: name, tags: tags.sorted(), url: url ?? "", notes: notes ?? "", expiresAt: expires, minTier: minTier ?? .hardware))
            secrets.sort { $0.name < $1.name }
        }
        return "1"
    }
    func update(name: String, tags: [String]?, url: String?, notes: String?, expires: Date?, minTier: Tier?, clear: Set<ClearField>) async throws -> String {
        lock.withLock { updates.append(UpdateCall(name: name, tags: tags, url: url, notes: notes, expires: expires, minTier: minTier, clear: clear)) }
        if let e = failure("update") { throw e }
        try lock.withLock {
            guard let i = secrets.firstIndex(where: { $0.name == name }) else {
                throw GrantdError.daemon(category: .notFound, reason: .secretNotFound, message: "")
            }
            if let tags { secrets[i].tags = tags.sorted() }
            if let url { secrets[i].url = url }
            if let notes { secrets[i].notes = notes }
            if let expires { secrets[i].expiresAt = expires }
            if let minTier { secrets[i].minTier = minTier }
            if clear.contains(.tags) { secrets[i].tags = [] }
            if clear.contains(.url) { secrets[i].url = "" }
            if clear.contains(.notes) { secrets[i].notes = "" }
            if clear.contains(.expires) { secrets[i].expiresAt = nil }
        }
        return "2"
    }
    func delete(_ name: String) async throws -> String {
        lock.withLock { deletes.append(name) }
        if let e = failure("delete:\(name)") ?? failure("delete") { throw e }
        try lock.withLock {
            guard secrets.contains(where: { $0.name == name }) else {
                throw GrantdError.daemon(category: .notFound, reason: .secretNotFound, message: "")
            }
            secrets.removeAll { $0.name == name }
        }
        return "3"
    }
    func listGrants() async throws -> [GrantInfo] { lock.withLock { grants } }
    func listAudit(limit: Int?) async throws -> AuditList {
        if let e = failure("audit") { throw e }
        return lock.withLock { audit }
    }
}

extension AuditList {
    static let empty = try! JSONDecoder().decode(AuditList.self, from: Data("{}".utf8))
    static func make(_ entries: [AuditEntry], truncated: Bool = false) -> AuditList {
        let enc = entries.map { e -> [String: Any] in
            var d: [String: Any] = ["id": e.id, "ts": ISO8601DateFormatter().string(from: e.ts), "caller": e.caller, "cwd": e.cwd,
                                    "argv": e.argv, "secrets": e.secrets, "decision": e.decision, "grant_id": e.grantID,
                                    "duration_ms": e.durationMS, "reason": e.reason]
            if let c = e.exitCode { d["exit_code"] = c }
            return d
        }
        let json = try! JSONSerialization.data(withJSONObject: ["entries": enc, "truncated": truncated])
        return try! Wire.decoder.decode(AuditList.self, from: json)
    }
}

final class FakePasteboard: PasteboardAccess {
    var text: String?
    var changeCount = 1
    private(set) var cleared = 0
    func string() -> String? { text }
    func clearContents() { text = nil; changeCount += 1; cleared += 1 }
}

let readyStatus = StatusResult(version: "v", pid: 1, vaultInitialized: true, keystoreTier: .hardware, approverTier: .hardware, secrets: 1, activeGrants: 0)

// MARK: - the form

@MainActor
final class SecretFormModelTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    var cal: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }

    func form(_ service: FakeService = FakeService(), original: SecretInfo? = nil, existing: [String] = [], keystore: Tier = .hardware,
              pasteboard: PasteboardAccess? = nil) -> SecretFormModel {
        SecretFormModel(service: service, original: original, existingNames: Set(existing), keystoreTier: keystore,
                        pasteboard: pasteboard, now: { self.now }, calendar: cal)
    }

    // add

    func testAddStartsInvalidWithVaultDefault() {
        let f = form()
        XCTAssertEqual(f.mode, .add)
        XCTAssertEqual(f.tier, .vaultDefault)
        XCTAssertEqual(f.expiryKind, .never)
        XCTAssertFalse(f.canSave)
        XCTAssertNil(f.nameMessage, "no complaint about an empty field")
    }

    func testLiveNameValidation() {
        let f = form()
        f.name = "bad name"
        XCTAssertEqual(f.nameMessage, "Use letters, numbers, _ . - and / only.")
        f.name = "/a"
        XCTAssertEqual(f.nameMessage, "Can't start or end with /.")
        f.name = "a..b"
        XCTAssertEqual(f.nameMessage, "Can't contain ..")
        f.name = String(repeating: "a", count: 257)
        XCTAssertEqual(f.nameMessage, "Too long (256 characters max).")
        f.name = "aws/key"
        XCTAssertNil(f.nameMessage)
        f.value = "v"
        XCTAssertTrue(f.canSave)
    }

    func testSaveNeedsAValue() {
        let f = form()
        f.name = "k"
        XCTAssertFalse(f.canSave)
        f.value = "\n"
        XCTAssertFalse(f.canSave)
        f.value = String(repeating: "x", count: (1 << 20) + 1)
        XCTAssertFalse(f.canSave)
        XCTAssertEqual(f.valueMessage, "Too large: 1 MiB maximum.")
        f.value = "x"
        XCTAssertTrue(f.canSave)
    }

    func testAddSendsEverythingAndClearsTheValue() async throws {
        let svc = FakeService()
        let f = form(svc)
        f.name = "aws/key"
        f.value = "s3cr3t\n"
        f.tagsText = "prod, billing prod"
        f.url = " https://example.com "
        f.notes = "n"
        f.expiryKind = .days30
        f.tier = .dialog
        let ok = await f.save()
        XCTAssertTrue(ok)
        let call = try XCTUnwrap(svc.sets.first)
        XCTAssertEqual(call, FakeService.SetCall(name: "aws/key", value: "s3cr3t", tags: ["prod", "billing"], url: "https://example.com", notes: "n",
                                                 expires: now.addingTimeInterval(30 * 86_400), minTier: .dialog, overwrite: false))
        XCTAssertEqual(f.value, "", "the typed value is dropped after a save")
        XCTAssertEqual(f.savedName, "aws/key")
        XCTAssertFalse(f.isSaving)
    }

    func testAddOmitsEmptyOptionalFieldsAndTheVaultDefault() async throws {
        let svc = FakeService()
        let f = form(svc)
        f.name = "k"; f.value = "v"
        _ = await f.save()
        let c = try XCTUnwrap(svc.sets.first)
        XCTAssertNil(c.url); XCTAssertNil(c.notes); XCTAssertNil(c.expires); XCTAssertNil(c.minTier)
        XCTAssertEqual(c.tags, [])
    }

    func testExistingNameTurnsSaveIntoReplaceWithOverwrite() async throws {
        let svc = FakeService(secrets: [SecretInfo(name: "k")])
        let f = form(svc, existing: ["k"])
        f.name = "k"; f.value = "v"
        XCTAssertTrue(f.nameExists)
        XCTAssertEqual(f.saveTitle, "Replace…")
        XCTAssertEqual(f.replaceConfirmation, Confirmation.replace(name: "k"))
        _ = await f.save()
        XCTAssertEqual(svc.sets.first?.overwrite, true)
    }

    func testPlainAddSendsOverwriteFalseSoARaceIsAnError() async {
        let svc = FakeService(secrets: [SecretInfo(name: "k")])  // appeared after the list was loaded
        let f = form(svc, existing: [])
        f.name = "k"; f.value = "v"
        XCTAssertEqual(f.saveTitle, "Save")
        let ok = await f.save()
        XCTAssertFalse(ok)
        XCTAssertEqual(svc.sets.first?.overwrite, false)
        XCTAssertEqual(f.error?.headline, "A secret with this name already exists.")
        XCTAssertEqual(f.value, "v", "the value stays so the person can retry")
    }

    func testFailureKeepsTheSheetAndMapsTheError() async {
        let svc = FakeService()
        svc.failNext["set"] = GrantdError.daemon(category: .badRequest, reason: .badRequest, message: "value too large")
        let f = form(svc)
        f.name = "k"; f.value = "v"
        let ok = await f.save()
        XCTAssertFalse(ok)
        XCTAssertEqual(f.error?.headline, "grantd rejected the request:")
        XCTAssertEqual(f.error?.detail, "value too large")
        XCTAssertNil(f.savedName)
        XCTAssertEqual(f.value, "v")
    }

    func testTagValidationBlocksSave() {
        let f = form()
        f.name = "k"; f.value = "v"
        f.tagsText = "ok, no/slash"
        XCTAssertFalse(f.canSave)
        XCTAssertEqual(f.tagParse.message, "Tags can use letters, numbers, _ . - and : only.")
        f.tagsText = "ok"
        XCTAssertTrue(f.canSave)
    }

    func testURLAndNotesLimitsBlockSave() {
        let f = form()
        f.name = "k"; f.value = "v"
        f.url = String(repeating: "a", count: 2049)
        XCTAssertFalse(f.canSave)
        f.url = "https://x"
        f.notes = String(repeating: "n", count: 2049)
        XCTAssertFalse(f.canSave)
        f.notes = ""
        XCTAssertTrue(f.canSave)
        f.url = "not a url"
        XCTAssertEqual(f.urlNote, "This isn't a web address.")
        XCTAssertTrue(f.canSave, "the URL remark never blocks")
    }

    func testExpiryChoices() async throws {
        let svc = FakeService()
        let f = form(svc)
        f.name = "k"; f.value = "v"
        f.expiryKind = .date
        f.expiryDate = now.addingTimeInterval(-86_400)
        XCTAssertEqual(f.expiryMessage, "Choose a date in the future.")
        XCTAssertFalse(f.canSave)
        f.expiryDate = now.addingTimeInterval(2 * 86_400)
        XCTAssertTrue(f.canSave)
        f.expiryKind = .custom
        XCTAssertFalse(f.canSave, "nothing typed yet")
        f.expiryCustom = "12x"
        XCTAssertEqual(f.expiryMessage, "Use a number and a unit: 30d, 2w, 12h, 90m.")
        f.expiryCustom = "12h"
        XCTAssertNil(f.expiryMessage)
        _ = await f.save()
        XCTAssertEqual(svc.sets.first?.expires, now.addingTimeInterval(43_200))
    }

    func testHardwareIsDisabledWithoutASecureEnclaveKey() {
        let f = form(keystore: .dialog)
        XCTAssertFalse(f.isAllowed(.hardware))
        XCTAssertTrue(f.isAllowed(.dialog))
        XCTAssertTrue(f.isAllowed(.vaultDefault))
        f.name = "k"; f.value = "v"; f.tier = .hardware
        XCTAssertFalse(f.canSave)
        XCTAssertTrue(form(keystore: .hardware).isAllowed(.hardware))
    }

    func testTheAppNeverSendsTierNone() {
        for c in TierChoice.allCases { XCTAssertNotEqual(c.tier, .vaultDefault) }
        XCTAssertNil(TierChoice.vaultDefault.tier)
    }

    // clipboard

    func testPasteReadsTheClipboardOnceAndClearsItAfterSavingWhenUnchanged() async {
        let pb = FakePasteboard()
        pb.text = "pasted-secret"
        let f = form(pasteboard: pb)
        f.name = "k"
        f.paste()
        XCTAssertEqual(f.value, "pasted-secret")
        XCTAssertTrue(f.pastedFromClipboard)
        XCTAssertEqual(pb.cleared, 0, "paste alone clears nothing")
        _ = await f.save()
        XCTAssertEqual(pb.cleared, 1)
        XCTAssertNil(pb.text)
    }

    func testClipboardIsLeftAloneIfSomethingElseWasCopiedMeanwhile() async {
        let pb = FakePasteboard()
        pb.text = "pasted"
        let f = form(pasteboard: pb)
        f.name = "k"
        f.paste()
        pb.text = "something else"; pb.changeCount += 1
        _ = await f.save()
        XCTAssertEqual(pb.cleared, 0)
        XCTAssertEqual(pb.text, "something else")
    }

    func testClipboardIsLeftAloneWhenTheBoxIsUncheckedOrTheValueWasTyped() async {
        let pb = FakePasteboard()
        pb.text = "pasted"
        let f = form(pasteboard: pb)
        f.name = "k"
        f.paste()
        f.clearClipboardAfterSaving = false
        _ = await f.save()
        XCTAssertEqual(pb.cleared, 0)

        let g = form(pasteboard: pb)
        g.name = "k2"; g.value = "typed"
        _ = await g.save()
        XCTAssertEqual(pb.cleared, 0, "never clears unless the value came from a Paste click")
    }

    func testClipboardIsNotClearedWhenSavingFails() async {
        let pb = FakePasteboard(); pb.text = "p"
        let svc = FakeService(); svc.failNext["set"] = GrantdError.timeout
        let f = form(svc, pasteboard: pb)
        f.name = "k"; f.paste()
        _ = await f.save()
        XCTAssertEqual(pb.cleared, 0)
    }

    func testDiscardSensitiveDropsTheValue() {
        let f = form()
        f.value = "secret"; f.showCharacters = true
        f.discardSensitive()
        XCTAssertEqual(f.value, "")
        XCTAssertFalse(f.showCharacters)
    }

    // edit details

    func original(tier: Tier = .dialog, expires: Date? = nil) -> SecretInfo {
        SecretInfo(name: "aws/key", tags: ["a", "b"], url: "https://old", notes: "old notes", expiresAt: expires, minTier: tier)
    }

    func testEditPrefillsAndStartsUnchanged() {
        let f = form(original: original(expires: now.addingTimeInterval(5 * 86_400)))
        XCTAssertEqual(f.mode, .editDetails)
        XCTAssertEqual(f.name, "aws/key")
        XCTAssertFalse(f.nameIsEditable)
        XCTAssertEqual(f.tagsText, "a, b")
        XCTAssertEqual(f.url, "https://old")
        XCTAssertEqual(f.expiryKind, .date)
        XCTAssertEqual(f.tier, .dialog)
        XCTAssertFalse(f.canSave, "nothing changed")
        XCTAssertFalse(f.needsValue)
    }

    func testEditSendsOnlyWhatChanged() async throws {
        let svc = FakeService(secrets: [original()])
        let f = form(svc, original: original())
        f.tagsText = "a, b, c"
        XCTAssertTrue(f.canSave)
        _ = await f.save()
        let u = try XCTUnwrap(svc.updates.first)
        XCTAssertEqual(u, FakeService.UpdateCall(name: "aws/key", tags: ["a", "b", "c"], url: nil, notes: nil, expires: nil, minTier: nil, clear: []))
        XCTAssertTrue(svc.sets.isEmpty, "editing details never sends a value")
    }

    func testEditReorderedTagsAreNotAChange() {
        let f = form(original: original())
        f.tagsText = "b, a"
        XCTAssertFalse(f.canSave)
    }

    func testEditClearsFieldsThroughClear() async throws {
        let exp = now.addingTimeInterval(10 * 86_400)
        let svc = FakeService(secrets: [original(expires: exp)])
        let f = form(svc, original: original(expires: exp))
        f.tagsText = ""
        f.url = ""
        f.notes = ""
        f.expiryKind = .never
        _ = await f.save()
        let u = try XCTUnwrap(svc.updates.first)
        XCTAssertEqual(u.clear, [.tags, .url, .notes, .expires])
        XCTAssertNil(u.tags); XCTAssertNil(u.url); XCTAssertNil(u.notes); XCTAssertNil(u.expires)
    }

    func testEditSetsANewExpiry() async throws {
        let svc = FakeService(secrets: [original()])
        let f = form(svc, original: original())
        f.expiryKind = .days90
        _ = await f.save()
        XCTAssertEqual(svc.updates.first?.expires, now.addingTimeInterval(90 * 86_400))
    }

    func testAnExpiredSecretCanBeEditedWithoutTouchingItsExpiry() {
        let f = form(original: original(expires: now.addingTimeInterval(-86_400)))
        f.notes = "changed"
        XCTAssertNil(f.expiryMessage)
        XCTAssertTrue(f.canSave)
    }

    func testRaisingTheTierDoesNotWarn() async throws {
        let svc = FakeService(secrets: [original(tier: .dialog)])
        let f = form(svc, original: original(tier: .dialog))
        f.tier = .hardware
        XCTAssertFalse(f.tierIsLowering)
        XCTAssertNil(f.lowerTierNote)
        _ = await f.save()
        XCTAssertEqual(svc.updates.first?.minTier, .hardware)
    }

    func testLoweringTheTierWarnsThatADialogAndTouchIDFollow() async throws {
        let svc = FakeService(secrets: [original(tier: .hardware)])
        let f = form(svc, original: original(tier: .hardware))
        f.tier = .dialog
        XCTAssertTrue(f.tierIsLowering)
        XCTAssertEqual(f.lowerTierNote, "Lowering the protection asks for confirmation: a dialog first, then Touch ID. Nothing changes unless you approve both.")
        _ = await f.save()
        XCTAssertEqual(svc.updates.first?.minTier, .dialog)
    }

    func testTheTierIsOnlySentWhenItChanged() async {
        let svc = FakeService(secrets: [original(tier: .hardware)])
        let f = form(svc, original: original(tier: .hardware))
        f.notes = "x"
        _ = await f.save()
        XCTAssertNil(svc.updates.first?.minTier, "sending min_tier would use the long timeout and may show a dialog")
    }

    func testEditCancelledLowering() async {
        let svc = FakeService(secrets: [original(tier: .hardware)])
        svc.failNext["update"] = GrantdError.daemon(category: .denied, reason: .userDenied, message: "")
        let f = form(svc, original: original(tier: .hardware))
        f.tier = .dialog
        let ok = await f.save()
        XCTAssertFalse(ok)
        XCTAssertEqual(f.error?.headline, "You cancelled the confirmation.")
    }

    // replace value

    func testReplaceValueUsesSetWithOverwriteAndKeepsMetadata() async throws {
        let exp = now.addingTimeInterval(10 * 86_400)
        let o = original(tier: .hardware, expires: exp)
        let svc = FakeService(secrets: [o])
        let f = form(svc, original: o)
        f.mode = .replaceValue
        XCTAssertTrue(f.needsValue)
        XCTAssertFalse(f.tierIsEditable)
        XCTAssertFalse(f.canSave, "needs a value")
        XCTAssertEqual(f.saveTitle, "Replace…")
        XCTAssertEqual(f.replaceConfirmation, Confirmation.replace(name: "aws/key"))
        f.value = "new-value"
        XCTAssertTrue(f.canSave)
        _ = await f.save()
        let c = try XCTUnwrap(svc.sets.first)
        XCTAssertEqual(c.name, "aws/key")
        XCTAssertEqual(c.value, "new-value")
        XCTAssertTrue(c.overwrite)
        XCTAssertEqual(c.tags, ["a", "b"])
        XCTAssertEqual(c.url, "https://old")
        XCTAssertEqual(c.notes, "old notes")
        XCTAssertEqual(c.minTier, .hardware)
        XCTAssertEqual(try XCTUnwrap(c.expires).timeIntervalSince(exp), 0, accuracy: 86_400, "the same day, end of day")
        XCTAssertTrue(svc.updates.isEmpty)
    }

    func testSwitchingModeDropsTheTypedValue() {
        let f = form(original: original())
        f.mode = .replaceValue
        f.value = "typed"
        f.mode = .editDetails
        XCTAssertEqual(f.value, "")
    }
}

// MARK: - the window

@MainActor
final class SecretsViewModelTests: XCTestCase {
    func vm(_ svc: FakeService) -> SecretsViewModel {
        let m = SecretsViewModel(service: svc, now: { Date(timeIntervalSince1970: 1_800_000_000) })
        m.connectionChanged(.ready(readyStatus))
        return m
    }

    func testRefreshLoadsAndSortsByName() async {
        let svc = FakeService(secrets: [SecretInfo(name: "b"), SecretInfo(name: "a10"), SecretInfo(name: "a2")])
        let m = vm(svc)
        await m.refresh()
        XCTAssertEqual(m.visibleSecrets.map(\.name), ["a2", "a10", "b"])
        m.sortAscending = false
        XCTAssertEqual(m.visibleSecrets.map(\.name), ["b", "a10", "a2"])
        XCTAssertTrue(m.hasLoaded)
    }

    func testSearchMatchesNameAndTagsCaseInsensitively() async {
        let svc = FakeService(secrets: [SecretInfo(name: "aws/key", tags: ["prod"]), SecretInfo(name: "db", tags: ["Billing"]), SecretInfo(name: "x", url: "https://aws.example")])
        let m = vm(svc)
        await m.refresh()
        m.searchText = "AWS"
        XCTAssertEqual(m.visibleSecrets.map(\.name), ["aws/key"], "the URL is not searched")
        m.searchText = "billing"
        XCTAssertEqual(m.visibleSecrets.map(\.name), ["db"])
        m.searchText = "zzz"
        XCTAssertEqual(m.emptyState, .noMatches)
        m.searchText = "  "
        XCTAssertEqual(m.visibleSecrets.count, 3)
    }

    func testEmptyState() async {
        let m = vm(FakeService())
        XCTAssertEqual(m.emptyState, .none, "not loaded yet")
        await m.refresh()
        XCTAssertEqual(m.emptyState, .noSecrets)
    }

    func testDisabledWhenTheDaemonIsNotUsable() {
        let m = SecretsViewModel(service: FakeService())
        XCTAssertFalse(m.isEnabled)
        XCTAssertEqual(m.disabledReason, "Checking grantd…")
        m.connectionChanged(.notRunning)
        XCTAssertEqual(m.disabledReason, "grantd is not running. Start it from the menu bar item.")
        m.connectionChanged(.locked(lastError: nil))
        XCTAssertEqual(m.disabledReason, "Unlock your Mac to use secrets.")
        m.connectionChanged(.notInitialized)
        XCTAssertEqual(m.disabledReason, "There is no vault yet. Create one from the menu bar item.")
        m.connectionChanged(.ready(readyStatus))
        XCTAssertNil(m.disabledReason)
        XCTAssertTrue(m.isEnabled)
    }

    func testBecomingReadyReloads() async throws {
        let svc = FakeService(secrets: [SecretInfo(name: "a")])
        let m = SecretsViewModel(service: svc)
        m.connectionChanged(.ready(readyStatus))
        for _ in 0..<50 where !m.hasLoaded { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(m.secrets.map(\.name), ["a"])
    }

    func testListFailureWhileDownIsNotABanner() async {
        let svc = FakeService()
        svc.listFailure = GrantdError.notRunning
        let m = vm(svc)
        await m.refresh()
        XCTAssertNil(m.banner)
        svc.listFailure = GrantdError.daemon(category: .failed, reason: .internalError, message: "")
        await m.refresh()
        XCTAssertEqual(m.banner?.headline, "grantd had an internal error. Details are in the log.")
        svc.listFailure = nil
        await m.refresh()
        XCTAssertNil(m.banner, "a good load clears the load-failure banner")
    }

    func testSelectionDropsNamesThatDisappear() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a"), SecretInfo(name: "b")])
        let m = vm(svc)
        await m.refresh()
        m.selection = ["a", "b"]
        svc.secrets.removeAll { $0.name == "b" }
        await m.refresh()
        XCTAssertEqual(m.selection, ["a"])
        XCTAssertEqual(m.detailSecret?.name, "a")
    }

    func testMaskedOnDemand() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a")])
        let m = vm(svc)
        await m.refresh()
        XCTAssertEqual(m.masked, .idle)
        XCTAssertTrue(svc.maskedCalls.isEmpty, "never asked until clicked")
        await m.checkLastCharacters(of: "a")
        XCTAssertEqual(m.masked, .value("****abcd"))
        m.resetMasked()
        XCTAssertEqual(m.masked, .idle)
        svc.failNext["masked"] = GrantdError.daemon(category: .notFound, reason: .secretNotFound, message: "")
        await m.checkLastCharacters(of: "a")
        XCTAssertEqual(m.masked, .failed(UserMessage("That secret no longer exists.", refreshAdvised: true)))
    }

    func testFormDidSaveRefreshesAndSelects() async {
        let svc = FakeService()
        let m = vm(svc)
        await m.refresh()
        let f = m.makeAddForm()
        f.name = "new/key"; f.value = "v"
        let ok = await f.save()
        XCTAssertTrue(ok)
        await m.formDidSave(name: "new/key")
        XCTAssertEqual(m.secrets.map(\.name), ["new/key"])
        XCTAssertEqual(m.selection, ["new/key"])
    }

    func testFormsKnowExistingNamesAndTheKeystore() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a")])
        let m = SecretsViewModel(service: svc)
        m.connectionChanged(.ready(StatusResult(keystoreTier: .dialog)))
        await m.refresh()
        let f = m.makeAddForm()
        f.name = "a"
        XCTAssertTrue(f.nameExists)
        XCTAssertFalse(f.isAllowed(.hardware))
    }

    // delete

    func testDeleteConfirmationMentionsActiveGrants() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a")])
        svc.grants = [GrantInfo(id: "g1", secrets: ["a"]), GrantInfo(id: "g2", secrets: ["a", "b"]), GrantInfo(id: "g3", secrets: ["aws/*"]),
                      GrantInfo(id: "g4", secrets: ["a"], tampered: true)]
        let m = vm(svc)
        let c = await m.deleteConfirmation(for: ["a"])
        XCTAssertEqual(c.title, "Delete \"a\"?")
        XCTAssertTrue(c.message.hasSuffix("2 active grants mention this secret. They stay in place but won't work until you add it again."))
        let many = await m.deleteConfirmation(for: ["a", "b"])
        XCTAssertEqual(many.title, "Delete 2 secrets?")
    }

    func testDeleteRefreshesAndClearsSelection() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a"), SecretInfo(name: "b")])
        let m = vm(svc)
        await m.refresh()
        m.selection = ["a"]
        let ok = await m.delete(names: ["a"])
        XCTAssertTrue(ok)
        XCTAssertEqual(m.secrets.map(\.name), ["b"])
        XCTAssertTrue(m.selection.isEmpty)
        XCTAssertEqual(svc.deletes, ["a"])
    }

    func testMultiDeleteStopsAtTheFirstFailureAndSaysWhatWasDeleted() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a"), SecretInfo(name: "b"), SecretInfo(name: "c")])
        svc.failNext["delete:b"] = GrantdError.daemon(category: .failed, reason: .internalError, message: "")
        let m = vm(svc)
        await m.refresh()
        let ok = await m.delete(names: ["a", "b", "c"])
        XCTAssertFalse(ok)
        XCTAssertEqual(svc.deletes, ["a", "b"], "c is not attempted")
        XCTAssertEqual(m.secrets.map(\.name), ["b", "c"])
        XCTAssertEqual(m.banner?.detail, "Deleted before the problem: a.")
    }

    func testDeletingSomethingAlreadyGoneRefreshes() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a")])
        let m = vm(svc)
        await m.refresh()
        svc.secrets = []
        let ok = await m.delete(names: ["a"])
        XCTAssertFalse(ok)
        XCTAssertEqual(m.banner?.headline, "That secret no longer exists.")
        XCTAssertTrue(m.secrets.isEmpty)
    }

    func testEditThenRefreshShowsTheNewMetadata() async {
        let svc = FakeService(secrets: [SecretInfo(name: "a", tags: ["x"])])
        let m = vm(svc)
        await m.refresh()
        let f = m.makeEditForm(for: m.secret(named: "a")!)
        f.tagsText = "x, y"
        let ok = await f.save()
        XCTAssertTrue(ok)
        await m.formDidSave(name: "a")
        XCTAssertEqual(m.secret(named: "a")?.tags, ["x", "y"])
    }
}
