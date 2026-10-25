import Foundation
import XCTest
@testable import GrantdKit

@MainActor
final class UninstallModelTests: XCTestCase {
    var temp: TempDir!
    var vault: URL { temp.url.appendingPathComponent("Application Support/grantd") }
    var logs: URL { temp.url.appendingPathComponent("Logs/grantd") }

    override func setUpWithError() throws {
        temp = try TempDir()
        for f in ["vault.db", "vault.db-wal", "vault.db-shm", "grantd.sock"] { _ = try temp.file("Application Support/grantd/\(f)") }
        for f in ["daemon.err.log", "daemon.out.log"] { _ = try temp.file("Logs/grantd/\(f)") }
    }

    func model(control: ServiceControl? = FakeServiceControl(), tier: Tier = .hardware, dev: Bool = false,
               answering: @escaping @Sendable () async -> Bool = { false }, keychain: FakeKeychain = FakeKeychain(),
               loginReset: @escaping @MainActor () -> Void = {}) -> UninstallModel {
        UninstallModel(control: control, secrets: 3, grants: 1, keystoreTier: tier, isDevelopment: dev,
                       vaultFolder: vault, logsFolder: logs, keychain: keychain, isDaemonAnswering: answering,
                       sleep: { _ in }, unregisterLoginItem: loginReset)
    }

    func exists(_ u: URL) -> Bool { FileManager.default.fileExists(atPath: u.path) }

    func testTheSheetTexts() {
        let m = model()
        XCTAssertEqual(UninstallModel.stopLabel, "Stop and remove the background service")
        XCTAssertEqual(m.deleteVaultLabel, "Delete my vault: 3 secrets, 1 grant and the audit log")
        XCTAssertEqual(UninstallModel.logsLabel, "Delete logs")
        XCTAssertEqual(UninstallModel.keychainLabel, "Delete the Keychain item used by weaker protection")
        XCTAssertEqual(UninstallModel.deleteWarning, "Deleting the vault permanently removes all secrets, grants and the audit log. grantd does not keep a copy and this can't be undone.")
        XCTAssertEqual(UninstallModel.confirmationPrompt, "Type \"delete\" to confirm.")
        XCTAssertEqual(UninstallModel.removeLabel, "Remove")
        XCTAssertEqual(UninstallModel.hardwareKeyNote, "The hardware key in your Keychain stays. It can't be exported and is useless without the vault file. grantd has no command to remove it yet.")
        XCTAssertEqual(UninstallModel.disconnectCommand, "claude mcp remove grantd")
        XCTAssertEqual(UninstallModel.trashText, "To finish, drag grantd to the Trash.")
    }

    func testNothingDestructiveIsPreTickedExceptStoppingTheService() {
        let m = model()
        XCTAssertTrue(m.stopService)
        XCTAssertFalse(m.deleteVault)
        XCTAssertFalse(m.deleteLogs)
        XCTAssertFalse(m.deleteKeychainItem)
        XCTAssertTrue(m.canRemove)
    }

    func testDeletingTheVaultNeedsTheTypedWord() {
        let m = model()
        m.deleteVault = true
        XCTAssertTrue(m.needsTypedConfirmation)
        XCTAssertFalse(m.canRemove)
        m.confirmationText = "Delete"
        XCTAssertFalse(m.canRemove)
        m.confirmationText = "delete "
        XCTAssertFalse(m.canRemove)
        m.confirmationText = "delete"
        XCTAssertTrue(m.canRemove)
    }

    func testDeletingTheVaultForcesStoppingTheService() {
        let m = model()
        m.stopService = false
        m.deleteVault = true
        XCTAssertTrue(m.stopIsForced)
        XCTAssertTrue(m.willStopService)
    }

    func testKeychainOptionOnlyForWeakerProtection() {
        XCTAssertFalse(model(tier: .hardware).offersKeychainItem)
        XCTAssertTrue(model(tier: .dialog).offersKeychainItem)
        let hw = model(tier: .hardware)
        hw.stopService = false
        hw.deleteKeychainItem = true
        XCTAssertFalse(hw.canRemove, "an option that is not offered does not count")
    }

    func testNothingChosenMeansNothingToRemove() {
        let m = model()
        m.stopService = false
        XCTAssertFalse(m.canRemove)
    }

    func testDevelopmentModeAndNoHelperDisable() {
        XCTAssertFalse(model(dev: true).canRemove)
        XCTAssertNotNil(model(dev: true).disabledReason)
        XCTAssertFalse(model(control: nil).canRemove)
    }

    func testStopOnlyKeepsEverythingElse() async {
        let c = FakeServiceControl()
        var loginReset = 0
        let m = model(control: c, loginReset: { loginReset += 1 })
        await m.remove()
        XCTAssertEqual(c.uninstalls, 1)
        XCTAssertEqual(loginReset, 1)
        XCTAssertTrue(exists(vault.appendingPathComponent("vault.db")))
        XCTAssertTrue(exists(logs))
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.succeeded)
        XCTAssertFalse(r.vaultDeleted)
        XCTAssertEqual(r.done, ["The background service was stopped and removed."])
        XCTAssertEqual(r.remains.count, 1)
        XCTAssertTrue(r.remains[0].hasPrefix("Your vault is still in "))
    }

    func testDeleteEverythingInOrder() async {
        let c = FakeServiceControl()
        let m = model(control: c)
        m.deleteVault = true
        m.deleteLogs = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.succeeded, r.problem ?? "")
        XCTAssertTrue(r.vaultDeleted)
        XCTAssertFalse(exists(vault), "the emptied vault folder is removed")
        XCTAssertFalse(exists(logs))
        XCTAssertEqual(r.remains, [UninstallModel.hardwareKeyNote])
        XCTAssertEqual(r.done.count, 3)
    }

    func testOnlyKnownFilesAreRemoved() async throws {
        _ = try temp.file("Application Support/grantd/other-tool.txt")
        try FileManager.default.createDirectory(at: vault.appendingPathComponent("sub"), withIntermediateDirectories: true)
        let m = model()
        m.deleteVault = true
        m.confirmationText = "delete"
        await m.remove()
        XCTAssertFalse(exists(vault.appendingPathComponent("vault.db")))
        XCTAssertFalse(exists(vault.appendingPathComponent("grantd.sock")))
        XCTAssertTrue(exists(vault.appendingPathComponent("other-tool.txt")), "files that are not grantd's stay")
        XCTAssertTrue(exists(vault), "a folder that is not empty stays")
    }

    func testASymlinkNamedLikeAVaultFileIsRemovedNotFollowed() async throws {
        let outside = try temp.file("precious.txt", "keep me")
        try FileManager.default.removeItem(at: vault.appendingPathComponent("vault.db-wal"))
        try FileManager.default.createSymbolicLink(at: vault.appendingPathComponent("vault.db-wal"), withDestinationURL: outside)
        let m = model()
        m.deleteVault = true
        m.confirmationText = "delete"
        await m.remove()
        XCTAssertTrue(exists(outside))
        XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "keep me")
    }

    func testAFailedStopNeverDeletesTheVault() async {
        let c = FakeServiceControl()
        c.uninstallResult = ActionResult(outcome: .failed, summary: "The background service could not be stopped.")
        let m = model(control: c)
        m.deleteVault = true
        m.deleteLogs = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertFalse(r.succeeded)
        XCTAssertEqual(r.problem, "The background service could not be stopped.")
        XCTAssertTrue(exists(vault.appendingPathComponent("vault.db")))
        XCTAssertTrue(exists(logs), "later steps do not run after a failure")
    }

    func testADaemonThatKeepsAnsweringKeepsTheVault() async {
        let m = model(answering: { true })
        m.deleteVault = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "grantd is still running, so the vault was not deleted.")
        XCTAssertFalse(r.vaultDeleted)
        XCTAssertTrue(exists(vault.appendingPathComponent("vault.db")))
    }

    func testTheWaitForTheDaemonIsBounded() async {
        final class Counter: @unchecked Sendable { var n = 0 }
        let polls = Counter()
        let m = model(answering: { polls.n += 1; return true })
        let stopped = await m.waitForDaemonToStop()
        XCTAssertFalse(stopped)
        XCTAssertEqual(polls.n, 51, "50 polls 0.1 s apart is 5 s, plus the last look")
        let quick = Counter()
        let m2 = model(answering: { quick.n += 1; return quick.n < 3 })
        let ok = await m2.waitForDaemonToStop()
        XCTAssertTrue(ok)
        XCTAssertEqual(quick.n, 3)
    }

    func testKeychainItemForWeakerProtection() async {
        let k = FakeKeychain()
        let m = model(tier: .dialog, keychain: k)
        m.deleteVault = true
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(k.calls.n, 1)
        XCTAssertTrue(r.succeeded)
        XCTAssertTrue(r.remains.isEmpty, "the key item is gone; there is no hardware key")
    }

    func testWeakerProtectionKeychainItemStaysIfNotTicked() async {
        let k = FakeKeychain()
        let m = model(tier: .dialog, keychain: k)
        m.deleteVault = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(k.calls.n, 0)
        XCTAssertEqual(r.remains, [UninstallModel.keychainItemNote])
    }

    func testKeychainFailureIsReported() async {
        let m = model(tier: .dialog, keychain: FakeKeychain(succeeds: false))
        m.stopService = false
        m.deleteKeychainItem = true
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "The Keychain item could not be deleted.")
    }

    func testTheSecurityCommand() {
        XCTAssertEqual(SecurityToolKeychain.arguments, ["delete-generic-password", "-s", "dev.grantd", "-a", "vault-kek"])
    }
}
