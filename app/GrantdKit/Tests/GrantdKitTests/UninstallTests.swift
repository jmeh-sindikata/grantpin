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

    func model(control: ServiceControl? = FakeServiceControl(), tier: Tier? = .hardware, dev: Bool = false,
               answering: @escaping @Sendable () async -> Bool = { false }, keychain: FakeKeychain = FakeKeychain(),
               loginReset: @escaping @MainActor () -> Void = {}) -> UninstallModel {
        state(control: control, tier: tier, dev: dev, state: { await answering() ? .answering : .stopped },
              keychain: keychain, loginReset: loginReset)
    }

    func state(control: ServiceControl? = FakeServiceControl(), tier: Tier? = .hardware, dev: Bool = false,
               state: @escaping @Sendable () async -> DaemonState, keychain: FakeKeychain = FakeKeychain(),
               loginReset: @escaping @MainActor () -> Void = {}) -> UninstallModel {
        UninstallModel(control: control, secrets: 3, grants: 1, keystoreTier: tier, isDevelopment: dev,
                       vaultFolder: vault, logsFolder: logs, keychain: keychain, daemonState: state,
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
        XCTAssertEqual(UninstallModel.hardwareKeyLabel, "Delete the hardware key")
        XCTAssertEqual(UninstallModel.keyWarning, "Deleting the key makes the vault permanently unreadable, even if you keep the vault file.")
        XCTAssertEqual(UninstallModel.removeLabel, "Remove")
        XCTAssertEqual(UninstallModel.hardwareKeyNote, "The hardware key in your Keychain stays. It can't be exported and is useless without the vault file. To remove it, tick \"Delete the hardware key\" when you uninstall.")
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
        XCTAssertTrue(model(tier: .hardware).offersHardwareKey)
        XCTAssertFalse(model(tier: .dialog).offersHardwareKey)
        let hw = model(tier: .hardware)
        hw.stopService = false
        hw.deleteKeychainItem = true
        XCTAssertFalse(hw.canRemove, "an option that is not offered does not count")
        XCTAssertFalse(hw.needsTypedConfirmation)
        let weak = model(tier: .dialog)
        weak.stopService = false
        weak.deleteHardwareKey = true
        XCTAssertFalse(weak.canRemove, "the hardware key option is not offered for a Keychain vault")
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
        XCTAssertEqual(stopped, .stillRunning)
        XCTAssertEqual(polls.n, 51, "50 polls 0.1 s apart is 5 s, plus the last look")
        let quick = Counter()
        let m2 = model(answering: { quick.n += 1; return quick.n < 3 })
        let ok = await m2.waitForDaemonToStop()
        XCTAssertEqual(ok, .stopped)
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
        XCTAssertEqual(k.calls.all, [.fallback])
        XCTAssertTrue(r.succeeded)
        XCTAssertTrue(r.done.contains("The Keychain item was deleted."))
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

    func testDeletingAKeyAloneNeedsTheTypedWordAndShowsTheWarning() {
        let m = model(tier: .dialog)
        m.stopService = false
        m.deleteKeychainItem = true
        XCTAssertTrue(m.needsTypedConfirmation)
        XCTAssertTrue(m.showsKeyWarning)
        XCTAssertFalse(m.canRemove, "no typed word, no deletion")
        m.confirmationText = "delete"
        XCTAssertTrue(m.canRemove)
        let hw = model(tier: .hardware)
        hw.stopService = false
        hw.deleteHardwareKey = true
        XCTAssertTrue(hw.needsTypedConfirmation)
        XCTAssertFalse(hw.canRemove)
        hw.confirmationText = "delete"
        XCTAssertTrue(hw.canRemove)
        XCTAssertFalse(model().showsKeyWarning)
    }

    func testDeletingAKeyForcesStoppingTheService() async {
        let c = FakeServiceControl()
        let k = FakeKeychain()
        let m = model(control: c, tier: .dialog, keychain: k)
        m.stopService = false
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        XCTAssertTrue(m.stopIsForced)
        XCTAssertTrue(m.willStopService)
        await m.remove()
        XCTAssertEqual(c.uninstalls, 1)
        XCTAssertEqual(k.calls.all, [.fallback])
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.succeeded, r.problem ?? "")
        XCTAssertTrue(exists(vault.appendingPathComponent("vault.db")), "the vault file is not touched")
    }

    func testTheHardwareKeyIsDeletedOnlyWhenAsked() async {
        let k = FakeKeychain()
        let m = model(tier: .hardware, keychain: k)
        m.deleteVault = true
        m.deleteHardwareKey = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(k.calls.all, [.hardware])
        XCTAssertTrue(r.done.contains("The hardware key was deleted."))
        XCTAssertTrue(r.remains.isEmpty)
        let k2 = FakeKeychain()
        let m2 = model(tier: .hardware, keychain: k2)
        m2.deleteVault = true
        m2.confirmationText = "delete"
        await m2.remove()
        XCTAssertEqual(k2.calls.n, 0)
        guard case .finished(let r2) = m2.phase else { return XCTFail("\(m2.phase)") }
        XCTAssertEqual(r2.remains, [UninstallModel.hardwareKeyNote])
    }

    func testAKeyThatIsNotFoundIsReportedAsNotDeleted() async {
        let m = model(tier: .dialog, keychain: FakeKeychain(result: .notFound))
        m.deleteVault = true
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.succeeded)
        XCTAssertFalse(r.done.contains { $0.contains("Keychain item was deleted") }, "nothing was deleted, so no success line")
        XCTAssertEqual(r.notices, ["Keychain item was not found, so nothing was deleted. It may have been removed already."])
        XCTAssertTrue(r.remains.isEmpty, "there is nothing left to mention")
    }

    func testAKeyDeletionFailureIsReportedWithTheHelpersMessage() async {
        let m = model(tier: .dialog, keychain: FakeKeychain(result: .failed(detail: "keystore: access denied")))
        m.stopService = false
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "The Keychain item could not be deleted. keystore: access denied")
    }

    func testAHelperRefusalBecauseTheDaemonRunsIsReported() async {
        let k = FakeKeychain(result: .daemonRunning)
        let m = model(tier: .hardware, keychain: k)
        m.deleteHardwareKey = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "grantd is still running, so the hardware key was not deleted.")
    }

    func testAKeyIsNeverDeletedWhileTheDaemonAnswers() async {
        let k = FakeKeychain()
        let m = model(tier: .dialog, answering: { true }, keychain: k)
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        await m.remove()
        XCTAssertEqual(k.calls.n, 0)
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "grantd is still running, so the Keychain item was not deleted.")
    }

    func testTheHelperCommandForEachKey() {
        XCTAssertEqual(HelperKeystore.arguments(for: .fallback), ["keystore", "delete", "--fallback", "--yes"])
        XCTAssertEqual(HelperKeystore.arguments(for: .hardware), ["keystore", "delete", "--hardware", "--yes"])
        XCTAssertFalse(HelperKeystore.arguments(for: .fallback).contains("--force"))
        XCTAssertFalse(HelperKeystore.arguments(for: .hardware).contains("--force"))
    }

    func testTheHelperExitCodesAreRead() {
        func out(_ code: Int32, _ err: String = "", timedOut: Bool = false) -> HelperOutput {
            HelperOutput(exitCode: code, stdout: "", stderr: err, timedOut: timedOut)
        }
        XCTAssertEqual(HelperKeystore.interpret(out(0)), .deleted)
        XCTAssertEqual(HelperKeystore.interpret(out(3, "no such key")), .notFound)
        XCTAssertEqual(HelperKeystore.interpret(out(2, "daemon is running")), .daemonRunning)
        XCTAssertEqual(HelperKeystore.interpret(out(1, "boom\n")), .failed(detail: "boom"))
        XCTAssertEqual(HelperKeystore.interpret(out(1)), .failed(detail: nil))
        if case .failed = HelperKeystore.interpret(out(0, "", timedOut: true)) {} else { XCTFail("a timeout is a failure") }
    }

    /// The real runner against a scripted helper: no Keychain is touched.
    func testTheRealRunnerAgainstAScriptedHelper() async throws {
        let script = try temp.file("fake-grantd.sh", "#!/bin/sh\necho \"$@\" > \"$0.args\"\nif [ \"$3\" = --hardware ]; then echo 'no such key' >&2; exit 3; fi\nexit 0\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        let keystore = HelperKeystore(helper: script, environment: ["PATH": "/usr/bin:/bin"])
        let a = await keystore.deleteKey(.fallback)
        XCTAssertEqual(a, .deleted)
        XCTAssertEqual(try String(contentsOf: URL(fileURLWithPath: script.path + ".args"), encoding: .utf8), "keystore delete --fallback --yes\n")
        let b = await keystore.deleteKey(.hardware)
        XCTAssertEqual(b, .notFound)
        let missing = HelperKeystore(helper: URL(fileURLWithPath: "/nonexistent/grantd"))
        let c = await missing.deleteKey(.fallback)
        XCTAssertEqual(c, .failed(detail: nil))
    }

    // MARK: a status call that fails is not "stopped"

    func testOnlyNotRunningMeansStopped() {
        XCTAssertEqual(DaemonState.classify(GrantdError.notRunning), .stopped)
        XCTAssertEqual(DaemonState.classify(GrantdError.timeout), .unknown("grantd took too long to answer."))
        if case .unknown = DaemonState.classify(GrantdError.noResponse) {} else { XCTFail("a closed connection is not a stop") }
        if case .unknown = DaemonState.classify(GrantdError.io("Permission denied")) {} else { XCTFail("an I/O error is not a stop") }
        if case .unknown = DaemonState.classify(GrantdError.malformedResponse("x")) {} else { XCTFail() }
        if case .unknown = DaemonState.classify(CancellationError()) {} else { XCTFail() }
        XCTAssertEqual(DaemonState.classify(daemonError(.failed, .vaultLocked)), .answering, "an error response is an answer")
    }

    func testAnUnreachableSocketPathIsStoppedAndAnExistingFileIsNot() async throws {
        let gone = await DaemonState.probe(Client(socketPath: temp.url.appendingPathComponent("no.sock").path))
        XCTAssertEqual(gone, .stopped)
        // A file where the socket should be: connect() fails with ECONNREFUSED/ENOTSOCK-like errors.
        let file = try temp.file("not-a-socket")
        let other = await DaemonState.probe(Client(socketPath: file.path))
        XCTAssertNotEqual(other, .answering)
    }

    func testAStatusTimeoutKeepsTheVaultAndSaysSo() async {
        let m = state(state: { .unknown("grantd took too long to answer.") })
        m.deleteVault = true
        m.deleteLogs = true
        m.confirmationText = "delete"
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(r.problem, "Could not tell whether grantd has stopped (grantd took too long to answer.), so nothing was deleted.")
        XCTAssertFalse(r.vaultDeleted)
        XCTAssertTrue(exists(vault.appendingPathComponent("vault.db")))
        XCTAssertTrue(exists(logs), "later steps do not run after a problem")
    }

    func testAnUnknownStateEndsTheWaitAtOnce() async {
        final class Counter: @unchecked Sendable { var n = 0 }
        let polls = Counter()
        let m = state(state: { polls.n += 1; return polls.n < 3 ? .answering : .unknown("reset") })
        let result = await m.waitForDaemonToStop()
        XCTAssertEqual(result, .unknown("reset"))
        XCTAssertEqual(polls.n, 3)
    }

    func testAKeyIsNotDeletedOnAnUnknownDaemonState() async {
        let k = FakeKeychain()
        let m = state(tier: .dialog, state: { .unknown("timeout") }, keychain: k)
        m.deleteKeychainItem = true
        m.confirmationText = "delete"
        await m.remove()
        XCTAssertEqual(k.calls.n, 0)
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertNotNil(r.problem)
    }

    // MARK: no tier, no key options

    func testWithoutAKnownTierNoKeyOptionIsOffered() async {
        let k = FakeKeychain()
        let m = model(tier: nil, keychain: k)
        XCTAssertTrue(m.tierUnknown)
        XCTAssertFalse(m.offersKeychainItem)
        XCTAssertFalse(m.offersHardwareKey)
        m.stopService = false
        m.deleteKeychainItem = true
        m.deleteHardwareKey = true
        XCTAssertFalse(m.willDeleteKey)
        XCTAssertFalse(m.canRemove, "ticks of options that are not offered do not count")
        XCTAssertFalse(model(tier: .hardware).tierUnknown)
        m.stopService = true
        m.deleteVault = true
        m.confirmationText = "delete"
        await m.remove()
        XCTAssertEqual(k.calls.n, 0)
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.vaultDeleted)
        XCTAssertEqual(r.remains, [UninstallModel.unknownKeyNote], "it does not claim a hardware key that may not exist")
    }
}
