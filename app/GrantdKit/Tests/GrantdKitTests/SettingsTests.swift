import Foundation
import XCTest
@testable import GrantdKit

@MainActor
final class SettingsModelTests: XCTestCase {
    func model(control: ServiceControl? = FakeServiceControl(), login: LoginItemControl? = FakeLoginItem(),
               dev: String? = nil, location: AppLocation = .ok, onChanged: @escaping @MainActor () async -> Void = {}) -> SettingsModel {
        SettingsModel(control: control, loginItem: login, developmentSocket: dev, resolvedSocket: "/s.sock", location: location,
                      pathDetector: PathDetector(environment: [:], shellsFile: "/nonexistent"), onChanged: onChanged)
    }

    func testStatusRowsFollowServiceStatus() async {
        let c = FakeServiceControl()
        c.status = .success(ServiceStatus(installed: true, loaded: true, running: true, pid: 5, exePath: "/x/grantd", plistPath: "/p.plist"))
        let m = model(control: c)
        await m.refresh()
        XCTAssertTrue(m.backgroundServiceOn)
        XCTAssertEqual(m.service?.pid, 5)
        XCTAssertEqual(m.helperVersion, "v1")
        c.status = .success(ServiceStatus(installed: false))
        await m.refresh()
        XCTAssertFalse(m.backgroundServiceOn)
        c.status = .failure(.unexpected)
        await m.refresh()
        XCTAssertTrue(m.serviceUnreadable)
        XCTAssertNil(m.service)
    }

    func testStartRepairRestartAreServiceInstall() async {
        let c = FakeServiceControl()
        var changed = 0
        let m = model(control: c, onChanged: { changed += 1 })
        await m.install()
        XCTAssertEqual(c.installs.count, 1)
        XCTAssertNil(c.installs[0], "no explicit path: the shell's PATH is detected")
        XCTAssertEqual(m.lastResult?.summary, "grantd is running in the background.")
        XCTAssertEqual(changed, 1, "status is polled right away")
        XCTAssertFalse(m.isBusy)
    }

    func testStopServiceUsesTheConfirmationText() async {
        XCTAssertEqual(SettingsModel.stopConfirmation.title, "Stop the background service?")
        XCTAssertEqual(SettingsModel.stopConfirmation.message, "Agents will not be able to use grantd until you turn it back on. Your secrets and grants stay as they are.")
        XCTAssertEqual(SettingsModel.stopConfirmation.confirmLabel, "Stop Service")
        let c = FakeServiceControl()
        let m = model(control: c)
        await m.stopService()
        XCTAssertEqual(c.uninstalls, 1)
    }

    func testDevelopmentModeTouchesNothing() async {
        let c = FakeServiceControl()
        let l = FakeLoginItem()
        let m = model(control: c, login: l, dev: "/tmp/gd-dev/s.sock")
        XCTAssertEqual(m.developmentBanner, "Development socket: /tmp/gd-dev/s.sock")
        XCTAssertNotNil(m.controlsDisabledReason)
        await m.refresh()
        await m.install()
        await m.stopService()
        await m.applyPath()
        m.setStartAtLogin(true)
        XCTAssertEqual(c.installs.count + c.uninstalls, 0)
        XCTAssertEqual(l.registered, 0)
        XCTAssertNil(m.service)
        XCTAssertFalse(m.loginItemAvailable)
    }

    func testNoHelperAndWrongLocationDisableTheControls() async {
        XCTAssertEqual(model(control: nil).controlsDisabledReason, "The helper inside this app could not be found.")
        let c = FakeServiceControl()
        let m = model(control: c, location: .elsewhere)
        XCTAssertEqual(m.controlsDisabledReason, "Move grantd to your Applications folder first")
        await m.install()
        XCTAssertEqual(c.installs.count, 0)
        m.location = .ok
        XCTAssertNil(m.controlsDisabledReason)
    }

    func testPathIssues() {
        XCTAssertNil(SettingsModel.pathIssue("/opt/homebrew/bin:/usr/bin:/bin"))
        XCTAssertNil(SettingsModel.pathIssue("  /usr/bin  "))
        XCTAssertNotNil(SettingsModel.pathIssue(""))
        XCTAssertNotNil(SettingsModel.pathIssue(":::"))
        XCTAssertNotNil(SettingsModel.pathIssue("/usr/bin:relative/bin"))
        XCTAssertNotNil(SettingsModel.pathIssue("bin"))
        XCTAssertNotNil(SettingsModel.pathIssue("/usr/bin\n/bin"))
        XCTAssertNotNil(SettingsModel.pathIssue("/usr/bin:\u{1}/bin"))
        XCTAssertEqual(SettingsModel.pathLabel, "Where grantd looks for commands")
        XCTAssertEqual(SettingsModel.pathHelp, "Programs that agents run through grantd can only find commands in these folders.")
    }

    func testApplyPathReinstallsWithIt() async {
        let c = FakeServiceControl()
        let m = model(control: c)
        m.pathText = "/opt/homebrew/bin:/usr/bin"
        await m.applyPath()
        XCTAssertEqual(c.installs, ["/opt/homebrew/bin:/usr/bin"])
        m.pathText = "relative"
        await m.applyPath()
        XCTAssertEqual(c.installs.count, 1, "an invalid PATH is not applied")
        XCTAssertNotNil(m.pathMessage)
    }

    func testRedetectFillsTheField() async throws {
        let d = try ScriptDir()
        let sh = try d.script("myshell", #"printf '__GD_BEGIN__%s__GD_END__' "/opt/test/bin:/usr/bin""#)
        let shells = d.url.appendingPathComponent("shells")
        try "\(sh.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        let m = SettingsModel(control: FakeServiceControl(), loginItem: nil, developmentSocket: nil, resolvedSocket: "/s",
                              pathDetector: PathDetector(environment: ["SHELL": sh.path], shellsFile: shells.path))
        await m.redetectPath()
        XCTAssertEqual(m.pathText, "/opt/test/bin:/usr/bin")
        m.pathText = "/custom"
        await m.loadPathIfNeeded()
        XCTAssertEqual(m.pathText, "/custom", "loading does not overwrite what the person typed")
    }

    func testLoginItem() {
        let l = FakeLoginItem()
        let m = model(login: l)
        XCTAssertFalse(m.startAtLogin)
        m.setStartAtLogin(true)
        XCTAssertEqual(l.registered, 1)
        XCTAssertTrue(m.startAtLogin)
        m.setStartAtLogin(false)
        XCTAssertEqual(l.unregistered, 1)
        XCTAssertFalse(m.startAtLogin)
    }

    func testLoginItemNeedsApprovalAndFailures() {
        let l = FakeLoginItem()
        l.status = .requiresApproval
        let m = model(login: l)
        XCTAssertTrue(m.startAtLogin)
        XCTAssertTrue(m.loginNeedsApproval)
        XCTAssertEqual(SettingsModel.approvalNeeded, "Allow grantd in System Settings > General > Login Items")
        m.openLoginItemsSettings()
        XCTAssertEqual(l.settingsOpened, 1)
        struct Boom: Error {}
        let l2 = FakeLoginItem()
        l2.registerFailure = Boom()
        let m2 = model(login: l2)
        m2.setStartAtLogin(true)
        XCTAssertEqual(m2.loginError, "grantd could not be added to the login items.")
    }

    func testVersionRowAndRepairRestart() async {
        let c = FakeServiceControl()
        c.version = "v2"
        let m = model(control: c)
        m.connectionChanged(.ready(StatusResult(version: "v2", protoV: 1)))
        await m.refresh()
        XCTAssertNil(m.versionNote)
        XCTAssertNil(m.versionAction)
        m.connectionChanged(.ready(StatusResult(version: "v1", protoV: 1)))
        XCTAssertEqual(m.versionNote, "grantd was updated. Restart the background service to finish.")
        XCTAssertEqual(m.versionAction, "Restart")
        m.connectionChanged(.ready(StatusResult(version: "v2", protoV: 2)))
        XCTAssertEqual(m.versionNote, "This app and the background service are out of step.")
        XCTAssertEqual(m.versionAction, "Repair")
        m.connectionChanged(.notRunning)
        XCTAssertNil(m.versionNote)
    }
}

final class SecurityFactsTests: XCTestCase {
    func testHardwareVault() {
        let f = SecurityFacts(status: StatusResult(version: "0.2.0", protoV: 1, keystoreTier: .hardware, approverTier: .hardware, socket: "/s.sock"), resolvedSocket: "/other")
        XCTAssertEqual(f.version, "0.2.0")
        XCTAssertEqual(f.protocolVersion, "1")
        XCTAssertEqual(f.vaultProtection, "Secure Enclave (hardware)")
        XCTAssertEqual(f.approval, "Touch ID or your password")
        XCTAssertEqual(f.socket, "/s.sock")
    }

    func testKeychainOnlyAndFallbacks() {
        let f = SecurityFacts(status: StatusResult(keystoreTier: .dialog, approverTier: .dialog, socket: ""), resolvedSocket: "/resolved.sock")
        XCTAssertEqual(f.vaultProtection, "Keychain only (weaker)")
        XCTAssertEqual(f.approval, "A confirmation dialog")
        XCTAssertEqual(f.socket, "/resolved.sock")
        XCTAssertEqual(SecurityFacts(status: StatusResult(vaultInitialized: false), resolvedSocket: "/x").vaultProtection, "No vault yet")
        let none = SecurityFacts(status: nil, resolvedSocket: "/x\u{1B}")
        XCTAssertEqual(none.version, "Not running")
        XCTAssertFalse(none.socket.unicodeScalars.contains { $0.value == 0x1B })
    }

    func testTheFixedParagraph() {
        XCTAssertEqual(SecurityFacts.managingParagraph,
                       "Saving, replacing and deleting secrets does not ask for Touch ID, and neither does revoking a grant. Any program running as you can do those things. Touch ID protects using a secret, not managing the list. See THREAT-MODEL.md.")
    }

    func testAppPaths() {
        let home = URL(fileURLWithPath: "/Users/me")
        XCTAssertEqual(AppPaths.vaultFolder(home: home).path, "/Users/me/Library/Application Support/grantd")
        XCTAssertEqual(AppPaths.logsFolder(home: home).path, "/Users/me/Library/Logs/grantd")
    }
}
