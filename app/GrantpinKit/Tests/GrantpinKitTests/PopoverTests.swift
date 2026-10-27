import Foundation
import XCTest
@testable import GrantpinKit

final class StatusLineTests: XCTestCase {
    func testChecking() {
        let l = StatusLine.from(nil)
        XCTAssertEqual(l.headline, "Checking…")
        XCTAssertEqual(l.level, .neutral)
        XCTAssertNil(l.button)
    }

    func testNotRunningOffersStart() {
        let l = StatusLine.from(.notRunning)
        XCTAssertEqual(l.headline, "Daemon not running")
        XCTAssertEqual(l.level, .error)
        XCTAssertEqual(l.button, .startService)
    }

    func testNotRunningBecauseThePathIsTooLong() {
        let l = StatusLine.from(.notRunning, lastError: .socketPathTooLong(120))
        XCTAssertEqual(l.detail, "Your account name is too long for grantpin's default socket path.")
    }

    func testLockedExplainsAndShowsTheSanitisedError() {
        let l = StatusLine.from(.locked(lastError: "keychain \u{1B}[31m locked \u{202E}"))
        XCTAssertEqual(l.level, .warning)
        XCTAssertNil(l.button)
        XCTAssertTrue(l.detail!.hasPrefix("Unlock your Mac to use secrets."))
        XCTAssertTrue(l.detail!.contains("keychain"))
        XCTAssertFalse(l.detail!.unicodeScalars.contains("\u{1B}"))
        XCTAssertFalse(l.detail!.unicodeScalars.contains("\u{202E}"))
        XCTAssertEqual(StatusLine.from(.locked(lastError: nil)).detail, "Unlock your Mac to use secrets. grantpin keeps trying.")
    }

    func testNotInitializedOffersCreateVault() {
        let l = StatusLine.from(.notInitialized)
        XCTAssertEqual(l.headline, "No vault yet")
        XCTAssertEqual(l.button, .setUp)
    }

    func testReadyShowsCounts() {
        let l = StatusLine.from(.ready(StatusResult(keystoreTier: .hardware, secrets: 3, activeGrants: 1)))
        XCTAssertEqual(l.level, .ok)
        XCTAssertEqual(l.headline, "grantpin is running")
        XCTAssertEqual(l.countsText, "3 secrets · 1 active grant")
        XCTAssertNil(l.tamperedWarning)
        XCTAssertEqual(StatusLine.from(.ready(StatusResult(secrets: 1, activeGrants: 2))).countsText, "1 secret · 2 active grants")
    }

    func testTamperedGrantsWarn() {
        let l = StatusLine.from(.ready(StatusResult(secrets: 1, activeGrants: 1, tamperedGrants: 2)))
        XCTAssertEqual(l.level, .warning)
        XCTAssertEqual(l.tamperedWarning, "TAMPERED: 2 grants failed verification. Open Grants to review.")
        XCTAssertEqual(StatusLine.from(.ready(StatusResult(tamperedGrants: 1))).tamperedWarning, "TAMPERED: 1 grant failed verification. Open Grants to review.")
    }

    func testProtocolMismatchAndKeychainOnlyWarn() {
        XCTAssertEqual(StatusLine.from(.ready(StatusResult(protoV: 2))).headline, "grantpin is out of step")
        let k = StatusLine.from(.ready(StatusResult(keystoreTier: .dialog)))
        XCTAssertEqual(k.level, .warning)
        XCTAssertTrue(k.detail!.contains("Keychain"))
    }
}

final class MenuBarIconTests: XCTestCase {
    private func icon(_ s: ConnectionState?) -> MenuBarIcon { MenuBarIcon.from(s) }

    func testEveryStateMapsToItsVariantAndLabel() {
        let cases: [(String, ConnectionState?, MenuBarIcon.Badge, Bool, String)] = [
            ("checking", nil, .none, true, "grantpin: checking"),
            ("not running", .notRunning, .error, true, "grantpin: not running"),
            ("locked", .locked(lastError: nil), .none, true, "grantpin: vault locked"),
            ("locked with error", .locked(lastError: "x"), .none, true, "grantpin: vault locked"),
            ("no vault", .notInitialized, .warning, false, "grantpin: no vault yet"),
            ("ready", .ready(StatusResult(keystoreTier: .hardware)), .none, false, "grantpin"),
            ("ready, keychain only", .ready(StatusResult(keystoreTier: .dialog)), .none, false, "grantpin"),
            ("tampered", .ready(StatusResult(tamperedGrants: 1)), .warning, false, "grantpin: grants failed verification"),
        ]
        for (name, state, badge, subdued, label) in cases {
            let i = icon(state)
            XCTAssertEqual(i.badge, badge, name)
            XCTAssertEqual(i.subdued, subdued, name)
            XCTAssertEqual(i.label, label, name)
        }
    }

    func testOnlyAHealthyDaemonLooksPlain() {
        let plainAndBright = [ConnectionState.ready(StatusResult(keystoreTier: .hardware))]
        for s in plainAndBright {
            XCTAssertEqual(icon(s), MenuBarIcon(subdued: false, badge: .none, label: "grantpin"))
        }
        XCTAssertNotEqual(icon(.notRunning), icon(.ready(StatusResult())), "a missing service must not look like a running one")
        XCTAssertEqual(icon(.notRunning).badge, .error)
        XCTAssertEqual(icon(.notRunning).label, "grantpin: not running")
    }

    func testBadgesNeedAColouredImageAndPlainStatesStayTemplates() {
        XCTAssertTrue(icon(.ready(StatusResult())).usesTemplateImage)
        XCTAssertTrue(icon(.locked(lastError: nil)).usesTemplateImage)
        XCTAssertTrue(icon(nil).usesTemplateImage)
        XCTAssertFalse(icon(.notRunning).usesTemplateImage)
        XCTAssertFalse(icon(.notInitialized).usesTemplateImage)
        XCTAssertFalse(icon(.ready(StatusResult(tamperedGrants: 2))).usesTemplateImage)
    }

    func testEveryStateHasAnAccessibilityLabel() {
        for s in [nil, ConnectionState.notRunning, .notInitialized, .locked(lastError: nil), .ready(StatusResult())] {
            XCTAssertTrue(icon(s).label.hasPrefix("grantpin"))
        }
    }
}

final class FakeActions: DaemonActions, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var started = 0, created = 0
    var startResult = ActionResult(outcome: .succeeded, summary: "grantpin is running in the background.")
    var createResult = ActionResult(outcome: .succeeded, summary: "Vault created.")
    var delayNanos: UInt64 = 0
    /// Runs when `startService` begins and may hold it; a test that needs to
    /// act while Start is in flight waits for it, instead of guessing a delay.
    var duringStart: (@Sendable () async -> Void)?
    func startService() async -> ActionResult {
        lock.withLock { started += 1 }
        if let duringStart { await duringStart() }
        if delayNanos > 0 { try? await Task.sleep(nanoseconds: delayNanos) }
        return startResult
    }
    func createVault() async -> ActionResult {
        lock.withLock { created += 1 }
        if delayNanos > 0 { try? await Task.sleep(nanoseconds: delayNanos) }
        return createResult
    }
}

@MainActor
final class PopoverModelTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func rows(_ n: Int) -> [AuditEntry] {
        (0..<n).map { AuditEntry(id: "\($0)", ts: t0.addingTimeInterval(Double($0)), argv: ["grantpin", "set", "S\($0)"], secrets: ["S\($0)"], decision: "allowed_once", reason: "set") }.reversed()
    }

    func testShowsTheLastThreeEventsNewestFirst() async {
        let svc = FakeService()
        svc.audit = .make(rows(10))
        let m = PopoverModel(audit: svc, actions: nil, now: { self.t0.addingTimeInterval(100) })
        await m.refreshActivity()
        XCTAssertEqual(m.recent.count, 3)
        XCTAssertEqual(m.recent.map(\.command), ["S9", "S8", "S7"])
        XCTAssertEqual(m.recent[0].title, "Secret saved")
        XCTAssertTrue(m.activityLoaded)
    }

    func testEmptyLog() async {
        let m = PopoverModel(audit: FakeService(), actions: nil)
        await m.refreshActivity()
        XCTAssertTrue(m.recent.isEmpty)
        XCTAssertTrue(m.activityLoaded)
    }

    func testAnErrorEmptiesTheList() async {
        let svc = FakeService()
        svc.audit = .make(rows(2))
        let m = PopoverModel(audit: svc, actions: nil)
        await m.refreshActivity()
        XCTAssertEqual(m.recent.count, 2)
        svc.failNext["audit"] = GrantpinError.notRunning
        await m.refreshActivity()
        XCTAssertTrue(m.recent.isEmpty)
        XCTAssertFalse(m.activityLoaded)
    }

    func testStartRunsTheActionAndKeepsTheResult() async {
        let actions = FakeActions()
        var polled = 0
        let m = PopoverModel(audit: FakeService(), actions: actions, onActionFinished: { polled += 1 })
        await m.start()
        XCTAssertEqual(actions.started, 1)
        XCTAssertEqual(m.lastResult?.summary, "grantpin is running in the background.")
        XCTAssertNil(m.running)
        XCTAssertEqual(polled, 1, "status is polled right away")
        m.dismissResult()
        XCTAssertNil(m.lastResult)
    }

    func testCreateVaultRunsInit() async {
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions)
        await m.createVault()
        XCTAssertEqual(actions.created, 1)
        XCTAssertEqual(actions.started, 0)
        XCTAssertEqual(m.lastResult?.summary, "Vault created.")
    }

    func testFailureIsShown() async {
        let actions = FakeActions()
        actions.startResult = ActionResult(outcome: .failed, summary: "grantpin could not be started.", detail: "boom")
        let m = PopoverModel(audit: FakeService(), actions: actions)
        await m.start()
        XCTAssertEqual(m.lastResult?.isSuccess, false)
        XCTAssertEqual(m.lastResult?.detail, "boom")
    }

    func testOnlyOneActionAtATime() async throws {
        let actions = FakeActions()
        actions.delayNanos = 100_000_000
        let m = PopoverModel(audit: FakeService(), actions: actions)
        async let a: Void = m.start()
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(m.running, .startService)
        await m.createVault()  // ignored while Start runs
        await a
        XCTAssertEqual(actions.created, 0)
    }

    func testDevelopmentModeNeverRunsTheHelper() async {
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions, developmentSocket: "/tmp/gd-dev/s.sock")
        XCTAssertTrue(m.isDevelopment)
        XCTAssertNotNil(m.buttonsDisabledReason)
        await m.start()
        await m.createVault()
        XCTAssertEqual(actions.started + actions.created, 0)
    }

    func testRepairAndRestartRunServiceInstall() async {
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions)
        await m.perform(.repair)
        await m.perform(.restart)
        await m.perform(.startService)
        XCTAssertEqual(actions.started, 3)
        // Set Up, Review and Open Logs Folder open windows or folders: the view does that
        await m.perform(.setUp); await m.perform(.review); await m.perform(.openLogs)
        XCTAssertEqual(actions.started + actions.created, 3)
        XCTAssertNil(m.running)
    }

    func testOutsideApplicationsTheButtonsAreOff() async {
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions, location: .elsewhere)
        XCTAssertEqual(m.buttonsDisabledReason, "Move grantpin to your Applications folder first")
        await m.start()
        XCTAssertEqual(actions.started, 0)
        m.location = .ok
        XCTAssertNil(m.buttonsDisabledReason)
        await m.start()
        XCTAssertEqual(actions.started, 1)
    }

    func testQuickListIsTheSixNewestSecrets() async {
        let svc = FakeService(secrets: (0..<9).map {
            SecretInfo(name: "S\($0)", updatedAt: Date(timeIntervalSince1970: Double(1_000 + ($0 * 7) % 9)))
        })
        let m = PopoverModel(audit: svc, actions: nil, secrets: svc)
        await m.refreshSecrets()
        XCTAssertEqual(m.quickSecrets.count, 6)
        let times = m.quickSecrets.map(\.updatedAt)
        XCTAssertEqual(times, times.sorted(by: >), "newest first")
        XCTAssertEqual(Set(m.quickSecrets.map(\.name)).count, 6)
        XCTAssertGreaterThanOrEqual(times.last!, Date(timeIntervalSince1970: 1_003))
    }

    func testQuickListEmptiesQuietlyOnAnError() async {
        let svc = FakeService(secrets: [SecretInfo(name: "A")])
        let m = PopoverModel(audit: svc, actions: nil, secrets: svc)
        await m.refreshSecrets()
        XCTAssertEqual(m.quickSecrets.map(\.name), ["A"])
        svc.listFailure = GrantpinError.daemon(category: .failed, reason: .vaultNotInitialized, message: "")
        await m.refreshSecrets()
        XCTAssertTrue(m.quickSecrets.isEmpty, "hidden, not shown as an error")
    }

    func testGrantsRowTitle() {
        XCTAssertEqual(grantsRowTitle(activeGrants: 3), "Grants (3)…")
        XCTAssertEqual(grantsRowTitle(activeGrants: 0), "Grants (0)…")
        XCTAssertEqual(grantsRowTitle(activeGrants: nil), "Grants…")
    }

    func testNoHelperMeansNoButtons() async {
        let m = PopoverModel(audit: FakeService(), actions: nil)
        XCTAssertEqual(m.buttonsDisabledReason, "The helper inside this app could not be found.")
        await m.start()
        XCTAssertNil(m.lastResult)
    }

    func testTheButtonsWaitWhileSomethingElseChangesTheService() async {
        var busy = true
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions, externallyBusy: { busy })
        XCTAssertEqual(m.buttonsDisabledReason, ServiceBusy.reason)
        let refused = await m.perform(.startService)
        XCTAssertNil(refused)
        XCTAssertEqual(actions.started, 0)
        busy = false
        XCTAssertNil(m.buttonsDisabledReason)
        await m.start()
        XCTAssertEqual(actions.started, 1)
    }

    func testPerformAnswersWhatThisRunDidAndNilWhenNothingRan() async throws {
        let actions = FakeActions()
        let m = PopoverModel(audit: FakeService(), actions: actions)
        let first = await m.perform(.startService)
        XCTAssertEqual(first, actions.startResult)
        XCTAssertEqual(m.lastResult, first)
        // a button that only opens something: nothing ran, and the screen's result stays
        let opened = await m.perform(.openLogs)
        XCTAssertNil(opened)
        XCTAssertEqual(m.lastResult, first)
        // a second press while one runs: nil, not the other run's result
        let (began, beganC) = AsyncStream.makeStream(of: Void.self)
        let (gate, gateC) = AsyncStream.makeStream(of: Void.self)
        actions.duringStart = {
            beganC.yield()
            for await _ in gate { break }
        }
        async let slow = m.perform(.startService)
        for await _ in began { break }
        XCTAssertEqual(m.running, .startService)
        let refused = await m.perform(.restart)
        XCTAssertNil(refused)
        gateC.yield()
        let slowResult = await slow
        XCTAssertEqual(slowResult, actions.startResult)
        XCTAssertEqual(actions.started, 2)
        actions.duringStart = nil
        // the buttons are off: nil, whatever lastResult says
        let off = PopoverModel(audit: FakeService(), actions: actions, location: .elsewhere)
        let offResult = await off.perform(.startService)
        XCTAssertNil(offResult)
        let noHelper = await PopoverModel(audit: FakeService(), actions: nil).perform(.startService)
        XCTAssertNil(noHelper)
    }
}
