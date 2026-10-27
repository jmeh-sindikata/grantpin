import Foundation
import XCTest
@testable import GrantpinKit

final class ServiceAskGateTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let ready = ConnectionState.ready(StatusResult(keystoreTier: .hardware))
    var gate = ServiceAskGate()

    /// One evaluation `seconds` after t0.
    func ask(_ state: ConnectionState?, at seconds: TimeInterval, onboarding: Bool = false, dev: Bool = false, popover: Bool = false) -> Bool {
        gate.evaluate(state, now: t0.addingTimeInterval(seconds), onboardingPending: onboarding, isDevelopment: dev, popoverOpen: popover)
    }

    override func setUp() { gate = ServiceAskGate() }

    func testLaunchWhileStoppedAsksOnceAfterTheGrace() {
        XCTAssertFalse(ask(nil, at: 0), "no state yet")
        XCTAssertFalse(ask(.notRunning, at: 1), "the service may still be starting at login")
        XCTAssertEqual(gate.waitTime(now: t0.addingTimeInterval(1)), ServiceAskGate.grace)
        XCTAssertFalse(ask(.notRunning, at: 5))
        XCTAssertTrue(ask(.notRunning, at: 1 + ServiceAskGate.grace))
        XCTAssertNil(gate.waitTime(now: t0.addingTimeInterval(20)), "nothing pending once asked")
        for t in stride(from: 12.0, through: 600, by: 15) { XCTAssertFalse(ask(.notRunning, at: t), "asked once per period (t=\(t))") }
    }

    func testAServiceThatComesUpWithinTheGraceNeverAsks() {
        XCTAssertFalse(ask(.notRunning, at: 0))
        XCTAssertFalse(ask(.notRunning, at: 6))
        XCTAssertFalse(ask(ready, at: 9))
        XCTAssertFalse(ask(ready, at: 40))
        XCTAssertNil(gate.waitTime(now: t0.addingTimeInterval(40)))
    }

    func testAfterTheAskNotAgainUntilRunningAndBack() {
        XCTAssertFalse(ask(.notRunning, at: 0))
        XCTAssertTrue(ask(.notRunning, at: 10))
        // the person dismisses the window; the daemon stays down
        XCTAssertFalse(ask(.notRunning, at: 30))
        XCTAssertFalse(ask(.notRunning, at: 3600))
        // started, ran for a long time, then went away
        XCTAssertFalse(ask(ready, at: 3700))
        XCTAssertFalse(ask(ready, at: 3700 + 600))
        XCTAssertFalse(ask(.notRunning, at: 3700 + 700), "grace first")
        XCTAssertTrue(ask(.notRunning, at: 3700 + 700 + ServiceAskGate.grace))
        XCTAssertFalse(ask(.notRunning, at: 3700 + 800))
    }

    func testARunningDaemonThatGoesAwayAsksOnce() {
        XCTAssertFalse(ask(ready, at: 0))
        XCTAssertFalse(ask(.locked(lastError: nil), at: 100), "locked or no vault is an answering daemon")
        XCTAssertFalse(ask(.notInitialized, at: 200))
        XCTAssertFalse(ask(.notRunning, at: 300))
        XCTAssertFalse(ask(.notRunning, at: 305))
        XCTAssertTrue(ask(.notRunning, at: 310))
        XCTAssertFalse(ask(.notRunning, at: 330))
    }

    func testAServiceThatKeepsStoppingDoesNotAskEveryTime() {
        XCTAssertFalse(ask(.notRunning, at: 0))
        XCTAssertTrue(ask(.notRunning, at: 10))
        XCTAssertFalse(ask(ready, at: 20), "started again")
        XCTAssertFalse(ask(.notRunning, at: 30), "down again after 10 seconds: the same trouble")
        XCTAssertFalse(ask(.notRunning, at: 45))
        XCTAssertFalse(ask(.notRunning, at: 90))
        XCTAssertNil(gate.waitTime(now: t0.addingTimeInterval(90)))
    }

    func testDownAfterAShortUpAtLaunchIsNotAsked() {
        XCTAssertFalse(ask(ready, at: 0))
        XCTAssertFalse(ask(.notRunning, at: 20))
        XCTAssertFalse(ask(.notRunning, at: 40))
    }

    func testNoAskDuringFirstRunOnboardingAndThePeriodIsUsedUp() {
        XCTAssertFalse(ask(.notRunning, at: 0, onboarding: true))
        XCTAssertFalse(ask(.notRunning, at: 10, onboarding: true))
        XCTAssertFalse(ask(.notRunning, at: 60, onboarding: false), "onboarding finished while still down: not asked now")
    }

    func testNoAskInDevelopmentMode() {
        XCTAssertFalse(ask(.notRunning, at: 0, dev: true))
        XCTAssertFalse(ask(.notRunning, at: 60, dev: true))
        XCTAssertNil(gate.waitTime(now: t0.addingTimeInterval(60)))
        // and nothing was remembered: leaving development mode starts a fresh grace
        XCTAssertFalse(ask(.notRunning, at: 61))
        XCTAssertTrue(ask(.notRunning, at: 61 + ServiceAskGate.grace))
    }

    func testNoAskWhileThePopoverIsOpen() {
        XCTAssertFalse(ask(.notRunning, at: 0))
        XCTAssertFalse(ask(.notRunning, at: 10, popover: true), "the person is looking at it")
        XCTAssertFalse(ask(.notRunning, at: 20, popover: false))
    }

    func testAnUnknownStateChangesNothing() {
        XCTAssertFalse(ask(.notRunning, at: 0))
        XCTAssertFalse(ask(nil, at: 5))
        XCTAssertTrue(ask(.notRunning, at: 10))
    }
}

final class BackgroundItemNoticeTests: XCTestCase {
    func testTheOnboardingSentenceNamesTheDeveloperAndWhereToSwitchItOff() {
        XCTAssertEqual(
            BackgroundItemNotice.full(developer: "S.A.P. SH.P.K."),
            "macOS will tell you that S.A.P. SH.P.K. (the developer of grantpin) added a background item. "
                + "That is grantpin's service; you can switch it off any time in System Settings > General > Login Items & Extensions.")
        XCTAssertEqual(BackgroundItemNotice.short(developer: "Acme"),
                       "macOS will tell you that Acme added a background item. That is grantpin's service.")
        XCTAssertEqual(OnboardingModel.serviceNotice, BackgroundItemNotice.full())
    }

    func testTheDeveloperNameIsNeverEmpty() {
        XCTAssertFalse(BackgroundItemNotice.developerName.isEmpty)
        XCTAssertEqual(BackgroundItemNotice.fallbackDeveloperName, "S.A.P. SH.P.K.")
    }

    func testTheNameComesOutOfTheCertificateSummary() {
        let n = BackgroundItemNotice.name(fromCertificateSummary:)
        XCTAssertEqual(n("Developer ID Application: S.A.P. SH.P.K. (MT2QHQX6PS)"), "S.A.P. SH.P.K.")
        XCTAssertEqual(n("Developer ID Application: Acme (Europe) Ltd (ABCDE12345)"), "Acme (Europe) Ltd")
        XCTAssertEqual(n("Apple Development: Jane Doe (ABCDE12345)"), "Jane Doe")
        XCTAssertEqual(n("Developer ID Application: No Team Id"), "No Team Id")
        XCTAssertNil(n("Developer ID Application: (ABCDE12345)"))
        XCTAssertNil(n("Developer ID Application: "))
        XCTAssertNil(n("-"), "ad-hoc or unknown shapes fall back")
        XCTAssertNil(n(""))
    }
}
