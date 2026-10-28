import Foundation
import XCTest
@testable import GrantpinKit

final class ReleaseVersionTests: XCTestCase {
    func testParsesTaggedVersionsAndNothingElse() {
        XCTAssertEqual(ReleaseVersion("0.2.5")?.parts, [0, 2, 5])
        XCTAssertEqual(ReleaseVersion("v0.2.5")?.parts, [0, 2, 5])
        XCTAssertEqual(ReleaseVersion(" v1.10.0 ")?.parts, [1, 10, 0])
        for text in ["dev", "", "v", "0.2", "0.2.5.1", "0.2.5-3-gabc1234", "v0.2.5-dirty", "0.2.x", "0..5", "a.b.c", "55c4e71-dirty", "V0.2.5", "٠.٢.٥"] {
            XCTAssertNil(ReleaseVersion(text), text)
        }
    }

    func testOrdersNumericallyNotTextually() {
        XCTAssertTrue(ReleaseVersion("0.2.4")! < ReleaseVersion("0.2.5")!)
        XCTAssertTrue(ReleaseVersion("0.2.9")! < ReleaseVersion("0.2.10")!)
        XCTAssertTrue(ReleaseVersion("0.9.9")! < ReleaseVersion("1.0.0")!)
        XCTAssertFalse(ReleaseVersion("0.2.5")! < ReleaseVersion("0.2.5")!)
        XCTAssertEqual(ReleaseVersion("v0.2.5"), ReleaseVersion("0.2.5"))
    }

    func testOnlyAnOlderReleaseDaemonIsAnUpgrade() {
        XCTAssertTrue(ReleaseVersion.isUpgrade(from: "0.2.4", to: "0.2.5"))
        XCTAssertTrue(ReleaseVersion.isUpgrade(from: "v0.2.4", to: "0.2.5"), "with and without the v")
        XCTAssertTrue(ReleaseVersion.isUpgrade(from: "0.2.4", to: "v0.3.0"))
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.5", to: "0.2.5"), "equal")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "v0.2.5", to: "0.2.5"), "equal but for the v")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.6", to: "0.2.5"), "the daemon is the newer one")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "dev", to: "0.2.5"), "a from-source daemon")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.4", to: "dev"), "a from-source app")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.4-3-gabc1234", to: "0.2.5"), "a suffix is not a release")
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.4", to: "0.2.5-dirty"))
        XCTAssertFalse(ReleaseVersion.isUpgrade(from: "0.2.4", to: "0.2.5-3-gabc1234"))
    }
}

final class ServiceRestartPolicyTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let helper = "0.2.5"
    func old(_ inFlight: Int?) -> ConnectionState { .ready(StatusResult(version: "0.2.4", inFlightRuns: inFlight)) }
    var new: ConnectionState { .ready(StatusResult(version: "0.2.5", inFlightRuns: 0)) }
    let idle = ServiceRestartPolicy.Inputs(inFlightRuns: 0)

    func testAMismatchIsAnAnsweringDaemonWithAnotherVersion() {
        XCTAssertTrue(ServiceRestartPolicy.isMismatch(old(0), helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isMismatch(new, helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isMismatch(old(0), helperVersion: nil), "helper version unknown")
        XCTAssertFalse(ServiceRestartPolicy.isMismatch(.notRunning, helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isMismatch(.locked(lastError: nil), helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isMismatch(nil, helperVersion: helper))
        XCTAssertTrue(ServiceRestartPolicy.isFixed(new, helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isFixed(old(0), helperVersion: helper))
        XCTAssertFalse(ServiceRestartPolicy.isFixed(new, helperVersion: nil))
    }

    func testASafeMismatchRestartsAtOnceAndOnlyOnce() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        XCTAssertTrue(p.attempted)
        XCTAssertEqual(p.mismatchSince, t0)
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(1)), .nothing, "the attempt is used")
    }

    func testANewerOrUnnumberedDaemonIsAskedAboutNeverRestarted() {
        for (name, version) in [("newer daemon", "0.2.6"), ("from-source daemon", "dev"), ("suffixed daemon", "0.2.4-3-gabc1234"), ("same but for the v", "v0.2.5")] {
            var p = ServiceRestartPolicy()
            let state = ConnectionState.ready(StatusResult(version: version, inFlightRuns: 0))
            if version == "v0.2.5" {
                XCTAssertTrue(ServiceRestartPolicy.isMismatch(state, helperVersion: helper), name)
            }
            XCTAssertFalse(ServiceRestartPolicy.isUpgrade(state, helperVersion: helper), name)
            XCTAssertFalse(p.decisionDue(state, helperVersion: helper, idle, now: t0), name)
            XCTAssertEqual(p.evaluate(state, helperVersion: helper, idle, now: t0), .nothing, name)
            XCTAssertFalse(p.attempted, name)
            XCTAssertEqual(p.waitTime(now: t0), ServiceRestartPolicy.grace, name)
            XCTAssertTrue(p.decisionDue(state, helperVersion: helper, idle, now: t0.addingTimeInterval(10)), name)
            XCTAssertEqual(p.evaluate(state, helperVersion: helper, idle, now: t0.addingTimeInterval(10)), .ask, "\(name): told, not restarted")
            XCTAssertEqual(p.evaluate(state, helperVersion: helper, idle, now: t0.addingTimeInterval(600)), .nothing, name)
            XCTAssertFalse(p.attempted, name)
        }
        XCTAssertTrue(ServiceRestartPolicy.isUpgrade(old(0), helperVersion: helper))
        XCTAssertTrue(ServiceRestartPolicy.isUpgrade(.ready(StatusResult(version: "v0.2.4")), helperVersion: "v0.2.5"), "tagged builds carry the v on both sides")
    }

    func testOnlyAKnownZeroIsIdle() {
        XCTAssertTrue(ServiceRestartPolicy.Inputs(inFlightRuns: 0).isIdle)
        XCTAssertFalse(ServiceRestartPolicy.Inputs(inFlightRuns: 1).isIdle)
        XCTAssertFalse(ServiceRestartPolicy.Inputs(inFlightRuns: nil).isIdle, "a daemon that cannot say is not idle")
    }

    func testARunInProgressWaitsThenAsksOnceAndRestartsOnceItIsOver() {
        var p = ServiceRestartPolicy()
        let busy = ServiceRestartPolicy.Inputs(inFlightRuns: 2)
        XCTAssertEqual(p.evaluate(old(2), helperVersion: helper, busy, now: t0), .nothing)
        XCTAssertFalse(p.attempted)
        XCTAssertEqual(p.waitTime(now: t0), ServiceRestartPolicy.grace)
        XCTAssertEqual(p.evaluate(old(2), helperVersion: helper, busy, now: t0.addingTimeInterval(5)), .nothing, "a run that ends in a moment never opens a window")
        XCTAssertEqual(p.evaluate(old(2), helperVersion: helper, busy, now: t0.addingTimeInterval(10)), .ask)
        XCTAssertTrue(p.asked)
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(10)), "asked: nothing time-based is left")
        XCTAssertEqual(p.evaluate(old(2), helperVersion: helper, busy, now: t0.addingTimeInterval(60)), .nothing, "once per period")
        // the run ends: the attempt is still unused, so the restart goes ahead (Later did not forbid it)
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(90)), .restart)
    }

    func testADaemonThatCannotReportItsRunsIsAskedAboutAndNeverRestarted() {
        var p = ServiceRestartPolicy()
        let unknown = ServiceRestartPolicy.Inputs(inFlightRuns: nil)
        XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0), .nothing)
        XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(10)), .ask)
        for s in stride(from: 20.0, through: 3600, by: 300) {
            XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(s)), .nothing, "t=\(s)")
        }
        XCTAssertFalse(p.attempted)
    }

    func testAFailedAttemptAsksAtOnce() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        p.noteRestartFailed()
        XCTAssertFalse(p.decisionDue(old(0), helperVersion: helper, idle, now: t0), "no poll for an ask that does not rest on activity")
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .ask, "no grace for a failure")
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(60)), .nothing)
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(1)))
    }

    func testAPendingRestartIsFixedWhenTheNewVersionAnswers() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        p.noteRestartStarted(now: t0)
        XCTAssertEqual(p.pendingSince, t0)
        XCTAssertEqual(p.waitTime(now: t0.addingTimeInterval(4)), ServiceRestartPolicy.grace - 4)
        XCTAssertEqual(p.resolvePending(old(0), helperVersion: helper, now: t0.addingTimeInterval(2)), .waiting, "a poll from before the restart")
        XCTAssertEqual(p.resolvePending(.notRunning, helperVersion: helper, now: t0.addingTimeInterval(4)), .waiting, "the job is restarting")
        XCTAssertEqual(p.resolvePending(new, helperVersion: helper, now: t0.addingTimeInterval(6)), .fixed)
        XCTAssertNil(p.pendingSince)
        XCTAssertNil(p.mismatchSince, "the period is over")
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(6)))
        XCTAssertEqual(p.evaluate(new, helperVersion: helper, idle, now: t0.addingTimeInterval(7)), .nothing)
        XCTAssertNil(p.resolvePending(new, helperVersion: helper, now: t0.addingTimeInterval(8)), "nothing pending")
    }

    func testAPendingRestartThatStillAnswersOldAfterTheGraceAsks() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        p.noteRestartStarted(now: t0)
        XCTAssertEqual(p.resolvePending(old(0), helperVersion: helper, now: t0.addingTimeInterval(10)), .persists)
        XCTAssertTrue(p.attemptFailed)
        XCTAssertNotNil(p.mismatchSince, "the same period goes on")
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(10)), .ask)
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(20)), .nothing)
    }

    func testAPendingRestartWhoseDaemonIsGoneHandsOver() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        p.noteRestartStarted(now: t0)
        XCTAssertEqual(p.resolvePending(.notRunning, helperVersion: helper, now: t0.addingTimeInterval(10)), .lost)
        XCTAssertNil(p.mismatchSince)
        XCTAssertNil(p.pendingSince)
        XCTAssertEqual(p.evaluate(.notRunning, helperVersion: helper, idle, now: t0.addingTimeInterval(11)), .nothing)
    }

    func testThePeriodEndsWhenTheVersionsAgreeOrTheDaemonStops() {
        var p = ServiceRestartPolicy()
        let busy = ServiceRestartPolicy.Inputs(inFlightRuns: 1)
        XCTAssertEqual(p.evaluate(old(1), helperVersion: helper, busy, now: t0), .nothing)
        XCTAssertEqual(p.mismatchSince, t0)
        // someone restarted from the CLI
        XCTAssertEqual(p.evaluate(new, helperVersion: helper, idle, now: t0.addingTimeInterval(5)), .nothing)
        XCTAssertNil(p.mismatchSince)
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(5)))
        // a new mismatch is a new period with a fresh grace
        XCTAssertEqual(p.evaluate(old(1), helperVersion: helper, busy, now: t0.addingTimeInterval(100)), .nothing)
        XCTAssertEqual(p.mismatchSince, t0.addingTimeInterval(100))
        XCTAssertEqual(p.evaluate(.notRunning, helperVersion: helper, busy, now: t0.addingTimeInterval(105)), .nothing)
        XCTAssertNil(p.mismatchSince, "the missing-service logic takes over")
        // locked or no vault says nothing about the version
        XCTAssertEqual(p.evaluate(old(1), helperVersion: helper, busy, now: t0.addingTimeInterval(200)), .nothing)
        p.observe(.locked(lastError: nil), helperVersion: helper, now: t0.addingTimeInterval(201))
        p.observe(nil, helperVersion: helper, now: t0.addingTimeInterval(202))
        XCTAssertEqual(p.mismatchSince, t0.addingTimeInterval(200))
        XCTAssertEqual(p.evaluate(.locked(lastError: nil), helperVersion: helper, busy, now: t0.addingTimeInterval(215)), .nothing,
                       "no decision on a state that does not show the mismatch")
    }

    func testLaterSilencesThePeriodUntilItClearsAndReappears() {
        var p = ServiceRestartPolicy()
        let unknown = ServiceRestartPolicy.Inputs(inFlightRuns: nil)
        _ = p.evaluate(old(nil), helperVersion: helper, unknown, now: t0)
        XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(10)), .ask)
        XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(3600)), .nothing)
        _ = p.evaluate(new, helperVersion: helper, idle, now: t0.addingTimeInterval(3700))
        _ = p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(3800))
        XCTAssertEqual(p.evaluate(old(nil), helperVersion: helper, unknown, now: t0.addingTimeInterval(3810)), .ask, "a new period asks again")
    }

    func testAnAttemptUsedInAnEarlierPeriodMeansTheNextPeriodAsks() {
        var p = ServiceRestartPolicy()
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0), .restart)
        p.noteRestartStarted(now: t0)
        XCTAssertEqual(p.resolvePending(new, helperVersion: helper, now: t0.addingTimeInterval(3)), .fixed)
        // a second update in the same launch
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(1000)), .nothing)
        XCTAssertEqual(p.waitTime(now: t0.addingTimeInterval(1000)), ServiceRestartPolicy.grace)
        XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, idle, now: t0.addingTimeInterval(1010)), .ask)
    }

    func testOnboardingDevelopmentLocationAndSuspendedDecideNothing() {
        for (name, inputs) in [
            ("onboarding", ServiceRestartPolicy.Inputs(inFlightRuns: 0, onboardingPending: true)),
            ("development", ServiceRestartPolicy.Inputs(inFlightRuns: 0, isDevelopment: true)),
            ("elsewhere", ServiceRestartPolicy.Inputs(inFlightRuns: 0, location: .elsewhere)),
            ("translocated", ServiceRestartPolicy.Inputs(inFlightRuns: 0, location: .translocated)),
            ("suspended", ServiceRestartPolicy.Inputs(inFlightRuns: 0, suspended: true)),
        ] {
            var p = ServiceRestartPolicy()
            XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, inputs, now: t0), .nothing, name)
            XCTAssertFalse(p.decisionDue(old(0), helperVersion: helper, inputs, now: t0.addingTimeInterval(60)), name)
            XCTAssertEqual(p.evaluate(old(0), helperVersion: helper, inputs, now: t0.addingTimeInterval(60)), .nothing, "\(name): no ask either")
            XCTAssertFalse(p.attempted, name)
            XCTAssertFalse(p.asked, name)
            XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(60)), "\(name): the grace passed with nothing to wait for")
        }
    }

    func testDecisionDueMirrorsEvaluate() {
        var p = ServiceRestartPolicy()
        let busy = ServiceRestartPolicy.Inputs(inFlightRuns: 1)
        XCTAssertTrue(p.decisionDue(old(0), helperVersion: helper, idle, now: t0), "a restart is due")
        XCTAssertFalse(p.decisionDue(old(1), helperVersion: helper, busy, now: t0), "not yet: the grace")
        _ = p.evaluate(old(1), helperVersion: helper, busy, now: t0)
        XCTAssertFalse(p.decisionDue(old(1), helperVersion: helper, busy, now: t0.addingTimeInterval(9)))
        XCTAssertTrue(p.decisionDue(old(1), helperVersion: helper, busy, now: t0.addingTimeInterval(10)), "the ask is due")
        XCTAssertFalse(p.decisionDue(new, helperVersion: helper, idle, now: t0.addingTimeInterval(10)), "no mismatch")
    }
}

@MainActor
final class ServiceRestartRecoveryTests: XCTestCase {
    final class World {
        var t = Date(timeIntervalSince1970: 1_800_000_000)
        var state: ConnectionState? = .ready(StatusResult(version: "0.2.4", inFlightRuns: 0))
        var helper: String? = "0.2.5"
        var onboarding = false
        var popover = false
        var suspended = false
        var restartResult: ActionResult? = ActionResult(outcome: .succeeded, summary: "grantpin is running in the background.")
        var restarts = 0
        var restores = 0
        var diagnoses = 0
        var refreshes = 0
        /// What the daemon answers when the monitor is asked to poll now; nil leaves the state alone.
        var onRefresh: ConnectionState?? = nil
        func advance(_ s: TimeInterval) { t = t.addingTimeInterval(s) }
        func old(_ inFlight: Int?) { state = .ready(StatusResult(version: "0.2.4", inFlightRuns: inFlight)) }
        func new() { state = .ready(StatusResult(version: "0.2.5", inFlightRuns: 0)) }
    }

    /// `XCTAssertEqual` cannot await: one look, then the comparison.
    func expectCheck(_ r: ServiceRecovery, _ expected: ServiceRecovery.Verdict, _ message: String = "",
                     file: StaticString = #filePath, line: UInt = #line) async {
        let verdict = await r.check()
        XCTAssertEqual(verdict, expected, message, file: file, line: line)
    }

    func recovery(_ w: World, location: AppLocation = .ok, dev: Bool = false) -> ServiceRecovery {
        ServiceRecovery(
            connection: { w.state }, location: location, isDevelopment: dev,
            onboardingPending: { w.onboarding }, popoverOpen: { w.popover }, suspended: { w.suspended },
            markerPresent: { true }, vaultExists: { true }, now: { w.t },
            refresh: { w.refreshes += 1; if let s = w.onRefresh { w.state = s } },
            diagnose: { w.diagnoses += 1; return .notRunning },
            restore: { w.restores += 1; return nil },
            helperVersion: { w.helper },
            restart: { w.restarts += 1; return w.restartResult })
    }

    func testASafeMismatchIsRestartedOnceAndNoticedOnceTheNewVersionAnswers() async {
        let w = World(), r = recovery(w)
        let first = await r.check()
        XCTAssertEqual(first, .nothing, "restarted: no window")
        XCTAssertEqual(w.restarts, 1)
        XCTAssertEqual(w.refreshes, 1, "the daemon's activity is looked at once more right before the restart")
        XCTAssertEqual(w.restores, 0)
        XCTAssertEqual(w.diagnoses, 0)
        XCTAssertNil(r.restartedAt, "not until the monitor has seen the new version")
        XCTAssertNil(r.noticeText)
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace, "a fresh grace for the new daemon to answer")
        // a poll from before the restart: still the old version
        w.advance(4)
        let stale = await r.check()
        XCTAssertEqual(stale, .nothing)
        XCTAssertEqual(w.restarts, 1)
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace - 4)
        // the job is down for a moment while launchd restarts it: not an outage
        w.advance(1); w.state = .notRunning
        let down = await r.check()
        XCTAssertEqual(down, .nothing)
        // the new daemon answers
        w.advance(2); w.new()
        let up = await r.check()
        XCTAssertEqual(up, .nothing)
        XCTAssertEqual(r.restartedAt, w.t)
        XCTAssertEqual(r.noticeText, "grantpin restarted its background service after the update.")
        XCTAssertEqual(ServiceRecovery.restartedNotice, "grantpin restarted its background service after the update.")
        XCTAssertNil(r.restoredAt)
        XCTAssertEqual(r.nextCheck(), ServiceRecovery.noticeDuration)
        // nothing more happens, and the attempt is used for this launch
        w.advance(60)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1)
        XCTAssertEqual(w.refreshes, 1)
    }

    func testTheRestartCountsAsAServiceActionWhileItRuns() async {
        let w = World()
        var r: ServiceRecovery!
        var busyDuring = false
        var verdictDuring: ServiceRecovery.Verdict?
        r = ServiceRecovery(
            connection: { w.state }, location: .ok, isDevelopment: false, onboardingPending: { false },
            now: { w.t }, diagnose: { nil }, restore: { nil }, helperVersion: { w.helper },
            restart: {
                busyDuring = r.isRestoring
                verdictDuring = await r.check()  // a look during the run, as a state change would cause
                return ActionResult(outcome: .succeeded, summary: "ok")
            })
        XCTAssertFalse(r.isRestoring)
        await expectCheck(r, .nothing)
        XCTAssertTrue(busyDuring, "Settings, Uninstall, onboarding and the popover refuse meanwhile")
        XCTAssertEqual(verdictDuring, .nothing)
        XCTAssertFalse(r.isRestoring)
    }

    func testTheRestartedNoticeExpiresByTheClockAndGoesWhenTheDaemonStops() async {
        let w = World(), r = recovery(w)
        _ = await r.check(); w.advance(3); w.new(); _ = await r.check()
        XCTAssertEqual(r.noticeText, ServiceRecovery.restartedNotice)
        w.advance(ServiceRecovery.noticeDuration - 1); _ = await r.check()
        XCTAssertEqual(r.noticeText, ServiceRecovery.restartedNotice)
        XCTAssertEqual(r.nextCheck(), 1)
        w.advance(1); _ = await r.check()
        XCTAssertNil(r.noticeText)
        XCTAssertNotNil(r.restartedAt, "Settings still says when")
        XCTAssertNil(r.nextCheck())

        let w2 = World(), r2 = recovery(w2)
        _ = await r2.check(); w2.advance(3); w2.new(); _ = await r2.check()
        XCTAssertEqual(r2.noticeText, ServiceRecovery.restartedNotice)
        w2.advance(30); w2.state = .notRunning
        _ = await r2.check()
        XCTAssertNil(r2.noticeText, "a red headline must not carry it")
        XCTAssertEqual(r2.nextCheck(), ServiceAskGate.grace, "a daemon that dies right after its restart is asked about")
        w2.advance(10)
        await expectCheck(r2, .askNow)
    }

    func testAStaleOldAnswerAfterTheGraceIsPolledBeforeTheRestartIsJudged() async {
        let w = World(), r = recovery(w)
        _ = await r.check()
        XCTAssertEqual(w.refreshes, 1)
        // in the background the monitor polls every 30 seconds: the state is still the one from before
        w.advance(ServiceRestartPolicy.grace)
        w.onRefresh = .some(.ready(StatusResult(version: "0.2.5", inFlightRuns: 0)))
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing)
        XCTAssertEqual(w.refreshes, 2)
        XCTAssertEqual(r.restartedAt, w.t)
        XCTAssertEqual(r.noticeText, ServiceRecovery.restartedNotice)
    }

    func testARestartAfterWhichTheOldVersionStillAnswersAsksOnce() async {
        let w = World(), r = recovery(w)
        _ = await r.check()
        w.advance(ServiceRestartPolicy.grace)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askRestart, "service install said yes, the old daemon is still the one answering")
        XCTAssertEqual(w.refreshes, 2, "polled first")
        XCTAssertNil(r.restartedAt)
        XCTAssertNil(r.noticeText)
        XCTAssertNil(r.nextCheck())
        w.advance(30)
        for _ in 0..<3 {
            await expectCheck(r, .nothing, "no second restart, no second ask")
            w.advance(15)
        }
        XCTAssertEqual(w.restarts, 1)
    }

    func testARestartWhoseJobNeverAnswersAgainHandsOverToTheMissingServiceLogic() async {
        // The safe path restarts seconds after launch: the gate has seen the
        // daemon up for less than its stableUp, which must not make the dead
        // restarted job "the same trouble" that is never asked about.
        let w = World(), r = recovery(w)
        _ = await r.check()
        XCTAssertEqual(w.restarts, 1)
        w.advance(ServiceRestartPolicy.grace); w.state = .notRunning
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing, "the outage is counted from now; the gate asks after its grace")
        XCTAssertNil(r.noticeText)
        XCTAssertEqual(r.nextCheck(), ServiceAskGate.grace)
        w.advance(10)
        await expectCheck(r, .askNow)
        XCTAssertEqual(w.restores, 0, "the job is installed but stopped: not restored")
        XCTAssertEqual(w.diagnoses, 1)
        XCTAssertEqual(w.restarts, 1)
    }

    func testADaemonThatDiesThirtySecondsAfterASuccessfulRestartIsAskedAbout() async {
        let w = World(), r = recovery(w)
        _ = await r.check(); w.advance(3); w.new(); _ = await r.check()
        XCTAssertEqual(r.restartedAt, w.t)
        w.advance(30); w.state = .notRunning
        await expectCheck(r, .nothing, "grace first")
        XCTAssertNil(r.noticeText)
        XCTAssertEqual(r.nextCheck(), ServiceAskGate.grace)
        w.advance(10)
        await expectCheck(r, .askNow, "the person saw no window for the restart, so this outage asks")
        XCTAssertEqual(w.restores, 0)
        XCTAssertEqual(w.restarts, 1)
    }

    func testAFailedRestartAsksOncePerPeriodAndLaterSilencesIt() async {
        let w = World(), r = recovery(w)
        w.restartResult = ActionResult(outcome: .failed, summary: "launchctl: nope")
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askRestart)
        XCTAssertEqual(w.restarts, 1)
        XCTAssertNil(r.restartedAt)
        XCTAssertNil(r.noticeText)
        XCTAssertNil(r.nextCheck())
        // Later: nothing more for this period
        for _ in 0..<3 {
            w.advance(30)
            await expectCheck(r, .nothing)
        }
        XCTAssertEqual(w.restarts, 1)
        // the mismatch clears (the person restarted from the window or the CLI) and reappears: asked again, never restarted again
        w.advance(60); w.new(); await expectCheck(r, .nothing)
        w.advance(60); w.old(0); await expectCheck(r, .nothing)
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace)
        w.advance(10)
        await expectCheck(r, .askRestart)
        XCTAssertEqual(w.restarts, 1)
    }

    func testNothingRanIsAFailureToo() async {
        let w = World(), r = recovery(w)
        w.restartResult = nil
        await expectCheck(r, .askRestart)
        XCTAssertEqual(w.restarts, 1)
    }

    func testARunInProgressWaitsAndTheRestartFollowsOnceItIsOver() async {
        let w = World(), r = recovery(w)
        w.old(2)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertEqual(w.refreshes, 0, "nothing to decide, nothing to poll for")
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace)
        // the count changes: a state change, hence a look
        w.advance(3); w.old(1)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        // and once it is zero the restart goes ahead
        w.advance(3); w.old(0)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1)
        XCTAssertEqual(w.refreshes, 1)
        w.advance(2); w.new()
        _ = await r.check()
        XCTAssertEqual(r.noticeText, ServiceRecovery.restartedNotice)
    }

    func testARunThatGoesOnForTheGraceOpensTheWindowOnceAndTheRestartStillFollows() async {
        let w = World(), r = recovery(w)
        w.old(1)
        await expectCheck(r, .nothing)
        w.advance(ServiceRestartPolicy.grace)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askRestart, "unsafe for the grace: the person is told")
        XCTAssertEqual(w.refreshes, 1, "polled first, so a run that just ended does not open a window")
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.nextCheck())
        w.advance(60)
        await expectCheck(r, .nothing, "once per period")
        // Later was pressed; the run ends: the app still restarts, the attempt is unused
        w.advance(60); w.old(0)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1)
    }

    func testARunThatEndsBeforeTheGraceIsNeverAskedAbout() async {
        let w = World(), r = recovery(w)
        w.old(1)
        await expectCheck(r, .nothing)
        // the timer fires; the monitor, asked first, sees the run gone
        w.advance(ServiceRestartPolicy.grace)
        w.onRefresh = .some(.ready(StatusResult(version: "0.2.4", inFlightRuns: 0)))
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1, "restarted, not asked")
    }

    func testAnOldDaemonThatCannotReportItsRunsIsAskedAboutAndNeverRestarted() async {
        let w = World(), r = recovery(w)
        w.old(nil)
        await expectCheck(r, .nothing)
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace)
        w.advance(10)
        await expectCheck(r, .askRestart)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.nextCheck())
        for _ in 0..<5 {
            w.advance(600)
            await expectCheck(r, .nothing)
        }
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.noticeText)
        // the person restarts from the window: the new daemon reports, nothing is left to do
        w.new()
        await expectCheck(r, .nothing)
        XCTAssertNil(r.noticeText, "a restart the person made is not announced as automatic")
        XCTAssertNil(r.restartedAt)
    }

    func testANewerDaemonIsNeverRePointedAtTheOlderHelper() async {
        let w = World(), r = recovery(w)
        w.state = .ready(StatusResult(version: "0.2.6", inFlightRuns: 0))
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertEqual(w.refreshes, 0)
        XCTAssertEqual(r.nextCheck(), ServiceRestartPolicy.grace)
        w.advance(10)
        await expectCheck(r, .askRestart, "the line and the window, with the same wording; no automatic restart")
        XCTAssertEqual(w.restarts, 0)
        w.advance(600)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.noticeText)
        // the same for a daemon built from source
        let d = World(), rd = recovery(d)
        d.state = .ready(StatusResult(version: "dev", inFlightRuns: 0))
        await expectCheck(rd, .nothing); d.advance(10)
        await expectCheck(rd, .askRestart)
        XCTAssertEqual(d.restarts, 0)
    }

    func testAMismatchThatClearsByItselfEndsThePeriodQuietly() async {
        let w = World(), r = recovery(w)
        w.old(3)
        await expectCheck(r, .nothing)
        w.advance(5); w.new()  // someone ran `grantpin service install` from a terminal
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.noticeText)
        XCTAssertNil(r.restartedAt)
        XCTAssertNil(r.nextCheck())
        w.advance(60)
        await expectCheck(r, .nothing)
    }

    func testTheAskWaitsForThePopoverToCloseButThePeriodCountsAsAsked() async {
        let w = World(), r = recovery(w)
        w.old(nil); w.popover = true
        _ = await r.check(); w.advance(10)
        await expectCheck(r, .nothing, "the person is looking at the line")
        w.popover = false
        await expectCheck(r, .nothing, "asked, as far as the period is concerned")
    }

    func testOnboardingDevelopmentLocationAndSuspendedRestartNothing() async {
        let w = World(), r = recovery(w)
        w.onboarding = true
        _ = await r.check(); w.advance(60); _ = await r.check()
        XCTAssertEqual(w.restarts, 0)
        XCTAssertEqual(w.refreshes, 0)
        XCTAssertNil(r.nextCheck())
        w.onboarding = false
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1, "onboarding done: the restart goes ahead")

        let dev = World(), rd = recovery(dev, dev: true)
        _ = await rd.check(); dev.advance(60)
        await expectCheck(rd, .nothing)
        XCTAssertEqual(dev.restarts, 0)
        XCTAssertEqual(dev.refreshes, 0)

        let away = World(), ra = recovery(away, location: .elsewhere)
        _ = await ra.check(); away.advance(60)
        await expectCheck(ra, .nothing)
        XCTAssertEqual(away.restarts, 0)
        XCTAssertNil(ra.nextCheck())

        let held = World(), rh = recovery(held)
        held.suspended = true
        _ = await rh.check(); held.advance(60)
        await expectCheck(rh, .nothing)
        XCTAssertEqual(held.restarts, 0)
        XCTAssertEqual(held.refreshes, 0)
        XCTAssertNil(rh.nextCheck(), "nothing time-based: the app looks again when the action ends")
        held.suspended = false
        await expectCheck(rh, .nothing)
        XCTAssertEqual(held.restarts, 1)
    }

    func testAnUnknownHelperVersionMeansNoMismatchYet() async {
        let w = World(), r = recovery(w)
        w.helper = nil
        _ = await r.check(); w.advance(60)
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 0)
        XCTAssertNil(r.nextCheck())
        // the helper answered `--version`: the app looks again and sees the mismatch
        w.helper = "0.2.5"
        await expectCheck(r, .nothing)
        XCTAssertEqual(w.restarts, 1)
    }

    func testTheRestoreTestsDoNotSeeTheRestart() async {
        // The restore world of ServiceRecoveryTests: a daemon that is down and no helper version.
        let w = World(), r = recovery(w)
        w.state = .notRunning; w.helper = nil
        _ = await r.check(); w.advance(10)
        await expectCheck(r, .askNow, "the job is stopped, not missing: asked, not restored")
        XCTAssertEqual(w.restarts, 0)
        XCTAssertEqual(w.diagnoses, 1)
    }
}
