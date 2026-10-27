import Foundation
import XCTest
@testable import GrantpinKit

final class ServiceMarkerTests: XCTestCase {
    private func folder() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("grantpin-marker-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: d) }
        return d
    }

    func testARegularFileCounts() throws {
        let d = try folder()
        XCTAssertFalse(ServiceMarker.isPresent(in: d))
        XCTAssertTrue(FileManager.default.createFile(atPath: d.appendingPathComponent("service.wanted").path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        XCTAssertTrue(ServiceMarker.isPresent(in: d))
        XCTAssertFalse(ServiceMarker.vaultExists(in: d))
        FileManager.default.createFile(atPath: d.appendingPathComponent("vault.db").path, contents: Data([1]))
        XCTAssertTrue(ServiceMarker.vaultExists(in: d))
    }

    func testASymbolicLinkIsIgnoredEvenToARealFile() throws {
        let d = try folder()
        let real = d.appendingPathComponent("real")
        FileManager.default.createFile(atPath: real.path, contents: Data())
        try FileManager.default.createSymbolicLink(atPath: d.appendingPathComponent("service.wanted").path, withDestinationPath: real.path)
        XCTAssertFalse(ServiceMarker.isPresent(in: d))
        try FileManager.default.createSymbolicLink(atPath: d.appendingPathComponent("vault.db").path, withDestinationPath: real.path)
        XCTAssertFalse(ServiceMarker.vaultExists(in: d))
    }

    func testADanglingLinkAndAFolderAreIgnored() throws {
        let d = try folder()
        try FileManager.default.createSymbolicLink(atPath: d.appendingPathComponent("service.wanted").path, withDestinationPath: "/nonexistent/x")
        XCTAssertFalse(ServiceMarker.isPresent(in: d))
        let d2 = try folder()
        try FileManager.default.createDirectory(at: d2.appendingPathComponent("service.wanted"), withIntermediateDirectories: false)
        XCTAssertFalse(ServiceMarker.isPresent(in: d2))
        XCTAssertFalse(ServiceMarker.isPresent(in: d.appendingPathComponent("missing")))
    }
}

final class ServiceRestorePolicyTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let ok = ServiceRestorePolicy.Inputs(markerPresent: true, diagnosis: .notInstalled)

    private func decide(_ inputs: ServiceRestorePolicy.Inputs, state: ConnectionState? = .notRunning, after: TimeInterval = 10) -> Bool {
        var p = ServiceRestorePolicy()
        p.observe(state, now: t0)
        return p.evaluate(state, inputs, now: t0.addingTimeInterval(after))
    }

    func testTheHappyPathRestores() {
        XCTAssertTrue(decide(ok))
    }

    func testEveryConditionIsNeeded() {
        var i = ok
        i.markerPresent = false; XCTAssertFalse(decide(i), "no marker: the person never installed it")
        i = ok; i.onboardingPending = true; XCTAssertFalse(decide(i), "first-run onboarding")
        i = ok; i.isDevelopment = true; XCTAssertFalse(decide(i), "development mode")
        i = ok; i.location = .elsewhere; XCTAssertFalse(decide(i), "outside Applications")
        i = ok; i.location = .translocated; XCTAssertFalse(decide(i), "translocated copy")
        i = ok; i.vaultExists = false; XCTAssertFalse(decide(i), "no vault")
        i = ok; i.suspended = true; XCTAssertFalse(decide(i), "uninstall or another action running")
    }

    func testOnlyANotInstalledServiceIsRestored() {
        for d: ServiceDiagnosis? in [nil, .exeMissing, .notRunning, .notAnswering(pid: 4), .keepsStopping] {
            XCTAssertFalse(decide(.init(markerPresent: true, diagnosis: d)), "\(String(describing: d))")
        }
    }

    func testOnlyANotRunningDaemonIsRestored() {
        XCTAssertFalse(decide(ok, state: nil))
        XCTAssertFalse(decide(ok, state: .ready(StatusResult())))
        XCTAssertFalse(decide(ok, state: .locked(lastError: nil)))
        XCTAssertFalse(decide(ok, state: .notInitialized))
    }

    func testTheGracePeriodComesFirst() {
        XCTAssertFalse(decide(ok, after: 0))
        XCTAssertFalse(decide(ok, after: ServiceRestorePolicy.grace - 0.1))
        XCTAssertTrue(decide(ok, after: ServiceRestorePolicy.grace))
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        XCTAssertEqual(p.waitTime(now: t0.addingTimeInterval(4)), ServiceRestorePolicy.grace - 4)
        XCTAssertFalse(p.isDue(now: t0.addingTimeInterval(4)))
    }

    func testAtMostOneAttemptPerLaunch() {
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        XCTAssertTrue(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(10)))
        XCTAssertFalse(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(20)))
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(20)))
        // the service came back and went away again: still no second attempt
        p.observe(.ready(StatusResult()), now: t0.addingTimeInterval(30))
        p.observe(.notRunning, now: t0.addingTimeInterval(400))
        XCTAssertFalse(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(420)))
    }

    func testOnceTheGraceIsOverNothingTimeBasedIsPending() {
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(ServiceRestorePolicy.grace)), "due now, not in 0 seconds")
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(60)))
        XCTAssertTrue(p.isDue(now: t0.addingTimeInterval(60)), "still due the moment a fact allows it")
    }

    func testOnceAskedNoRestoreInTheSameOutage() {
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        p.noteAsked()
        XCTAssertFalse(p.isDue(now: t0.addingTimeInterval(10)))
        XCTAssertFalse(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(10)))
        XCTAssertNil(p.waitTime(now: t0.addingTimeInterval(3)))
        XCTAssertFalse(p.attempted, "the attempt is kept for a later outage")
        // the daemon answers and goes down again: a new period
        p.observe(.ready(StatusResult()), now: t0.addingTimeInterval(100))
        XCTAssertFalse(p.asked)
        p.observe(.notRunning, now: t0.addingTimeInterval(200))
        XCTAssertTrue(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(210)))
    }

    func testAnIneligibleLookDoesNotUseTheAttempt() {
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        XCTAssertFalse(p.evaluate(.notRunning, .init(markerPresent: true, diagnosis: .notRunning), now: t0.addingTimeInterval(10)))
        XCTAssertFalse(p.attempted)
        XCTAssertTrue(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(20)))
    }

    func testAnAnsweringDaemonResetsTheClock() {
        var p = ServiceRestorePolicy()
        p.observe(.notRunning, now: t0)
        p.observe(.ready(StatusResult()), now: t0.addingTimeInterval(5))
        XCTAssertNil(p.downSince)
        p.observe(.notRunning, now: t0.addingTimeInterval(8))
        XCTAssertFalse(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(12)))
        XCTAssertTrue(p.evaluate(.notRunning, ok, now: t0.addingTimeInterval(18)))
    }
}

@MainActor
final class ServiceRecoveryTests: XCTestCase {
    final class World {
        var t = Date(timeIntervalSince1970: 1_800_000_000)
        var state: ConnectionState? = .notRunning
        var marker = true
        var vault = true
        var onboarding = false
        var popover = false
        var suspended = false
        var diagnosis: ServiceDiagnosis? = .notInstalled
        var restoreResult: ActionResult? = ActionResult(outcome: .succeeded, summary: "grantpin is running in the background.")
        var restores = 0
        var diagnoses = 0
        func advance(_ s: TimeInterval) { t = t.addingTimeInterval(s) }
    }

    func recovery(_ w: World, location: AppLocation = .ok, dev: Bool = false) -> ServiceRecovery {
        ServiceRecovery(
            connection: { w.state }, location: location, isDevelopment: dev,
            onboardingPending: { w.onboarding }, popoverOpen: { w.popover }, suspended: { w.suspended },
            markerPresent: { w.marker }, vaultExists: { w.vault }, now: { w.t },
            diagnose: { w.diagnoses += 1; return w.diagnosis },
            restore: { w.restores += 1; return w.restoreResult })
    }

    func testSuccessRestoresOnceAndCountsWhenTheDaemonIsSeenAnswering() async {
        let w = World(), r = recovery(w)
        let first = await r.check()
        XCTAssertEqual(first, .nothing)
        XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace)
        XCTAssertNil(r.noticeText)
        w.advance(10)
        let second = await r.check()
        XCTAssertEqual(second, .nothing, "restored: no ask window")
        XCTAssertEqual(w.restores, 1)
        XCTAssertNil(r.restoredAt, "not until the monitor has seen the daemon")
        XCTAssertNil(r.noticeText, "not under a red headline")
        XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace, "a fresh grace for the daemon to answer")
        // the monitor has not caught up yet: the ask must stay quiet
        w.advance(4)
        let third = await r.check()
        XCTAssertEqual(third, .nothing)
        XCTAssertEqual(w.restores, 1)
        XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace - 4)
        // the daemon answers: the restore is recorded and the notice shows
        w.advance(2); w.state = .ready(StatusResult())
        _ = await r.check()
        XCTAssertEqual(r.restoredAt, w.t)
        XCTAssertEqual(r.noticeText, "grantpin restored its background service.")
        XCTAssertEqual(ServiceRecovery.restoredNotice, "grantpin restored its background service.")
        XCTAssertNil(r.nextCheck())
    }

    func testARestoredDaemonThatDiesAgainSoonIsAskedAbout() async {
        let w = World(), r = recovery(w)
        _ = await r.check(); w.advance(10); _ = await r.check()
        w.advance(2); w.state = .ready(StatusResult()); _ = await r.check()
        XCTAssertEqual(r.restoredAt, w.t)
        // down again 30 seconds later: the person saw no window for the restore, so this one asks
        w.advance(30); w.state = .notRunning
        let down = await r.check()
        XCTAssertEqual(down, .nothing)
        XCTAssertNil(r.noticeText)
        XCTAssertEqual(r.nextCheck(), ServiceAskGate.grace)
        w.advance(10)
        let later = await r.check()
        XCTAssertEqual(later, .askNow, "a service that keeps stopping right after its restore gets the window")
        XCTAssertEqual(w.restores, 1)
    }

    func testASuccessNeverSeenAnsweringEndsInTheAsk() async {
        let w = World(), r = recovery(w)
        _ = await r.check(); w.advance(10)
        let restored = await r.check()
        XCTAssertEqual(restored, .nothing)
        XCTAssertEqual(w.restores, 1)
        w.advance(ServiceRestorePolicy.grace)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow, "service install said yes, but the job died before the monitor saw it")
        XCTAssertNil(r.restoredAt)
        XCTAssertNil(r.noticeText)
        XCTAssertNil(r.nextCheck())
    }

    func testTheNoticeGoesWhenTheRestoredDaemonStopsAgain() async {
        let w = World(), r = recovery(w)
        _ = await r.check(); w.advance(10); _ = await r.check()
        w.state = .ready(StatusResult()); _ = await r.check()
        XCTAssertEqual(r.noticeText, ServiceRecovery.restoredNotice)
        w.advance(30); w.state = .notRunning
        _ = await r.check()
        XCTAssertNil(r.noticeText, "a red headline with a green 'restored' line under it would lie")
        XCTAssertEqual(r.restoredAt, w.t.addingTimeInterval(-30), "Settings still says when")
        // answering again does not bring it back
        w.state = .ready(StatusResult()); _ = await r.check()
        XCTAssertNil(r.noticeText)
    }

    func testTheNoticeExpiresByItselfAfterTenMinutes() async throws {
        let w = World()
        let rec = SleepRecorder(), release = ManagedFlag()
        let r = ServiceRecovery(
            connection: { w.state }, location: .ok, isDevelopment: false, onboardingPending: { false },
            markerPresent: { true }, vaultExists: { true }, now: { w.t },
            sleep: { seconds in
                try await rec.sleep(seconds)
                while !release.value { try await Task.sleep(nanoseconds: 1_000_000) }
            },
            diagnose: { .notInstalled }, restore: { ActionResult(outcome: .succeeded, summary: "ok") })
        _ = await r.check(); w.advance(10); _ = await r.check()
        w.state = .ready(StatusResult()); _ = await r.check()
        XCTAssertEqual(r.noticeText, ServiceRecovery.restoredNotice)
        for _ in 0..<200 where rec.count < 1 { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(rec.delays, [ServiceRecovery.noticeDuration])
        XCTAssertEqual(r.noticeText, ServiceRecovery.restoredNotice, "still there while the ten minutes run")
        release.set()
        for _ in 0..<200 where r.noticeText != nil { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertNil(r.noticeText)
        XCTAssertNotNil(r.restoredAt, "Settings still says when")
    }

    func testFailureFallsBackToTheAskWindowExactlyOnce() async {
        let w = World(), r = recovery(w)
        w.restoreResult = ActionResult(outcome: .failed, summary: "launchctl: nope")
        _ = await r.check()
        w.advance(10)
        let failed = await r.check()
        XCTAssertEqual(failed, .askNow)
        XCTAssertEqual(w.restores, 1)
        XCTAssertNil(r.restoredAt)
        XCTAssertNil(r.noticeText)
        w.advance(30)
        for _ in 0..<3 {
            let again = await r.check()
            XCTAssertEqual(again, .nothing, "no second restore, no second ask")
            w.advance(15)
        }
        XCTAssertEqual(w.restores, 1)
    }

    func testStartedButNotAnsweringWaitsAndIsARestoreOnceTheDaemonAnswers() async {
        let w = World(), r = recovery(w)
        w.restoreResult = ActionResult(outcome: .startedNotAnswering, summary: "started")
        _ = await r.check(); w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing, "launchd has the job: no window for a service the app just started")
        XCTAssertEqual(w.restores, 1)
        XCTAssertNil(r.restoredAt)
        XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace, "a fresh grace")
        w.advance(4)
        let still = await r.check()
        XCTAssertEqual(still, .nothing)
        XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace - 4)
        w.advance(2); w.state = .ready(StatusResult())
        let up = await r.check()
        XCTAssertEqual(up, .nothing)
        XCTAssertEqual(r.restoredAt, w.t)
        XCTAssertNil(r.nextCheck())
        // a later outage asks as usual; the one attempt is used
        w.advance(120); w.state = .notRunning; _ = await r.check(); w.advance(10)
        let later = await r.check()
        XCTAssertEqual(later, .askNow)
        XCTAssertEqual(w.restores, 1)
    }

    func testStartedButNotAnsweringAsksOnceTheFreshGraceIsOver() async {
        let w = World(), r = recovery(w)
        w.restoreResult = ActionResult(outcome: .startedNotAnswering, summary: "started")
        _ = await r.check(); w.advance(10)
        _ = await r.check()
        w.advance(ServiceRestorePolicy.grace)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow)
        XCTAssertNil(r.restoredAt)
        XCTAssertNil(r.nextCheck())
        XCTAssertEqual(w.restores, 1)
    }

    func testNothingRanIsAFailureToo() async {
        let w = World(), r = recovery(w)
        w.restoreResult = nil
        _ = await r.check()
        w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow)
    }

    func testWithoutAMarkerTheAskWindowOpensAndNothingIsRestored() async {
        let w = World(), r = recovery(w)
        w.marker = false
        _ = await r.check()
        w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow)
        XCTAssertEqual(w.restores, 0)
        XCTAssertEqual(w.diagnoses, 0, "no marker: the helper is not even asked")
    }

    func testAStoppedButInstalledServiceIsAskedAboutNotRestored() async {
        let w = World(), r = recovery(w)
        w.diagnosis = .notRunning
        _ = await r.check()
        w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow)
        XCTAssertEqual(w.restores, 0)
    }

    func testOnboardingDevelopmentAndLocationNeverRestore() async {
        for (name, setup) in [
            ("onboarding", { (w: World) in w.onboarding = true }),
            ("suspended", { (w: World) in w.suspended = true }),
            ("no vault", { (w: World) in w.vault = false }),
        ] as [(String, (World) -> Void)] {
            let w = World(), r = recovery(w)
            setup(w)
            _ = await r.check(); w.advance(10); _ = await r.check()
            XCTAssertEqual(w.restores, 0, name)
            XCTAssertEqual(w.diagnoses, 0, "\(name): a free fact already says no, so the helper is not asked")
        }
        let dev = World(), rd = recovery(dev, dev: true)
        _ = await rd.check(); dev.advance(10)
        let devVerdict = await rd.check()
        XCTAssertEqual(dev.restores, 0)
        XCTAssertEqual(dev.diagnoses, 0)
        XCTAssertEqual(devVerdict, .nothing)
        let away = World(), ra = recovery(away, location: .elsewhere)
        _ = await ra.check(); away.advance(10)
        let awayVerdict = await ra.check()
        XCTAssertEqual(away.restores, 0)
        XCTAssertEqual(away.diagnoses, 0)
        XCTAssertEqual(awayVerdict, .askNow, "the window shows where the app has to be moved to")
    }

    func testTheHelperIsAskedOnceAndOnlyWhenTheFreeFactsAllowARestore() async {
        let w = World(), r = recovery(w)
        _ = await r.check()
        XCTAssertEqual(w.diagnoses, 0, "not due yet")
        w.advance(10)
        _ = await r.check()
        XCTAssertEqual(w.diagnoses, 1)
        XCTAssertEqual(w.restores, 1)
    }

    func testADaemonSeenAnsweringDuringTheRestoreStillAsksAboutALaterOutage() async {
        let w = World()
        var r: ServiceRecovery!
        r = ServiceRecovery(
            connection: { w.state }, location: .ok, isDevelopment: false, onboardingPending: { false },
            markerPresent: { true }, vaultExists: { true }, now: { w.t },
            diagnose: { .notInstalled },
            restore: {
                // the socket answers before `service install` exits: the monitor's look comes first
                w.state = .ready(StatusResult())
                _ = await r.check()
                return ActionResult(outcome: .succeeded, summary: "ok")
            })
        _ = await r.check(); w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing)
        XCTAssertEqual(r.restoredAt, w.t)
        XCTAssertNil(r.nextCheck())
        // hours later the daemon dies: a new outage, asked about after the grace
        w.advance(3600); w.state = .notRunning
        let down = await r.check()
        XCTAssertEqual(down, .nothing)
        XCTAssertEqual(r.nextCheck(), ServiceAskGate.grace)
        w.advance(10)
        let later = await r.check()
        XCTAssertEqual(later, .askNow)
    }

    func testAnIneligibleLookLeavesNothingToWaitFor() async {
        for (name, setup) in [
            ("no marker", { (w: World) in w.marker = false }),
            ("stopped job", { (w: World) in w.diagnosis = .notRunning }),
        ] as [(String, (World) -> Void)] {
            let w = World(), r = recovery(w)
            setup(w)
            _ = await r.check()
            XCTAssertEqual(r.nextCheck(), ServiceRestorePolicy.grace, name)
            w.advance(10)
            let verdict = await r.check()
            XCTAssertEqual(verdict, .askNow, name)
            XCTAssertNil(r.nextCheck(), "\(name): nothing time-based is left; a 0 would be a tight loop")
            w.advance(30)
            let again = await r.check()
            XCTAssertEqual(again, .nothing, name)
            XCTAssertNil(r.nextCheck(), name)
            XCTAssertEqual(w.restores, 0, name)
        }
    }

    func testOnceAskedNothingIsRestoredBehindThePersonsBackInTheSameOutage() async {
        let w = World(), r = recovery(w)
        w.diagnosis = .notRunning  // the job is there but stopped when the grace ends
        _ = await r.check(); w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .askNow)
        // the job goes missing while the window is up and the app looks again: nothing is installed
        w.diagnosis = .notInstalled
        let after = await r.check()
        XCTAssertEqual(after, .nothing)
        XCTAssertEqual(w.restores, 0)
        XCTAssertNil(r.nextCheck())
        // the daemon answers and later goes away again: the attempt is still there
        w.state = .ready(StatusResult()); _ = await r.check()
        w.advance(120); w.state = .notRunning; _ = await r.check()
        w.advance(10)
        let later = await r.check()
        XCTAssertEqual(later, .nothing)
        XCTAssertEqual(w.restores, 1)
    }

    func testWhileSomethingElseChangesTheServiceNothingIsDecided() async {
        // the Uninstall sheet is open when the grace ends: no restore, and no window over the sheet
        let w = World(), r = recovery(w)
        w.suspended = true
        _ = await r.check(); w.advance(10)
        let during = await r.check()
        XCTAssertEqual(during, .nothing)
        XCTAssertEqual(w.restores, 0)
        XCTAssertEqual(w.diagnoses, 0)
        XCTAssertNil(r.nextCheck(), "nothing time-based: the app looks again when the action ends")
        // the sheet is cancelled: the restore goes ahead
        w.suspended = false
        let after = await r.check()
        XCTAssertEqual(after, .nothing)
        XCTAssertEqual(w.restores, 1)
        // without a marker the window opens then instead
        let bare = World(), rb = recovery(bare)
        bare.marker = false; bare.suspended = true
        _ = await rb.check(); bare.advance(10)
        let bareDuring = await rb.check()
        XCTAssertEqual(bareDuring, .nothing)
        bare.suspended = false
        let bareAfter = await rb.check()
        XCTAssertEqual(bareAfter, .askNow)
        XCTAssertEqual(bare.restores, 0)
    }

    func testAnAnsweringDaemonDoesNothing() async {
        let w = World(), r = recovery(w)
        w.state = .ready(StatusResult())
        _ = await r.check(); w.advance(60)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing)
        XCTAssertEqual(w.restores, 0)
        XCTAssertNil(r.nextCheck())
    }

    func testTheAskDoesNotOpenWhileARestoreIsRunning() async {
        let w = World()
        var r: ServiceRecovery!
        var verdictDuring: ServiceRecovery.Verdict?
        r = ServiceRecovery(
            connection: { w.state }, location: .ok, isDevelopment: false, onboardingPending: { false },
            markerPresent: { true }, vaultExists: { true }, now: { w.t },
            diagnose: { .notInstalled },
            restore: {
                // a second look at the same moment, as a state change would cause
                verdictDuring = await r.check()
                return ActionResult(outcome: .succeeded, summary: "ok")
            })
        _ = await r.check(); w.advance(10)
        let verdict = await r.check()
        XCTAssertEqual(verdict, .nothing)
        XCTAssertEqual(verdictDuring, .nothing)
    }
}
