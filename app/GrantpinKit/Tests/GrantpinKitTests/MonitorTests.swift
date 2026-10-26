import Foundation
import XCTest
@testable import GrantpinKit

/// A transport that answers from a script.
final class FakeTransport: StatusTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [Result<StatusResult, Error>]
    private var calls = 0
    init(_ script: [Result<StatusResult, Error>]) { self.script = script }
    var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls }
    func status() async throws -> StatusResult {
        let next: Result<StatusResult, Error> = lock.withLock {
            calls += 1
            return script.count > 1 ? script.removeFirst() : script[0]
        }
        return try next.get()
    }
}

/// Records the delays the loop asks for and returns at once.
final class SleepRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var delays = [TimeInterval]()
    var count: Int { lock.lock(); defer { lock.unlock() }; return delays.count }
    func sleep(_ d: TimeInterval) async throws {
        lock.withLock { delays.append(d) }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
}

enum Fixture {
    static let ready = StatusResult(version: "v1", pid: 7, vaultInitialized: true, keystoreTier: .hardware, approverTier: .hardware, secrets: 2, activeGrants: 1)
    static let uninit = StatusResult(vaultInitialized: false)
    static let locked = StatusResult(vaultInitialized: true, vaultLocked: true, vaultLockedError: "keychain locked")
}

@MainActor
final class MonitorStateTests: XCTestCase {
    static let ready = Fixture.ready
    static let uninit = Fixture.uninit
    static let locked = Fixture.locked

    private func monitor(_ script: [Result<StatusResult, Error>]) -> (DaemonMonitor, FakeTransport) {
        let t = FakeTransport(script)
        return (DaemonMonitor(transport: t), t)
    }

    func testNoStateBeforeTheFirstPoll() {
        let (m, _) = monitor([.success(Self.ready)])
        XCTAssertNil(m.state)
        XCTAssertNil(m.lastError)
    }

    func testReady() async {
        let (m, _) = monitor([.success(Self.ready)])
        await m.refreshNow()
        XCTAssertEqual(m.state, .ready(Self.ready))
        XCTAssertNil(m.lastError)
    }

    func testNotInitialized() async {
        let (m, _) = monitor([.success(Self.uninit)])
        await m.refreshNow()
        XCTAssertEqual(m.state, .notInitialized)
    }

    func testLockedCarriesTheLastError() async {
        let (m, _) = monitor([.success(Self.locked)])
        await m.refreshNow()
        XCTAssertEqual(m.state, .locked(lastError: "keychain locked"))
        // no message from the daemon: nil, not an empty string
        let (m2, _) = monitor([.success(StatusResult(vaultInitialized: true, vaultLocked: true))])
        await m2.refreshNow()
        XCTAssertEqual(m2.state, .locked(lastError: nil))
    }

    func testNotRunningKeepsTheReason() async {
        let (m, _) = monitor([.failure(GrantpinError.notRunning)])
        await m.refreshNow()
        XCTAssertEqual(m.state, .notRunning)
        XCTAssertEqual(m.lastError, .notRunning)
        // a daemon that is there but answers wrongly is also "no usable daemon", with its reason kept
        let (m2, _) = monitor([.failure(GrantpinError.noResponse)])
        await m2.refreshNow()
        XCTAssertEqual(m2.state, .notRunning)
        XCTAssertEqual(m2.lastError, .noResponse)
    }

    func testTransitionsFollowTheDaemon() async {
        let (m, _) = monitor([
            .failure(GrantpinError.notRunning), .success(Self.uninit), .success(Self.locked), .success(Self.ready),
            .success(Self.ready), .failure(GrantpinError.notRunning),
        ])
        var seen = [ConnectionState?]()
        for _ in 0..<6 { await m.refreshNow(); seen.append(m.state) }
        XCTAssertEqual(seen, [.notRunning, .notInitialized, .locked(lastError: "keychain locked"), .ready(Self.ready), .ready(Self.ready), .notRunning])
        XCTAssertEqual(m.lastError, .notRunning)
        await m.refreshNow()  // script stays on its last element
    }

    func testAnswerClearsThePreviousError() async {
        let (m, _) = monitor([.failure(GrantpinError.timeout), .success(Self.ready)])
        await m.refreshNow()
        XCTAssertEqual(m.lastError, .timeout)
        await m.refreshNow()
        XCTAssertNil(m.lastError)
    }

    func testCancelledPollChangesNothing() async {
        let (m, _) = monitor([.success(Self.ready), .failure(CancellationError())])
        await m.refreshNow()
        await m.refreshNow()
        XCTAssertEqual(m.state, .ready(Self.ready))
    }

    func testClassification() {
        XCTAssertEqual(ConnectionState.from(Self.ready), .ready(Self.ready))
        // a locked vault wins over the initialised flag
        XCTAssertEqual(ConnectionState.from(Self.locked), .locked(lastError: "keychain locked"))
        XCTAssertEqual(ConnectionState.from(StatusResult(vaultInitialized: false, vaultLocked: true)), .locked(lastError: nil))
        XCTAssertEqual(ConnectionState.from(Self.uninit), .notInitialized)
    }
}

@MainActor
final class MonitorScheduleTests: XCTestCase {
    private func monitor(_ script: [Result<StatusResult, Error>]) -> DaemonMonitor {
        DaemonMonitor(transport: FakeTransport(script))
    }

    func testIntervalsFollowVisibility() async {
        let m = monitor([.success(Fixture.ready)])
        await m.refreshNow()
        m.isVisible = true
        XCTAssertEqual(m.nextDelay(), 3)
        m.isVisible = false
        XCTAssertEqual(m.nextDelay(), 30)
    }

    func testNotInitializedPollsLikeReady() async {
        let m = monitor([.success(Fixture.uninit)])
        await m.refreshNow()
        m.isVisible = true
        XCTAssertEqual(m.nextDelay(), 3)
        m.isVisible = false
        XCTAssertEqual(m.nextDelay(), 30)
    }

    func testUnreachableIntervals() async {
        let m = monitor([.failure(GrantpinError.notRunning)])
        await m.refreshNow()
        m.isVisible = true
        XCTAssertEqual(m.nextDelay(), 3)
        m.isVisible = false
        XCTAssertEqual(m.nextDelay(), 15)
    }

    func testBeforeTheFirstPollTheNormalIntervalApplies() {
        let m = monitor([.success(Fixture.ready)])
        XCTAssertEqual(m.nextDelay(), 30)
    }

    func testBacksOffWhileLockedAndResetsWhenItClears() async {
        let m = monitor([.success(Fixture.locked)])
        m.isVisible = true
        var delays = [TimeInterval]()
        for _ in 0..<7 { await m.refreshNow(); delays.append(m.nextDelay()) }
        XCTAssertEqual(delays, [3, 6, 12, 24, 30, 30, 30])

        // hidden: already at the idle interval, never longer than the ceiling
        let hidden = monitor([.success(Fixture.locked)])
        for _ in 0..<4 { await hidden.refreshNow() }
        XCTAssertEqual(hidden.nextDelay(), 30)

        // the vault opens: back to the normal interval at once
        let t = FakeTransport([.success(Fixture.locked), .success(Fixture.locked), .success(Fixture.ready)])
        let m2 = DaemonMonitor(transport: t)
        m2.isVisible = true
        await m2.refreshNow(); await m2.refreshNow()
        XCTAssertEqual(m2.nextDelay(), 6)
        await m2.refreshNow()
        XCTAssertEqual(m2.nextDelay(), 3)
    }

    func testTheLoopPollsAndSleepsForTheComputedDelays() async throws {
        let rec = SleepRecorder()
        let t = FakeTransport([.failure(GrantpinError.notRunning), .success(Fixture.locked), .success(Fixture.locked), .success(Fixture.ready)])
        let m = DaemonMonitor(transport: t, sleep: { try await rec.sleep($0) })
        m.isVisible = true
        m.start()
        m.start()  // a second start is ignored
        for _ in 0..<200 where rec.count < 4 { try await Task.sleep(nanoseconds: 10_000_000) }
        m.stop()
        XCTAssertGreaterThanOrEqual(rec.count, 4)
        XCTAssertEqual(Array(rec.delays.prefix(4)), [3, 3, 6, 3])  // down (visible), locked 1, locked 2, ready
        XCTAssertEqual(m.state, .ready(Fixture.ready))
        let calls = t.callCount
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertLessThanOrEqual(t.callCount, calls + 1, "the loop kept polling after stop()")
    }

    func testOverlappingPollsAreNotDuplicated() async throws {
        final class Slow: StatusTransport, @unchecked Sendable {
            private let lock = NSLock(); private var n = 0
            var calls: Int { lock.lock(); defer { lock.unlock() }; return n }
            func status() async throws -> StatusResult {
                lock.withLock { n += 1 }
                try await Task.sleep(nanoseconds: 200_000_000)
                return Fixture.ready
            }
        }
        let slow = Slow()
        let m = DaemonMonitor(transport: slow)
        async let a: Void = m.refreshNow()
        async let b: Void = m.refreshNow()
        _ = await (a, b)
        XCTAssertEqual(slow.calls, 1)
    }
}

/// One test against the real dev daemon: the monitor follows it through
/// "no vault", "ready" and "stopped".
@MainActor
final class MonitorDevDaemonTests: DevDaemonCase {
    func testMonitorFollowsTheDevDaemon() async throws {
        let m = DaemonMonitor(transport: client)
        await m.refreshNow()
        XCTAssertEqual(m.state, .notRunning)
        XCTAssertEqual(m.lastError, .notRunning)

        try await startDaemon(initVault: false)
        await m.refreshNow()
        XCTAssertEqual(m.state, .notInitialized)
        XCTAssertNil(m.lastError)

        try initVault()  // the running daemon picks the vault up without a restart
        await m.refreshNow()
        guard case .ready(let s)? = m.state else { return XCTFail("state = \(String(describing: m.state))") }
        XCTAssertEqual(s.secrets, 0)
        XCTAssertEqual(s.socket, socket)

        try await put("MON", "monitor-test-value-1")
        await m.refreshNow()
        guard case .ready(let s2)? = m.state else { return XCTFail() }
        XCTAssertEqual(s2.secrets, 1)

        stopDaemon()
        await m.refreshNow()
        XCTAssertEqual(m.state, .notRunning)
    }
}
