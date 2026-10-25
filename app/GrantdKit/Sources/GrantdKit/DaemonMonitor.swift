import Foundation
import Observation

/// What the monitor knows about the daemon (docs/UI-SPEC.md 2.5 and 3.1).
public enum ConnectionState: Equatable, Sendable {
    /// Nothing answers on the socket (or what answers is not usable; see
    /// `DaemonMonitor.lastError`).
    case notRunning
    /// The daemon runs and the vault exists, but the key store is
    /// temporarily unavailable (screen locked, session not yet unlocked). The
    /// daemon retries by itself; `lastError` is its last error, display only.
    case locked(lastError: String?)
    /// The daemon runs and there is no vault yet.
    case notInitialized
    /// The daemon runs and the vault is open.
    case ready(StatusResult)

    /// Maps a `status` answer to a state. A locked vault wins over the
    /// initialised flag: the file exists, the key does not answer.
    public static func from(_ status: StatusResult) -> ConnectionState {
        if status.vaultLocked {
            return .locked(lastError: status.vaultLockedError.isEmpty ? nil : status.vaultLockedError)
        }
        if !status.vaultInitialized { return .notInitialized }
        return .ready(status)
    }
}

/// Anything that can answer `status`. `Client` does; tests use a fake.
public protocol StatusTransport: Sendable {
    func status() async throws -> StatusResult
}

extension Client: StatusTransport {}

/// How often the monitor asks (docs/UI-SPEC.md 2.4).
public struct PollIntervals: Equatable, Sendable {
    /// Popover open or an app window key.
    public var visible: TimeInterval = 3
    /// App running, nothing visible.
    public var background: TimeInterval = 30
    /// Daemon unreachable, something visible.
    public var downVisible: TimeInterval = 3
    /// Daemon unreachable, nothing visible.
    public var downBackground: TimeInterval = 15
    /// While the vault stays locked the interval doubles per poll, up to this.
    public var lockedCeiling: TimeInterval = 30

    public init() {}
}

/// Polls `status` and publishes the connection state.
///
/// There is no push channel from the daemon, so the app asks: every 3 seconds
/// while something is visible and every 30 seconds otherwise, every 3 or 15
/// seconds while the daemon is unreachable, and with a back-off (3, 6, 12, 24,
/// then 30 seconds) while the vault stays locked, so a Mac that is locked for
/// hours is not polled every few seconds. Any change of state starts the
/// schedule over. `refreshNow()` polls at once (system wake, the popover
/// opening).
///
/// The monitor never logs anything: no state, error or status field goes to a
/// logger, a file or the console.
@Observable
@MainActor
public final class DaemonMonitor {
    /// The latest state; nil until the first poll has finished.
    public private(set) var state: ConnectionState?
    /// Why the last poll found no usable daemon, nil when it answered.
    public private(set) var lastError: GrantdError?
    /// Whether something the user can see is open. Set by the UI; picks the
    /// polling interval.
    public var isVisible = false

    @ObservationIgnored private let transport: StatusTransport
    @ObservationIgnored private let intervals: PollIntervals
    @ObservationIgnored private let sleep: @Sendable (TimeInterval) async throws -> Void
    @ObservationIgnored private var loop: Task<Void, Never>?
    @ObservationIgnored private var polling = false
    @ObservationIgnored private var lockedStreak = 0

    public init(
        transport: StatusTransport = Client(),
        intervals: PollIntervals = PollIntervals(),
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { seconds in
            try await Task.sleep(nanoseconds: UInt64(max(seconds, 0) * 1_000_000_000))
        }
    ) {
        self.transport = transport
        self.intervals = intervals
        self.sleep = sleep
    }

    /// Starts polling, first immediately. Does nothing if already started.
    public func start() {
        guard loop == nil else { return }
        let sleep = self.sleep
        loop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.pollOnce()
                let delay = self.nextDelay()
                do { try await sleep(delay) } catch { return }
            }
        }
    }

    /// Stops polling. The last state stays.
    public func stop() {
        loop?.cancel()
        loop = nil
    }

    /// Polls now (a poll already in flight is not duplicated).
    public func refreshNow() async {
        await pollOnce()
    }

    /// One `status` request and the state transition it causes.
    func pollOnce() async {
        guard !polling else { return }
        polling = true
        defer { polling = false }
        let new: ConnectionState
        var failure: GrantdError?
        do {
            new = ConnectionState.from(try await transport.status())
        } catch is CancellationError {
            return
        } catch let e as GrantdError {
            new = .notRunning
            failure = e
        } catch {
            new = .notRunning
            failure = .io("unexpected failure")
        }
        if case .locked = new { lockedStreak += 1 } else { lockedStreak = 0 }
        if state != new { state = new }
        if lastError != failure { lastError = failure }
    }

    /// The wait before the next poll, from the current state and visibility.
    func nextDelay() -> TimeInterval {
        let i = intervals
        switch state {
        case .locked:
            let base = isVisible ? i.visible : i.background
            let doubled = base * pow(2, Double(max(lockedStreak - 1, 0)))
            return min(doubled, max(i.lockedCeiling, base))
        case .notRunning:
            return isVisible ? i.downVisible : i.downBackground
        case .none, .notInitialized, .ready:
            return isVisible ? i.visible : i.background
        }
    }
}
