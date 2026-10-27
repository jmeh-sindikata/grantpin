import Foundation
import Observation

/// The durable fact "the person installed the background service": an empty
/// file `service.wanted` in the vault folder. The `grantpin` command creates
/// it after a successful `service install` and removes it on `service
/// uninstall`; a package manager removing the launchd job leaves it alone.
/// The app only reads it.
public enum ServiceMarker {
    public static let fileName = "service.wanted"
    public static let vaultFileName = "vault.db"

    /// The marker exists as a regular file of this user. A symbolic link, a
    /// folder or someone else's file does not count.
    public static func isPresent(in folder: URL = AppPaths.vaultFolder()) -> Bool {
        isOwnRegularFile(folder.appendingPathComponent(fileName).path)
    }

    /// There is a vault file (the daemon would have something to open).
    public static func vaultExists(in folder: URL = AppPaths.vaultFolder()) -> Bool {
        isOwnRegularFile(folder.appendingPathComponent(vaultFileName).path)
    }

    /// `lstat`, so a link is judged as a link and never followed.
    static func isOwnRegularFile(_ path: String) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return (st.st_mode & S_IFMT) == S_IFREG && st.st_uid == getuid()
    }
}

/// When the app may bring the background service back by itself: only when
/// the person had installed it (the marker), the launchd job is gone (not
/// merely stopped, not "running but not answering"), and nothing about the
/// situation is unusual. At most one attempt per app launch, so a failure never
/// turns into a loop; the visible ask (`ServiceAskGate`) takes over then.
///
/// Pure: the caller passes what it sees and the time.
public struct ServiceRestorePolicy: Sendable {
    /// How long the daemon must have been down first (the same wait as the ask).
    public static let grace: TimeInterval = ServiceAskGate.grace

    public struct Inputs: Equatable, Sendable {
        public var markerPresent: Bool
        public var diagnosis: ServiceDiagnosis?
        public var onboardingPending: Bool
        public var isDevelopment: Bool
        public var location: AppLocation
        public var vaultExists: Bool
        /// Something else is changing the service or the vault right now (the
        /// Uninstall sheet, a Settings action, onboarding's Install, the
        /// popover's Start).
        public var suspended: Bool

        public init(markerPresent: Bool, diagnosis: ServiceDiagnosis?, onboardingPending: Bool = false, isDevelopment: Bool = false,
                    location: AppLocation = .ok, vaultExists: Bool = true, suspended: Bool = false) {
            self.markerPresent = markerPresent; self.diagnosis = diagnosis; self.onboardingPending = onboardingPending
            self.isDevelopment = isDevelopment; self.location = location; self.vaultExists = vaultExists; self.suspended = suspended
        }

        /// Everything but the diagnosis, which costs a helper run: when this
        /// is false there is no point asking for one.
        var allowsRestoreApartFromDiagnosis: Bool {
            markerPresent && !onboardingPending && !isDevelopment && location.isOK && vaultExists && !suspended
        }

        var allowsRestore: Bool { allowsRestoreApartFromDiagnosis && diagnosis == .notInstalled }
    }

    public private(set) var downSince: Date?
    /// The one attempt of this launch has been used.
    public private(set) var attempted = false
    /// The ask window opened for the not-running period in progress: the
    /// person has been shown the situation, so the service is not restored
    /// behind their back later in the same period (the two are alternatives).
    /// Cleared once the daemon has answered for `ServiceAskGate.stableUp`,
    /// the point from which the gate counts the next trouble as a new period;
    /// a shorter up is the same trouble to both.
    public private(set) var asked = false
    /// Since when the daemon has answered, nil while it is down.
    private var upSince: Date?

    public init() {}

    /// Notes whether the daemon is down. Only `.notRunning` is down; no answer
    /// yet changes nothing.
    public mutating func observe(_ state: ConnectionState?, now: Date) {
        guard let state else { return }
        if case .notRunning = state {
            if downSince == nil { downSince = now }
            if let up = upSince, now.timeIntervalSince(up) >= ServiceAskGate.stableUp { asked = false }
            upSince = nil
        } else {
            downSince = nil
            if upSince == nil { upSince = now }
            if let up = upSince, now.timeIntervalSince(up) >= ServiceAskGate.stableUp { asked = false }
        }
    }

    /// The daemon has been down for the grace period, the attempt is unused
    /// and this period has not been asked about.
    public func isDue(now: Date) -> Bool {
        guard !attempted, !asked, let since = downSince else { return false }
        return now.timeIntervalSince(since) >= Self.grace
    }

    /// True exactly once at most: the app should restore the service now.
    public mutating func evaluate(_ state: ConnectionState?, _ inputs: Inputs, now: Date) -> Bool {
        observe(state, now: now)
        guard isDue(now: now), inputs.allowsRestore else { return false }
        attempted = true
        return true
    }

    /// The ask window opened for this period (see `asked`).
    public mutating func noteAsked() { asked = true }

    /// Seconds until the grace period ends, nil when nothing is pending: no
    /// outage, the attempt used, the period asked about, or the grace already
    /// over. Once it is over, time changes nothing more: a restore is due at
    /// once or ruled out by a fact, and the caller re-checks when a fact
    /// changes rather than on a timer.
    public func waitTime(now: Date) -> TimeInterval? {
        guard !attempted, !asked, let since = downSince else { return nil }
        let remaining = Self.grace - now.timeIntervalSince(since)
        return remaining > 0 ? remaining : nil
    }
}

/// Restores the service when the policy says so, and otherwise hands over to
/// the visible ask. The UI calls `check()` on every connection change,
/// whenever a fact the decision depends on changes (a service action ending,
/// onboarding finishing, what `service status` says) and again after
/// `nextCheck()` seconds, and opens the ask window when it answers `.askNow`.
@Observable
@MainActor
public final class ServiceRecovery {
    public enum Verdict: Equatable, Sendable {
        case nothing
        /// Open the "background service" window.
        case askNow
    }

    public static let restoredNotice = "grantpin restored its background service."
    public static let restoredAtPrefix = "Restored automatically on "
    /// How long the notice stays in the status header.
    public nonisolated static let noticeDuration: TimeInterval = 600

    /// When the last automatic restore succeeded in this launch (Settings >
    /// General shows it).
    public private(set) var restoredAt: Date?
    /// `restoredNotice` for the status header: from the restore (the moment
    /// the restored daemon is seen answering) for `noticeDuration`, or until
    /// it stops again (a red headline must not carry a green "restored"
    /// line). Nil otherwise.
    public private(set) var noticeText: String?
    /// An automatic restore is running.
    public private(set) var isRestoring = false

    @ObservationIgnored private var policy = ServiceRestorePolicy()
    @ObservationIgnored private var gate = ServiceAskGate()
    /// `service install` ran and said the job is up, or started but not
    /// answering yet (docs/UI-SPEC.md 2.5): since when the decision waits for
    /// the daemon to be seen answering, a fresh grace long. Only that counts
    /// as a restore; a job that dies before it is seen gets the ask.
    @ObservationIgnored private var pendingSince: Date?
    /// The monitor is being asked before a pending restore is given up.
    @ObservationIgnored private var refreshingForPending = false
    @ObservationIgnored private var noticeExpiry: Task<Void, Never>?
    @ObservationIgnored private let connection: @MainActor () -> ConnectionState?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let sleep: @Sendable (TimeInterval) async throws -> Void
    @ObservationIgnored private let markerPresent: () -> Bool
    @ObservationIgnored private let vaultExists: () -> Bool
    @ObservationIgnored private let location: AppLocation
    @ObservationIgnored private let isDevelopment: Bool
    /// Neither development mode nor where the app runs from rules a restore
    /// out; both are fixed for this launch, so otherwise the policy is never
    /// consulted.
    @ObservationIgnored private let restorePossible: Bool
    @ObservationIgnored private let onboardingPending: @MainActor () -> Bool
    @ObservationIgnored private let popoverOpen: @MainActor () -> Bool
    @ObservationIgnored private let suspended: @MainActor () -> Bool
    @ObservationIgnored private let refresh: @MainActor () async -> Void
    @ObservationIgnored private let diagnose: @MainActor () async -> ServiceDiagnosis?
    @ObservationIgnored private let restore: @MainActor () async -> ActionResult?

    /// - Parameters:
    ///   - sleep: waits for the notice to expire; tests pass their own.
    ///   - refresh: polls the daemon now (the monitor), so that a pending
    ///     restore is judged on the current state, not on a poll from before.
    ///   - diagnose: asks the helper what `service status` says now.
    ///   - restore: runs what the Start button runs; nil when nothing ran.
    public init(
        connection: @escaping @MainActor () -> ConnectionState?,
        location: AppLocation, isDevelopment: Bool,
        onboardingPending: @escaping @MainActor () -> Bool,
        popoverOpen: @escaping @MainActor () -> Bool = { false },
        suspended: @escaping @MainActor () -> Bool = { false },
        markerPresent: @escaping () -> Bool = { ServiceMarker.isPresent() },
        vaultExists: @escaping () -> Bool = { ServiceMarker.vaultExists() },
        now: @escaping () -> Date = Date.init,
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { seconds in
            try await Task.sleep(nanoseconds: UInt64(max(seconds, 0) * 1_000_000_000))
        },
        refresh: @escaping @MainActor () async -> Void = {},
        diagnose: @escaping @MainActor () async -> ServiceDiagnosis?,
        restore: @escaping @MainActor () async -> ActionResult?
    ) {
        self.connection = connection; self.location = location; self.isDevelopment = isDevelopment
        self.restorePossible = !isDevelopment && location.isOK
        self.onboardingPending = onboardingPending; self.popoverOpen = popoverOpen; self.suspended = suspended
        self.markerPresent = markerPresent; self.vaultExists = vaultExists; self.now = now; self.sleep = sleep
        self.refresh = refresh; self.diagnose = diagnose; self.restore = restore
    }

    /// One look at the situation. Restores the service when allowed (once per
    /// launch); when that fails, or does not apply, lets the ask decide.
    public func check() async -> Verdict {
        guard !isRestoring else { return .nothing }
        var state = connection()
        if restorePossible {
            policy.observe(state, now: now())
            if policy.isDue(now: now()) {
                // The free facts first; the helper is asked only when they leave a restore possible.
                var inputs = ServiceRestorePolicy.Inputs(
                    markerPresent: markerPresent(), diagnosis: nil, onboardingPending: onboardingPending(),
                    isDevelopment: isDevelopment, location: location, vaultExists: vaultExists(), suspended: suspended())
                if inputs.allowsRestoreApartFromDiagnosis {
                    inputs.diagnosis = await diagnose()
                    inputs.suspended = suspended()
                    state = connection()
                    if policy.evaluate(state, inputs, now: now()) {
                        isRestoring = true
                        let result = await restore()
                        isRestoring = false
                        // The monitor may have seen the daemon answer while the
                        // restore ran; that look returned early above, so the
                        // connection is read again before anything decides.
                        state = connection()
                        policy.observe(state, now: now())
                        switch result?.outcome {
                        case .succeeded?, .startedNotAnswering?:
                            // launchd has the job; the restore counts once the
                            // monitor sees the daemon answer, within a fresh grace.
                            pendingSince = now()
                        case .failed?, nil:
                            break  // the ask decides below
                        }
                    }
                }
            }
        }
        // Another check may have started a restore while this one waited.
        guard !isRestoring else { return .nothing }
        if let since = pendingSince {
            // A look while the poll below runs would judge the same stale state.
            guard !refreshingForPending else { return .nothing }
            if now().timeIntervalSince(since) >= ServiceRestorePolicy.grace, state == nil || state == .notRunning {
                // With nothing visible the monitor polls every 15 seconds, longer
                // than this grace: ask it now rather than give up on a poll from before.
                refreshingForPending = true
                await refresh()
                refreshingForPending = false
                state = connection()
            }
            switch state {
            case .notRunning?, nil:
                if now().timeIntervalSince(since) < ServiceRestorePolicy.grace { return .nothing }
                pendingSince = nil  // it never answered: the ask decides below
            default:
                pendingSince = nil
                recordRestore()
            }
        }
        updateNotice(state)
        // Every connection seen reaches the gate, decided on or not, so an
        // outage is counted from when it began and a later one asks again.
        gate.observe(state, now: now())
        // While something else is changing the service nothing is decided
        // (docs/UI-SPEC.md 3.1): no restore, and no window over the Uninstall
        // sheet or a running Settings action. The end of that action brings
        // the next look.
        if restorePossible, suspended() { return .nothing }
        let ask = gate.evaluate(state, now: now(), onboardingPending: onboardingPending(),
                                isDevelopment: isDevelopment, popoverOpen: popoverOpen())
        // Asked and restored are alternatives: no silent restore later in this outage.
        if ask { policy.noteAsked() }
        return ask ? .askNow : .nothing
    }

    /// Seconds until `check()` should run again, nil when nothing time-based
    /// is pending. Never zero: a decision that is due now was taken by the
    /// `check()` just made, and only a later moment is worth a timer.
    public func nextCheck() -> TimeInterval? {
        guard !isRestoring else { return nil }
        let t = now()
        var waits = [gate.waitTime(now: t), policy.waitTime(now: t)]
        if let since = pendingSince { waits.append(ServiceRestorePolicy.grace - t.timeIntervalSince(since)) }
        return waits.compactMap { $0 }.filter { $0 > 0 }.min()
    }

    /// The restore is done: the daemon the app started has been seen
    /// answering. The notice shows and expires `noticeDuration` from now, and
    /// the gate starts a fresh period so that the next trouble asks.
    private func recordRestore() {
        let t = now()
        restoredAt = t
        gate.restoredNow(now: t)
        noticeText = Self.restoredNotice
        noticeExpiry?.cancel()
        let sleep = self.sleep
        noticeExpiry = Task { [weak self] in
            do { try await sleep(Self.noticeDuration) } catch { return }
            guard !Task.isCancelled else { return }
            self?.noticeText = nil
        }
    }

    /// A restored daemon that stops again takes the notice away for good.
    private func updateNotice(_ state: ConnectionState?) {
        guard case .notRunning? = state, noticeText != nil else { return }
        noticeText = nil
        noticeExpiry?.cancel()
        noticeExpiry = nil
    }
}
