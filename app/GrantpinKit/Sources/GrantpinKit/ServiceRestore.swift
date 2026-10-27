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
        /// Uninstall sheet, a Settings action, the Start button).
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
    /// Cleared when the daemon answers.
    public private(set) var asked = false

    public init() {}

    /// Notes whether the daemon is down. Only `.notRunning` is down; no answer
    /// yet changes nothing.
    public mutating func observe(_ state: ConnectionState?, now: Date) {
        guard let state else { return }
        if case .notRunning = state {
            if downSince == nil { downSince = now }
        } else {
            downSince = nil
            asked = false
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

    /// When the last automatic restore succeeded in this launch.
    public private(set) var restoredAt: Date?
    /// An automatic restore is running.
    public private(set) var isRestoring = false

    @ObservationIgnored private var policy = ServiceRestorePolicy()
    @ObservationIgnored private var gate = ServiceAskGate()
    /// The restore started the job but the daemon had not answered when
    /// `service install` returned (docs/UI-SPEC.md 2.5): since when the
    /// decision waits for it, a fresh grace long.
    @ObservationIgnored private var pendingSince: Date?
    @ObservationIgnored private let connection: @MainActor () -> ConnectionState?
    @ObservationIgnored private let now: () -> Date
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
    @ObservationIgnored private let diagnose: @MainActor () async -> ServiceDiagnosis?
    @ObservationIgnored private let restore: @MainActor () async -> ActionResult?

    /// - Parameters:
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
        diagnose: @escaping @MainActor () async -> ServiceDiagnosis?,
        restore: @escaping @MainActor () async -> ActionResult?
    ) {
        self.connection = connection; self.location = location; self.isDevelopment = isDevelopment
        self.restorePossible = !isDevelopment && location.isOK
        self.onboardingPending = onboardingPending; self.popoverOpen = popoverOpen; self.suspended = suspended
        self.markerPresent = markerPresent; self.vaultExists = vaultExists; self.now = now
        self.diagnose = diagnose; self.restore = restore
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
                        case .succeeded?:
                            restoredAt = now()
                            gate.resolve()
                        case .startedNotAnswering?:
                            // launchd has the job; the daemon gets a fresh grace to answer.
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
            switch state {
            case .notRunning?, nil:
                if now().timeIntervalSince(since) < ServiceRestorePolicy.grace { return .nothing }
                pendingSince = nil  // it never answered: the ask decides below
            default:
                pendingSince = nil
                restoredAt = now()
            }
        }
        // Every connection seen reaches the gate: after a restore it moves to
        // "up" as soon as the daemon answers, so the next outage asks again.
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

    /// "grantpin restored its background service." for a while after a restore.
    public func noticeText(at date: Date? = nil) -> String? {
        guard let restoredAt, (date ?? now()).timeIntervalSince(restoredAt) < Self.noticeDuration else { return nil }
        return Self.restoredNotice
    }
}
