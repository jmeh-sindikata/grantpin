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

        var allowsRestore: Bool {
            markerPresent && diagnosis == .notInstalled && !onboardingPending && !isDevelopment
                && location.isOK && vaultExists && !suspended
        }
    }

    public private(set) var downSince: Date?
    /// The one attempt of this launch has been used.
    public private(set) var attempted = false

    public init() {}

    /// Notes whether the daemon is down. Only `.notRunning` is down; no answer
    /// yet changes nothing.
    public mutating func observe(_ state: ConnectionState?, now: Date) {
        guard let state else { return }
        if case .notRunning = state {
            if downSince == nil { downSince = now }
        } else {
            downSince = nil
        }
    }

    /// The daemon has been down for the grace period and the attempt is unused.
    public func isDue(now: Date) -> Bool {
        guard !attempted, let since = downSince else { return false }
        return now.timeIntervalSince(since) >= Self.grace
    }

    /// True exactly once at most: the app should restore the service now.
    public mutating func evaluate(_ state: ConnectionState?, _ inputs: Inputs, now: Date) -> Bool {
        observe(state, now: now)
        guard isDue(now: now), inputs.allowsRestore else { return false }
        attempted = true
        return true
    }

    /// Seconds until the grace period ends, nil when no attempt is pending.
    public func waitTime(now: Date) -> TimeInterval? {
        guard !attempted, let since = downSince else { return nil }
        return max(Self.grace - now.timeIntervalSince(since), 0)
    }
}

/// Restores the service when the policy says so, and otherwise hands over to
/// the visible ask. The UI calls `check()` on every connection change and
/// again after `nextCheck()` seconds, and opens the ask window when it
/// answers `.askNow`.
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
    @ObservationIgnored private let connection: @MainActor () -> ConnectionState?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let markerPresent: () -> Bool
    @ObservationIgnored private let vaultExists: () -> Bool
    @ObservationIgnored private let location: AppLocation
    @ObservationIgnored private let isDevelopment: Bool
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
        self.onboardingPending = onboardingPending; self.popoverOpen = popoverOpen; self.suspended = suspended
        self.markerPresent = markerPresent; self.vaultExists = vaultExists; self.now = now
        self.diagnose = diagnose; self.restore = restore
    }

    /// One look at the situation. Restores the service when allowed (once per
    /// launch); when that fails, or does not apply, lets the ask decide.
    public func check() async -> Verdict {
        guard !isRestoring else { return .nothing }
        policy.observe(connection(), now: now())
        if policy.isDue(now: now()), markerPresent() {
            let diagnosis = await diagnose()
            let inputs = ServiceRestorePolicy.Inputs(
                markerPresent: markerPresent(), diagnosis: diagnosis, onboardingPending: onboardingPending(),
                isDevelopment: isDevelopment, location: location, vaultExists: vaultExists(), suspended: suspended())
            if policy.evaluate(connection(), inputs, now: now()) {
                isRestoring = true
                let result = await restore()
                isRestoring = false
                if result?.outcome == .succeeded {
                    restoredAt = now()
                    gate.resolve()
                    return .nothing
                }
            }
        }
        // Another check may have started a restore while this one waited.
        guard !isRestoring else { return .nothing }
        let ask = gate.evaluate(connection(), now: now(), onboardingPending: onboardingPending(),
                                isDevelopment: isDevelopment, popoverOpen: popoverOpen())
        return ask ? .askNow : .nothing
    }

    /// Seconds until `check()` should run again, nil when nothing is pending.
    public func nextCheck() -> TimeInterval? {
        guard !isRestoring else { return nil }
        let t = now()
        return [gate.waitTime(now: t), policy.waitTime(now: t)].compactMap { $0 }.min()
    }

    /// "grantpin restored its background service." for a while after a restore.
    public func noticeText(at date: Date? = nil) -> String? {
        guard let restoredAt, (date ?? now()).timeIntervalSince(restoredAt) < Self.noticeDuration else { return nil }
        return Self.restoredNotice
    }
}
