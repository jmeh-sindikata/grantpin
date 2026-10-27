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

/// When the app may restart the background service by itself after an update
/// (docs/UI-SPEC.md 3.1 "Updated, restart needed"): the daemon answers with a
/// version other than the helper's (the old daemon kept running through a
/// `brew upgrade` or a replaced app), it reports that no run is in progress,
/// and nothing about the situation is unusual. At most one attempt per app
/// launch, so a failure never turns into a loop. A mismatch the app may not
/// fix by itself opens the visible ask once per mismatch period: a run in
/// progress or a daemon too old to report its runs (both after `grace`, so a
/// command that finishes in a moment never opens a window), a failed attempt,
/// or an old daemon still answering after the restart.
///
/// A mismatch period starts when the daemon is first seen answering with
/// another version than the helper's and ends when the versions agree again
/// or the daemon is not running (the missing-service logic takes over then).
/// "Later" in the window closes it for the period; the automatic restart is
/// still made once nothing runs through the service, if the attempt is unused.
///
/// Pure: the caller passes what it sees and the time.
public struct ServiceRestartPolicy: Sendable {
    /// How long an unsafe mismatch is waited out before the ask, and how long
    /// a restarted daemon has to be seen answering with the new version.
    public static let grace: TimeInterval = ServiceRestorePolicy.grace

    public struct Inputs: Equatable, Sendable {
        /// `in_flight_runs` of the status seen; nil when the daemon predates
        /// the field (the 0.2.4 daemon during the first upgrade to 0.2.5).
        public var inFlightRuns: Int?
        public var onboardingPending: Bool
        public var isDevelopment: Bool
        public var location: AppLocation
        /// Something else is changing the service right now (see
        /// `ServiceRestorePolicy.Inputs.suspended`).
        public var suspended: Bool

        public init(inFlightRuns: Int?, onboardingPending: Bool = false, isDevelopment: Bool = false,
                    location: AppLocation = .ok, suspended: Bool = false) {
            self.inFlightRuns = inFlightRuns; self.onboardingPending = onboardingPending
            self.isDevelopment = isDevelopment; self.location = location; self.suspended = suspended
        }

        /// Nothing runs through the service, as far as the daemon can tell. A
        /// daemon that does not say (nil) is not idle: restarting it could cut
        /// a command off in the middle of a release.
        public var isIdle: Bool { inFlightRuns == 0 }
        /// Anything may be decided at all: not during first-run onboarding or
        /// in development mode, only from an Applications folder, and not
        /// while something else is changing the service.
        var permitsDecision: Bool { !onboardingPending && !isDevelopment && location.isOK && !suspended }
    }

    public enum Verdict: Equatable, Sendable {
        case nothing
        /// Restart the service now (the attempt is used by this answer).
        case restart
        /// Open the "background service" window with the updated line (the
        /// period is asked about by this answer).
        case ask
    }

    /// What became of a restart in progress.
    public enum PendingOutcome: Equatable, Sendable {
        /// Not seen with the new version yet, within the grace.
        case waiting
        /// Seen answering with the helper's version: the period is over.
        case fixed
        /// Still answering with the old version after the grace: the ask is due.
        case persists
        /// Not answering after the grace: the missing-service logic takes over.
        case lost
    }

    /// Since when the mismatch has been seen: the period in progress. Nil
    /// while the versions agree or the daemon is not running.
    public private(set) var mismatchSince: Date?
    /// The one attempt of this launch has been used.
    public private(set) var attempted = false
    /// The ask window opened, or was ruled out, for this period.
    public private(set) var asked = false
    /// This period's attempt failed or did not fix it: the ask is due at once.
    public private(set) var attemptFailed = false
    /// `service install` ran and said the job is up or started: since when the
    /// policy waits to see the daemon answer with the helper's version.
    public private(set) var pendingSince: Date?

    public init() {}

    /// The daemon answers with a version other than the helper's. The
    /// protocol version does not matter here: a daemon that is out of step
    /// is fixed by the same `service install` (its line says Repair).
    public static func isMismatch(_ state: ConnectionState?, helperVersion: String?) -> Bool {
        guard case .ready(let s)? = state, let h = helperVersion else { return false }
        return s.version != h
    }

    /// The daemon answers with the helper's version.
    public static func isFixed(_ state: ConnectionState?, helperVersion: String?) -> Bool {
        guard case .ready(let s)? = state, let h = helperVersion else { return false }
        return s.version == h
    }

    /// Follows the connection without deciding anything. A restart in progress
    /// is judged by `resolvePending` instead, so the moment the job is down
    /// while it restarts does not end the period.
    public mutating func observe(_ state: ConnectionState?, helperVersion: String?, now: Date) {
        guard pendingSince == nil else { return }
        switch state {
        case .ready(let s)?:
            guard let h = helperVersion else { return }
            if s.version != h {
                if mismatchSince == nil { startPeriod(now) }
            } else {
                endPeriod()
            }
        case .notRunning?:
            endPeriod()
        case nil, .locked?, .notInitialized?:
            break  // nothing learned about the version
        }
    }

    private mutating func startPeriod(_ now: Date) {
        mismatchSince = now
        asked = false
        attemptFailed = false
    }

    private mutating func endPeriod() {
        mismatchSince = nil
        asked = false
        attemptFailed = false
    }

    /// Whether `evaluate` would answer `.restart` or `.ask` now on the
    /// strength of the daemon's activity, so the caller can spend a poll on
    /// fresher facts before a decision rests on them. The ask after a failed
    /// attempt does not depend on activity and is not announced here.
    public func decisionDue(_ state: ConnectionState?, helperVersion: String?, _ inputs: Inputs, now: Date) -> Bool {
        guard Self.isMismatch(state, helperVersion: helperVersion), pendingSince == nil, inputs.permitsDecision,
              !attemptFailed else { return false }
        if !attempted, inputs.isIdle { return true }
        guard !asked else { return false }
        return now.timeIntervalSince(mismatchSince ?? now) >= Self.grace
    }

    /// Call on every look. `.restart` at most once per launch, `.ask` at most
    /// once per period, `.nothing` otherwise.
    public mutating func evaluate(_ state: ConnectionState?, helperVersion: String?, _ inputs: Inputs, now: Date) -> Verdict {
        observe(state, helperVersion: helperVersion, now: now)
        guard let since = mismatchSince, pendingSince == nil, inputs.permitsDecision,
              Self.isMismatch(state, helperVersion: helperVersion) else { return .nothing }
        if !attempted, inputs.isIdle {
            attempted = true
            return .restart
        }
        // No restart now: a run in progress, a daemon that cannot say, the
        // attempt used or failed. The person is told, once per period, after
        // a grace for a run to finish; a failed attempt is told at once.
        guard !asked else { return .nothing }
        if attemptFailed || now.timeIntervalSince(since) >= Self.grace {
            asked = true
            return .ask
        }
        return .nothing
    }

    /// `service install` ran and said the job is up, or started but not
    /// answering yet: the mismatch counts as fixed once the daemon is seen
    /// answering with the helper's version, within a fresh grace.
    public mutating func noteRestartStarted(now: Date) { pendingSince = now }

    /// `service install` failed, or nothing ran: the ask is due.
    public mutating func noteRestartFailed() { attemptFailed = true }

    /// A restart in progress has had its grace.
    public func pendingGraceOver(now: Date) -> Bool {
        guard let since = pendingSince else { return false }
        return now.timeIntervalSince(since) >= Self.grace
    }

    /// Judges a restart in progress on the state seen now; nil when none is.
    public mutating func resolvePending(_ state: ConnectionState?, helperVersion: String?, now: Date) -> PendingOutcome? {
        guard pendingSince != nil else { return nil }
        let over = pendingGraceOver(now: now)
        if Self.isFixed(state, helperVersion: helperVersion) {
            pendingSince = nil
            endPeriod()
            return .fixed
        }
        if Self.isMismatch(state, helperVersion: helperVersion) {
            guard over else { return .waiting }
            pendingSince = nil
            attemptFailed = true
            return .persists
        }
        guard over else { return .waiting }
        pendingSince = nil
        endPeriod()
        return .lost
    }

    /// Seconds until a time-based decision is due, nil when none is: the rest
    /// of the grace of a restart in progress, or of an unsafe mismatch that
    /// has not been asked about. Never zero.
    public func waitTime(now: Date) -> TimeInterval? {
        let remaining: TimeInterval
        if let p = pendingSince {
            remaining = Self.grace - now.timeIntervalSince(p)
        } else if let since = mismatchSince, !asked, !attemptFailed {
            remaining = Self.grace - now.timeIntervalSince(since)
        } else {
            return nil
        }
        return remaining > 0 ? remaining : nil
    }
}

/// Restores the service when the policy says so, restarts it after an update
/// when the restart policy says so, and otherwise hands over to the visible
/// ask. The UI calls `check()` on every connection change, whenever a fact a
/// decision depends on changes (a service action ending, onboarding finishing,
/// what `service status` says, the helper's version becoming known) and again
/// after `nextCheck()` seconds, and opens the ask window when it answers
/// `.askNow` or `.askRestart`.
@Observable
@MainActor
public final class ServiceRecovery {
    public enum Verdict: Equatable, Sendable {
        case nothing
        /// Open the "background service" window: the service is missing or stopped.
        case askNow
        /// Open the "background service" window: the service was updated and
        /// needs a restart the app may not, or could not, make by itself.
        case askRestart
    }

    public static let restoredNotice = "grantpin restored its background service."
    public static let restoredAtPrefix = "Restored automatically on "
    public static let restartedNotice = "grantpin restarted its background service after the update."
    public static let restartedAtPrefix = "Restarted automatically on "
    /// How long a notice stays in the status header.
    public nonisolated static let noticeDuration: TimeInterval = 600

    /// When the last automatic restore succeeded in this launch (Settings >
    /// General shows it).
    public private(set) var restoredAt: Date?
    /// When the last automatic restart after an update succeeded in this
    /// launch (the daemon seen answering with the new version).
    public private(set) var restartedAt: Date?
    /// `restoredNotice` for the status header: from the restore (the moment
    /// the restored daemon is seen answering) for `noticeDuration`, or until
    /// it stops again (a red headline must not carry a green "restored"
    /// line). Nil otherwise. The expiry is read off the clock: `check()`
    /// clears it once `noticeDuration` has passed and `nextCheck()` says how
    /// long that is, so no timer of its own runs here.
    public private(set) var noticeText: String?
    /// When `noticeText` was shown; nil while there is none.
    @ObservationIgnored private var noticeSince: Date?
    /// An automatic restore, or an automatic restart after an update, is
    /// running: a service action like any other, so the other controls wait.
    public private(set) var isRestoring = false

    @ObservationIgnored private var policy = ServiceRestorePolicy()
    @ObservationIgnored private var restartPolicy = ServiceRestartPolicy()
    @ObservationIgnored private var gate = ServiceAskGate()
    /// `service install` ran and said the job is up, or started but not
    /// answering yet (docs/UI-SPEC.md 2.5): since when the decision waits for
    /// the daemon to be seen answering, a fresh grace long. Only that counts
    /// as a restore; a job that dies before it is seen gets the ask.
    @ObservationIgnored private var pendingSince: Date?
    /// The monitor is being asked before a pending restore or restart is given up.
    @ObservationIgnored private var refreshingForPending = false
    /// The monitor is being asked before a restart is decided on.
    @ObservationIgnored private var refreshingForRestart = false
    @ObservationIgnored private let connection: @MainActor () -> ConnectionState?
    @ObservationIgnored private let helperVersion: @MainActor () -> String?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let markerPresent: () -> Bool
    @ObservationIgnored private let vaultExists: () -> Bool
    @ObservationIgnored private let location: AppLocation
    @ObservationIgnored private let isDevelopment: Bool
    /// Neither development mode nor where the app runs from rules a restore
    /// or a restart out; both are fixed for this launch, so otherwise the
    /// policies are never consulted.
    @ObservationIgnored private let restorePossible: Bool
    @ObservationIgnored private let onboardingPending: @MainActor () -> Bool
    @ObservationIgnored private let popoverOpen: @MainActor () -> Bool
    @ObservationIgnored private let suspended: @MainActor () -> Bool
    @ObservationIgnored private let refresh: @MainActor () async -> Void
    @ObservationIgnored private let diagnose: @MainActor () async -> ServiceDiagnosis?
    @ObservationIgnored private let restore: @MainActor () async -> ActionResult?
    @ObservationIgnored private let restart: @MainActor () async -> ActionResult?

    /// - Parameters:
    ///   - now: the clock; tests pass their own.
    ///   - refresh: polls the daemon now (the monitor), so that a pending
    ///     restore or restart is judged on the current state, not on a poll
    ///     from before, and a restart on the daemon's current activity.
    ///   - diagnose: asks the helper what `service status` says now.
    ///   - restore: runs what the Start button runs; nil when nothing ran.
    ///   - helperVersion: the helper's `--version` as the app knows it (nil
    ///     while unknown); the app determines it once per launch.
    ///   - restart: runs what the Restart button runs; nil when nothing ran.
    public init(
        connection: @escaping @MainActor () -> ConnectionState?,
        location: AppLocation, isDevelopment: Bool,
        onboardingPending: @escaping @MainActor () -> Bool,
        popoverOpen: @escaping @MainActor () -> Bool = { false },
        suspended: @escaping @MainActor () -> Bool = { false },
        markerPresent: @escaping () -> Bool = { ServiceMarker.isPresent() },
        vaultExists: @escaping () -> Bool = { ServiceMarker.vaultExists() },
        now: @escaping () -> Date = Date.init,
        refresh: @escaping @MainActor () async -> Void = {},
        diagnose: @escaping @MainActor () async -> ServiceDiagnosis?,
        restore: @escaping @MainActor () async -> ActionResult?,
        helperVersion: @escaping @MainActor () -> String? = { nil },
        restart: @escaping @MainActor () async -> ActionResult? = { nil }
    ) {
        self.connection = connection; self.location = location; self.isDevelopment = isDevelopment
        self.restorePossible = !isDevelopment && location.isOK
        self.onboardingPending = onboardingPending; self.popoverOpen = popoverOpen; self.suspended = suspended
        self.markerPresent = markerPresent; self.vaultExists = vaultExists; self.now = now
        self.refresh = refresh; self.diagnose = diagnose; self.restore = restore
        self.helperVersion = helperVersion; self.restart = restart
    }

    /// One look at the situation. Restores the service when allowed (once per
    /// launch); when that fails, or does not apply, lets the ask decide. With
    /// the daemon answering, restarts it after an update when the restart
    /// policy allows, and otherwise lets that ask decide.
    public func check() async -> Verdict {
        guard !isRestoring else { return .nothing }
        var state = connection()
        let helper = helperVersion()
        if restartPolicy.pendingSince != nil {
            // A restart after an update is in progress: it counts once the
            // daemon is seen answering with the helper's version, within a
            // fresh grace; the monitor is asked before that is given up.
            guard !refreshingForPending else { return .nothing }
            if restartPolicy.pendingGraceOver(now: now()), !ServiceRestartPolicy.isFixed(state, helperVersion: helper) {
                refreshingForPending = true
                await refresh()
                refreshingForPending = false
                state = connection()
            }
            switch restartPolicy.resolvePending(state, helperVersion: helper, now: now()) {
            case .waiting?:
                return .nothing
            case .fixed?:
                recordRestart()
            case .persists?, .lost?, nil:
                break  // persists: the ask decides below; lost: the missing-service logic does
            }
        }
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
        restartPolicy.observe(state, helperVersion: helper, now: now())
        // While something else is changing the service nothing is decided
        // (docs/UI-SPEC.md 3.1): no restore, no restart, and no window over
        // the Uninstall sheet or a running Settings action. The end of that
        // action brings the next look.
        if restorePossible, suspended() { return .nothing }
        if restorePossible {
            var inputs = ServiceRestartPolicy.Inputs(
                inFlightRuns: Self.inFlightRuns(state), onboardingPending: onboardingPending(),
                isDevelopment: isDevelopment, location: location, suspended: false)
            if restartPolicy.decisionDue(state, helperVersion: helper, inputs, now: now()) {
                // A decision rests on the daemon's activity, which the monitor
                // last saw up to a poll interval ago: look once more first.
                guard !refreshingForRestart else { return .nothing }
                refreshingForRestart = true
                await refresh()
                refreshingForRestart = false
                guard !isRestoring else { return .nothing }
                state = connection()
                inputs.inFlightRuns = Self.inFlightRuns(state)
                inputs.suspended = suspended()
            }
            var verdict = restartPolicy.evaluate(state, helperVersion: helper, inputs, now: now())
            if verdict == .restart {
                isRestoring = true
                let result = await restart()
                isRestoring = false
                state = connection()
                switch result?.outcome {
                case .succeeded?, .startedNotAnswering?:
                    // launchd restarted the job; it counts once the monitor
                    // sees the daemon answer with the new version.
                    restartPolicy.noteRestartStarted(now: now())
                case .failed?, nil:
                    restartPolicy.noteRestartFailed()
                }
                // A failed attempt asks at once; a pending one decides nothing more.
                verdict = restartPolicy.evaluate(state, helperVersion: helper, inputs, now: now())
            }
            if verdict == .ask {
                // Not over an open popover: the person is looking at the line
                // already. The period counts as asked either way, as for the gate.
                return popoverOpen() ? .nothing : .askRestart
            }
        }
        let ask = gate.evaluate(state, now: now(), onboardingPending: onboardingPending(),
                                isDevelopment: isDevelopment, popoverOpen: popoverOpen())
        // Asked and restored are alternatives: no silent restore later in this outage.
        if ask { policy.noteAsked() }
        return ask ? .askNow : .nothing
    }

    /// Seconds until `check()` should run again, nil when nothing time-based
    /// is pending (a grace, or the notice's expiry). Never zero: a decision
    /// that is due now was taken by the `check()` just made, and only a later
    /// moment is worth a timer.
    public func nextCheck() -> TimeInterval? {
        guard !isRestoring else { return nil }
        let t = now()
        var waits = [gate.waitTime(now: t), policy.waitTime(now: t), restartPolicy.waitTime(now: t)]
        if let since = pendingSince { waits.append(ServiceRestorePolicy.grace - t.timeIntervalSince(since)) }
        if noticeText != nil, let since = noticeSince { waits.append(Self.noticeDuration - t.timeIntervalSince(since)) }
        return waits.compactMap { $0 }.filter { $0 > 0 }.min()
    }

    /// The restore is done: the daemon the app started has been seen
    /// answering. The notice shows for `noticeDuration` from now, and the gate
    /// starts a fresh period so that the next trouble asks.
    private func recordRestore() {
        let t = now()
        restoredAt = t
        gate.restoredNow(now: t)
        showNotice(Self.restoredNotice, at: t)
    }

    /// The restart is done: the daemon has been seen answering with the new
    /// version. The notice shows for `noticeDuration`, and the gate starts a
    /// fresh period, as after a restore, so that a job that dies right after
    /// its restart is asked about.
    private func recordRestart() {
        let t = now()
        restartedAt = t
        gate.restoredNow(now: t)
        showNotice(Self.restartedNotice, at: t)
    }

    /// `in_flight_runs` of an answering daemon; nil when it is not answering
    /// or does not report it.
    private static func inFlightRuns(_ state: ConnectionState?) -> Int? {
        guard case .ready(let s)? = state else { return nil }
        return s.inFlightRuns
    }

    private func showNotice(_ text: String, at t: Date) {
        noticeText = text
        noticeSince = t
    }

    /// A notice goes once `noticeDuration` has passed, and for good when the
    /// restored or restarted daemon stops again (a red headline must not carry it).
    private func updateNotice(_ state: ConnectionState?) {
        guard noticeText != nil, let since = noticeSince else { return }
        var expired = now().timeIntervalSince(since) >= Self.noticeDuration
        if case .notRunning? = state { expired = true }
        guard expired else { return }
        noticeText = nil
        noticeSince = nil
    }
}
