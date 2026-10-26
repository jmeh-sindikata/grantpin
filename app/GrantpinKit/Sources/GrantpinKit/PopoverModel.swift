import Foundation
import Observation

/// What the status line at the top of the popover says (docs/UI-SPEC.md 3.1).
public struct StatusLine: Equatable, Sendable {
    public enum Level: Equatable, Sendable {
        /// Not known yet.
        case neutral
        case ok
        case warning
        case error
    }

    public enum Button: Equatable, Sendable {
        /// "Start": installs and starts the background service.
        case startService
        /// "Create vault…" (runs `init`; onboarding uses `.setUp` instead).
        case createVault
        /// "Set Up…": opens onboarding at the vault step.
        case setUp
        /// "Repair": `service install` again, for a service that points to a
        /// missing file or speaks another protocol version.
        case repair
        /// "Restart": `service install`, which restarts the job.
        case restart
        /// "Review": opens the Grants window.
        case review
        /// "Open Logs Folder".
        case openLogs

        public var title: String {
            switch self {
            case .startService: return "Start"
            case .createVault: return "Create vault…"
            case .setUp: return "Set Up…"
            case .repair: return "Repair"
            case .restart: return "Restart"
            case .review: return "Review"
            case .openLogs: return "Open Logs Folder"
            }
        }
    }

    public var level: Level
    public var headline: String
    public var detail: String?
    public var button: Button?
    /// A second button next to the first ("Open Logs Folder").
    public var secondButton: Button?
    /// Counts for the ready state.
    public var secrets: Int?
    public var activeGrants: Int?
    /// `tampered_grants` of the daemon, when above zero.
    public var tamperedGrants: Int?

    /// The warning shown under the counts when grants failed verification.
    public var tamperedWarning: String? {
        guard let n = tamperedGrants, n > 0 else { return nil }
        return "TAMPERED: \(n) \(n == 1 ? "grant failed" : "grants failed") verification. Open Grants to review."
    }

    /// Derives the line from the monitor's state. The locked error is the
    /// daemon's own text and is sanitised. `service` is what `service status`
    /// found while the daemon was down; `helperVersion` is the helper's
    /// `--version` (nil when unknown).
    public static func from(_ state: ConnectionState?, lastError: GrantpinError? = nil,
                            service: ServiceDiagnosis? = nil, helperVersion: String? = nil) -> StatusLine {
        switch state {
        case nil:
            return StatusLine(level: .neutral, headline: "Checking…")
        case .notRunning?:
            if case .socketPathTooLong? = lastError {
                return StatusLine(level: .error, headline: "Daemon not running",
                                  detail: "Your account name is too long for grantpin's default socket path.", button: .startService)
            }
            if let service {
                var line = StatusLine(level: .error, headline: service.headline, detail: service.detail)
                switch service {
                case .notInstalled, .notRunning: line.button = .startService
                case .exeMissing: line.button = .repair
                case .notAnswering: line.button = .restart; line.secondButton = .openLogs
                case .keepsStopping: line.button = .openLogs
                }
                return line
            }
            return StatusLine(level: .error, headline: "Daemon not running",
                              detail: "grantpin is not running in the background. Start it to use your secrets.", button: .startService)
        case .locked(let message)?:
            var detail = "Unlock your Mac to use secrets. grantpin keeps trying."
            if let message, !message.isEmpty { detail += " " + DisplayText.sanitise(message) }
            return StatusLine(level: .warning, headline: "Vault locked", detail: detail)
        case .notInitialized?:
            return StatusLine(level: .warning, headline: "No vault yet",
                              detail: "Create a vault to start storing secrets.", button: .setUp)
        case .ready(let s)?:
            var line = StatusLine(level: .ok, headline: "grantpin is running", secrets: s.secrets, activeGrants: s.activeGrants)
            if s.protoV != 1 {
                line.level = .warning
                line.headline = "grantpin is out of step"
                line.detail = "This app and the background service are out of step."
                line.button = .repair
            } else if let h = helperVersion, h != s.version {
                line.level = .warning
                line.headline = "grantpin was updated"
                line.detail = "grantpin was updated. Restart the background service to finish."
                line.button = .restart
            } else if s.tamperedGrants > 0 {
                line.level = .warning
                line.button = .review
            } else if s.keystoreTier == .dialog {
                line.level = .warning
                line.detail = "The vault key is protected by the Keychain only. That is weaker than the Secure Enclave."
            }
            if s.tamperedGrants > 0 { line.tamperedGrants = s.tamperedGrants }
            return line
        }
    }

    /// `3 secrets · 1 active grant`, for the ready state.
    public var countsText: String? {
        guard let secrets, let activeGrants else { return nil }
        let s = secrets == 1 ? "1 secret" : "\(secrets) secrets"
        let g = activeGrants == 1 ? "1 active grant" : "\(activeGrants) active grants"
        return "\(s) · \(g)"
    }
}

/// The menu-bar icon for a state (docs/UI-SPEC.md 3.1): a template SF Symbol,
/// plain when healthy, a quieter outline while the vault is locked or being
/// checked, and a warning badge when the daemon is down, there is no vault, or
/// grants failed verification.
public struct MenuBarIcon: Equatable, Sendable {
    public var symbol: String
    /// Draw dimmed: the state is not a problem, just not active.
    public var subdued: Bool
    public var label: String

    public static func from(_ state: ConnectionState?) -> MenuBarIcon {
        switch state {
        case nil:
            return MenuBarIcon(symbol: "lock.shield", subdued: true, label: "grantpin: checking")
        case .notRunning?:
            return MenuBarIcon(symbol: "lock.trianglebadge.exclamationmark", subdued: false, label: "grantpin: not running")
        case .notInitialized?:
            return MenuBarIcon(symbol: "lock.trianglebadge.exclamationmark", subdued: false, label: "grantpin: no vault yet")
        case .locked?:
            return MenuBarIcon(symbol: "lock.shield", subdued: true, label: "grantpin: vault locked")
        case .ready(let s)?:
            if s.tamperedGrants > 0 {
                return MenuBarIcon(symbol: "lock.trianglebadge.exclamationmark", subdued: false, label: "grantpin: grants failed verification")
            }
            return MenuBarIcon(symbol: "lock.shield.fill", subdued: false, label: "grantpin")
        }
    }
}

/// What the popover's quick list needs: the secrets' metadata.
public protocol SecretsListing: Sendable {
    func listSecrets() async throws -> [SecretInfo]
}

/// "Grants (n)…" for the popover's footer.
public func grantsRowTitle(activeGrants: Int?) -> String {
    guard let n = activeGrants else { return "Grants…" }
    return "Grants (\(n))…"
}

/// State of the popover that the daemon does not hold: the last audit rows
/// and the result of the Start and Create vault buttons.
@Observable
@MainActor
public final class PopoverModel {
    /// The newest three events (newest first), or empty.
    public private(set) var recent: [AuditEvent] = []
    public private(set) var activityLoaded = false
    /// The six most recently updated secrets (docs/UI-SPEC.md 3.1), newest first.
    public private(set) var quickSecrets: [SecretInfo] = []
    /// The button that is running now, if any.
    public private(set) var running: StatusLine.Button?
    /// The result of the last button press, shown under the status line.
    public private(set) var lastResult: ActionResult?
    /// Development mode (the app talks to a dev socket): the buttons that
    /// would touch the real launchd job or vault are off.
    public let developmentSocket: String?

    @ObservationIgnored private let audit: AuditService
    @ObservationIgnored private let secretsList: SecretsListing?
    /// Where the app runs from; outside an Applications folder the service and
    /// vault actions are off.
    public var location: AppLocation
    @ObservationIgnored private let actions: DaemonActions?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let onActionFinished: @MainActor () async -> Void

    /// How many rows to ask for; the pairing needs a few more than are shown.
    public nonisolated static let auditWindow = 12

    /// - Parameters:
    ///   - actions: nil when no helper can be found (for example an unsigned
    ///     development build); the buttons then explain.
    ///   - onActionFinished: runs after Start or Create vault, to poll `status` at once.
    public init(audit: AuditService, actions: DaemonActions?, developmentSocket: String? = nil,
                secrets: SecretsListing? = nil, location: AppLocation = .ok,
                now: @escaping () -> Date = Date.init, onActionFinished: @escaping @MainActor () async -> Void = {}) {
        self.audit = audit
        self.secretsList = secrets
        self.location = location
        self.actions = actions
        self.developmentSocket = developmentSocket
        self.now = now
        self.onActionFinished = onActionFinished
    }

    public var isDevelopment: Bool { developmentSocket != nil }

    /// Whether Start and Create vault can run, and if not, why.
    public var buttonsDisabledReason: String? {
        if isDevelopment { return "In development mode the background service and the vault are not touched." }
        if actions == nil { return "The helper inside this app could not be found." }
        if !location.isOK { return AppLocation.blockedMessage }
        return nil
    }

    /// How many secrets the quick list shows.
    public nonisolated static let quickListCount = 6

    /// Loads the newest secrets for the quick list. A failure empties it
    /// quietly: the status line already says why, and `vault_not_initialized`
    /// hides the list rather than showing an error.
    public func refreshSecrets() async {
        guard let secretsList else { return }
        do {
            let all = try await secretsList.listSecrets()
            quickSecrets = Array(all.sorted { $0.updatedAt > $1.updatedAt }.prefix(Self.quickListCount))
        } catch is CancellationError {
            return
        } catch {
            quickSecrets = []
        }
    }

    /// Loads the last three events. Quietly empties the list when the daemon
    /// cannot answer (the status line already says why).
    public func refreshActivity(windowSize: Int = PopoverModel.auditWindow) async {
        do {
            let list = try await audit.listAudit(limit: windowSize)
            let complete = !list.truncated && list.entries.count < windowSize
            recent = AuditPairing.recent(list.entries, windowIsComplete: complete, count: 3, now: now())
            activityLoaded = true
        } catch is CancellationError {
            return
        } catch {
            recent = []
            activityLoaded = false
        }
    }

    /// The Start button: `service install` through the helper.
    public func start() async { await run(.startService) }

    /// The Create vault button: `init` through the helper.
    public func createVault() async { await run(.createVault) }

    /// Any of the status line's buttons that run the helper (Start, Repair,
    /// Restart, Create vault). The others (Set Up, Review, Open Logs Folder)
    /// only open a window or a folder and are handled by the view.
    public func perform(_ button: StatusLine.Button) async { await run(button) }

    private func run(_ button: StatusLine.Button) async {
        guard running == nil else { return }
        guard buttonsDisabledReason == nil, let actions else { return }
        switch button {
        case .setUp, .review, .openLogs: return
        default: break
        }
        running = button
        lastResult = nil
        let result: ActionResult
        switch button {
        case .startService, .repair, .restart: result = await actions.startService()
        case .createVault: result = await actions.createVault()
        case .setUp, .review, .openLogs: return
        }
        lastResult = result
        running = nil
        await onActionFinished()
    }

    public func dismissResult() { lastResult = nil }
}
