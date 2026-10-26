import Foundation
import Observation

/// The app's own login item (`SMAppService.mainApp`), as far as the screens
/// need it. The real one lives in the app target (it imports
/// ServiceManagement); tests use a fake.
@MainActor
public protocol LoginItemControl: AnyObject {
    var status: LoginItemStatus { get }
    func register() throws
    func unregister() throws
    /// Opens System Settings > General > Login Items.
    func openSystemSettings()
}

public enum LoginItemStatus: Equatable, Sendable {
    case notRegistered
    case enabled
    /// Registered, but the person has to allow it in System Settings.
    case requiresApproval
    case notFound
}

/// The facts of the "Security & data" tab (docs/UI-SPEC.md 3.5), read-only.
public struct SecurityFacts: Equatable, Sendable {
    public var version: String
    public var protocolVersion: String
    public var vaultProtection: String
    public var approval: String
    public var socket: String

    /// The fixed paragraph: the honest statement of the gap in THREAT-MODEL 4.1.
    public static let managingParagraph =
        "Saving, replacing and deleting secrets does not ask for Touch ID, and neither does revoking a grant. "
        + "Any program running as you can do those things. Touch ID protects using a secret, not managing the list. "
        + "See THREAT-MODEL.md."

    public init(status: StatusResult?, resolvedSocket: String) {
        guard let s = status else {
            version = "Not running"
            protocolVersion = "—"
            vaultProtection = "—"
            approval = "—"
            socket = DisplayText.sanitise(resolvedSocket, limit: DisplayText.detailLimit)
            return
        }
        version = DisplayText.sanitise(s.version, limit: 80)
        protocolVersion = String(s.protoV)
        vaultProtection = s.vaultInitialized ? Self.protectionText(s.keystoreTier) : "No vault yet"
        approval = Self.approvalText(s.approverTier)
        socket = DisplayText.sanitise(s.socket.isEmpty ? resolvedSocket : s.socket, limit: DisplayText.detailLimit)
    }

    public static func protectionText(_ tier: Tier) -> String {
        switch tier.rank {
        case 2: return "Secure Enclave (hardware)"
        case 1: return "Keychain only (weaker)"
        default: return "None (development build)"
        }
    }

    public static func approvalText(_ tier: Tier) -> String {
        switch tier.rank {
        case 2: return "Touch ID or your password"
        case 1: return "A confirmation dialog"
        default: return "None (development build)"
        }
    }
}

/// The paths the app shows and opens: the vault folder, the logs folder.
public enum AppPaths {
    public static func vaultFolder(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Application Support/grantd", isDirectory: true)
    }
    public static func logsFolder(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Logs/grantd", isDirectory: true)
    }
}

/// The Settings "General" tab (docs/UI-SPEC.md 3.5): start at login, the
/// background service, the PATH the service records, and the version row with
/// Repair and Restart.
///
/// Everything here goes through the helper (`ServiceControl`) or the app's
/// login item. In development mode (the app talks to a dev socket), when the
/// helper cannot be found, or when the app is not in an Applications folder,
/// the controls that would touch the real launchd job are disabled.
@Observable
@MainActor
public final class SettingsModel {
    public private(set) var service: ServiceStatus?
    public private(set) var serviceUnreadable = false
    public private(set) var helperVersion: String?
    public private(set) var isBusy = false
    /// The result of the last Start, Repair, Restart or Stop.
    public private(set) var lastResult: ActionResult?
    public var pathText = ""
    public private(set) var pathMessage: String?
    public private(set) var loginStatus: LoginItemStatus = .notRegistered
    public private(set) var loginError: String?
    public private(set) var connection: ConnectionState?
    /// A problem outside the helper actions, such as a failed move to Applications.
    public private(set) var problem: String?

    public let developmentSocket: String?
    public let resolvedSocket: String
    public var location: AppLocation

    @ObservationIgnored private let control: ServiceControl?
    @ObservationIgnored private let loginItem: LoginItemControl?
    @ObservationIgnored private let pathDetector: PathDetector
    @ObservationIgnored private let onChanged: @MainActor () async -> Void

    public static let pathLabel = "Where grantd looks for commands"
    public static let pathHelp = "Programs that agents run through grantd can only find commands in these folders."
    public static let approvalNeeded = "Allow grantd in System Settings > General > Login Items"

    public init(control: ServiceControl?, loginItem: LoginItemControl?, developmentSocket: String?, resolvedSocket: String,
                location: AppLocation = .ok, pathDetector: PathDetector = PathDetector(),
                onChanged: @escaping @MainActor () async -> Void = {}) {
        self.control = control
        self.loginItem = loginItem
        self.developmentSocket = developmentSocket
        self.resolvedSocket = resolvedSocket
        self.location = location
        self.pathDetector = pathDetector
        self.onChanged = onChanged
        self.loginStatus = loginItem?.status ?? .notRegistered
    }

    public func connectionChanged(_ state: ConnectionState?) { connection = state }

    public var status: StatusResult? {
        switch connection {
        case .ready(let s)?: return s
        default: return nil
        }
    }

    // MARK: what is allowed

    /// Why the service and login controls are off, or nil.
    public var controlsDisabledReason: String? {
        if developmentSocket != nil { return "In development mode the background service and the login item are not touched." }
        if control == nil { return "The helper inside this app could not be found." }
        if !location.isOK { return AppLocation.blockedMessage }
        return nil
    }

    public var developmentBanner: String? {
        developmentSocket.map { "Development socket: " + DisplayText.sanitise($0) }
    }

    // MARK: service

    public var backgroundServiceOn: Bool { service?.installed == true }

    /// Reads `service status` and the helper's version.
    public func refresh() async {
        loginStatus = loginItem?.status ?? .notRegistered
        guard let control, developmentSocket == nil else { return }
        do {
            service = try await control.serviceStatus()
            serviceUnreadable = false
        } catch {
            if error is CancellationError { return }
            service = nil
            serviceUnreadable = true
        }
        if helperVersion == nil { helperVersion = await control.helperVersion() }
    }

    public var protocolMismatch: Bool {
        if let s = status { return s.protoV != 1 }
        return false
    }

    public var versionMismatch: Bool {
        guard let s = status, let h = helperVersion else { return false }
        return s.version != h
    }

    /// The sentence beside the version row, or nil when all is well.
    public var versionNote: String? {
        if protocolMismatch { return "This app and the background service are out of step." }
        if versionMismatch { return "grantd was updated. Restart the background service to finish." }
        return nil
    }

    public var versionAction: String? {
        if protocolMismatch { return "Repair" }
        if versionMismatch { return "Restart" }
        return nil
    }

    /// Start (service off), Repair and Restart: `service install`, which is
    /// idempotent and restarts the job. `path` nil detects the shell's PATH.
    public func install(path: String? = nil) async {
        guard controlsDisabledReason == nil, let control, !isBusy else { return }
        isBusy = true
        lastResult = nil
        let r = await control.installService(path: path)
        lastResult = r
        isBusy = false
        await refresh()
        await onChanged()
    }

    public static let stopConfirmation = Confirmation(
        title: "Stop the background service?",
        message: "Agents will not be able to use grantd until you turn it back on. Your secrets and grants stay as they are.",
        confirmLabel: "Stop Service")

    /// After the person confirmed `stopConfirmation`.
    public func stopService() async {
        guard controlsDisabledReason == nil, let control, !isBusy else { return }
        isBusy = true
        lastResult = nil
        let r = await control.uninstallService()
        lastResult = r
        isBusy = false
        await refresh()
        await onChanged()
    }

    public func dismissResult() { lastResult = nil }

    public func noteProblem(_ text: String?) { problem = text }

    // MARK: PATH

    /// Fills the field with the login shell's PATH.
    public func redetectPath() async {
        pathText = await pathDetector.detect()
        pathMessage = nil
    }

    /// Loads the field once, from the shell. Not when the service controls are
    /// off (development mode, no helper, wrong location): the PATH cannot be
    /// applied there, so no login shell is started for it.
    public func loadPathIfNeeded() async {
        if controlsDisabledReason == nil, pathText.isEmpty { await redetectPath() }
    }

    /// A problem with the PATH field, or nil. Only absolute folders count
    /// (the service layer drops the rest).
    public static func pathIssue(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return "Enter at least one folder." }
        if t.contains("\n") { return "Put the folders on one line, separated by colons." }
        let parts = t.split(separator: ":", omittingEmptySubsequences: true)
        if parts.isEmpty { return "Enter at least one folder." }
        if parts.contains(where: { !$0.hasPrefix("/") }) { return "Every folder must be an absolute path starting with /." }
        if t.unicodeScalars.contains(where: { $0.value < 0x20 }) { return "The folders can't contain control characters." }
        return nil
    }

    /// Applying a changed PATH re-runs `service install` with it.
    public func applyPath() async {
        let t = pathText.trimmingCharacters(in: .whitespacesAndNewlines)
        if let issue = Self.pathIssue(t) { pathMessage = issue; return }
        pathMessage = nil
        await install(path: t)
    }

    // MARK: login item

    public var loginItemAvailable: Bool { loginItem != nil && developmentSocket == nil && location.isOK }
    public var startAtLogin: Bool { loginStatus == .enabled || loginStatus == .requiresApproval }
    public var loginNeedsApproval: Bool { loginStatus == .requiresApproval }

    public func setStartAtLogin(_ on: Bool) {
        guard loginItemAvailable, let loginItem else { return }
        loginError = nil
        do {
            if on { try loginItem.register() } else { try loginItem.unregister() }
        } catch {
            loginError = on ? "grantd could not be added to the login items." : "grantd could not be removed from the login items."
        }
        loginStatus = loginItem.status
    }

    public func openLoginItemsSettings() { loginItem?.openSystemSettings() }
}
