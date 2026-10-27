import Foundation
import Observation

/// Which vault key `grantpin keystore delete` removes.
public enum VaultKeyKind: Equatable, Sendable {
    /// The Keychain item of the weaker protection (`--fallback`).
    case fallback
    /// The Secure Enclave key (`--hardware`).
    case hardware

    var flag: String { self == .fallback ? "--fallback" : "--hardware" }
}

/// What `grantpin keystore delete` reported.
public enum KeyDeletion: Equatable, Sendable {
    /// Exit 0.
    case deleted
    /// Exit 3: there was no such key. Nothing was deleted.
    case notFound
    /// Exit 2: the daemon is still running, so the helper refused.
    case daemonRunning
    /// Any other result; `detail` is the helper's stderr, sanitised.
    case failed(detail: String?)
}

/// Removes a vault key through the helper (docs/UI-SPEC.md 3.5). The
/// fallback key lives in the data-protection keychain and the hardware key in
/// the Secure Enclave; `security` reaches neither (it answers 44, "not found",
/// for an item that is there), so only the signed helper can delete them.
public protocol KeychainItemRemoval: Sendable {
    func deleteKey(_ kind: VaultKeyKind) async -> KeyDeletion
}

/// `grantpin keystore delete --fallback --yes` or `--hardware --yes`. The app
/// never passes `--force`: the service is stopped first, and a daemon that is
/// still running is a refusal (exit 2) the sheet reports.
public struct HelperKeystore: KeychainItemRemoval {
    public static let timeout: TimeInterval = 20
    public let helper: URL
    let environment: [String: String]

    public init(helper: URL, environment: [String: String]? = nil) {
        self.helper = helper
        self.environment = environment ?? ImportRunner.standardEnvironment()
    }

    public static func arguments(for kind: VaultKeyKind) -> [String] {
        ["keystore", "delete", kind.flag, "--yes"]
    }

    public func deleteKey(_ kind: VaultKeyKind) async -> KeyDeletion {
        guard let out = try? await HelperProcess.run(
            executable: helper, arguments: Self.arguments(for: kind), environment: environment,
            standardInput: nil, timeout: Self.timeout)
        else { return .failed(detail: nil) }
        return Self.interpret(out)
    }

    static func interpret(_ out: HelperOutput) -> KeyDeletion {
        if out.timedOut { return .failed(detail: "The helper took too long.") }
        switch out.exitCode {
        case 0: return .deleted
        case 3: return .notFound
        case 2: return .daemonRunning
        default: return .failed(detail: HelperActions.tail(out.stderr))
        }
    }
}

/// Whether the daemon is gone, as far as the Uninstall sheet can tell.
public enum DaemonState: Equatable, Sendable {
    /// A `status` call got an answer (of any kind from the daemon).
    case answering
    /// Nothing listens on the socket: it is absent or refuses connections.
    case stopped
    /// The call failed some other way (a timeout, a reset connection). That
    /// proves nothing about whether the daemon still holds the vault.
    case unknown(String)

    /// Only `GrantpinError.notRunning` (socket absent or connection refused)
    /// means the daemon is stopped. A daemon error is an answer.
    public static func classify(_ error: Error) -> DaemonState {
        if let e = error as? GrantpinError {
            if e.isNotRunning { return .stopped }
            if case .daemon = e { return .answering }
            return .unknown(e.errorDescription ?? "unknown error")
        }
        return .unknown("unknown error")
    }

    /// One `status` call.
    public static func probe(_ client: Client) async -> DaemonState {
        do {
            _ = try await client.status()
            return .answering
        } catch {
            return classify(error)
        }
    }
}

/// The Uninstall sheet (docs/UI-SPEC.md 3.5).
///
/// Order of operations: `service uninstall`; wait for the daemon to stop
/// answering (up to 5 seconds); only then remove `vault.db`, `vault.db-wal`,
/// `vault.db-shm` and a leftover `grantpin.sock` in the vault folder, then the
/// folder if it is empty. The vault is never deleted while the daemon may
/// still hold it open. Deleting the vault therefore always includes stopping
/// the service. The file operations use the default folders only.
@Observable
@MainActor
public final class UninstallModel {
    public enum Phase: Equatable, Sendable {
        case choosing
        case running(String)
        case finished(UninstallReport)
    }

    public var stopService = true
    public var deleteVault = false
    public var deleteLogs = false
    public var deleteKeychainItem = false
    public var deleteHardwareKey = false
    /// Ticked by default when `~/.local/bin/grantpin` is a link into this app.
    public var removeCommandLine = true
    public var confirmationText = ""
    public private(set) var phase: Phase = .choosing

    /// The vault's counts, or nil when `status` has no counts to give (the
    /// daemon is down or the vault is locked).
    public let secrets: Int?
    public let grants: Int?
    /// The daemon answered, but the vault is locked.
    public let vaultLocked: Bool
    /// The vault's protection, or nil when `status` did not answer: the key
    /// options are then not offered (nothing says which key the vault uses).
    public let keystoreTier: Tier?
    public let isDevelopment: Bool

    @ObservationIgnored private let control: ServiceControl?
    @ObservationIgnored private let vaultFolder: URL
    @ObservationIgnored private let logsFolder: URL
    @ObservationIgnored private let keychain: KeychainItemRemoval?
    @ObservationIgnored private let daemonState: @Sendable () async -> DaemonState
    @ObservationIgnored private let sleep: @Sendable (TimeInterval) async -> Void
    @ObservationIgnored private let unregisterLoginItem: @MainActor () -> Void
    @ObservationIgnored private let commandLine: CommandLineTool?
    @ObservationIgnored private let externallyBusy: @MainActor () -> Bool

    public static let vaultFiles = ["vault.db", "vault.db-wal", "vault.db-shm", "grantpin.sock"]
    public static let logFiles = ["daemon.err.log", "daemon.out.log"]

    public static let stopLabel = "Stop and remove the background service"
    public static let logsLabel = "Delete logs"
    public static let keychainLabel = "Delete the Keychain item used by weaker protection"
    public static let hardwareKeyLabel = "Delete the hardware key"
    public static let keyWarning =
        "Deleting the key makes the vault permanently unreadable, even if you keep the vault file."
    public static let deleteWarning =
        "Deleting the vault permanently removes all secrets, grants and the audit log. grantpin does not keep a copy and this can't be undone."
    public static let confirmationPrompt = "Type \"delete\" to confirm."
    public static let confirmationWord = "delete"
    public static let removeLabel = "Remove"
    public static let hardwareKeyNote =
        "The hardware key in your Keychain stays. It can't be exported and is useless without the vault file. To remove it, tick \"Delete the hardware key\" when you uninstall."
    public static let tierUnknownNote =
        "grantpin did not answer, so it is not known how the vault key is protected and no key option is offered."
    public static let tierLockedNote =
        "The vault is locked, so it is not known how its key is protected and no key option is offered. Unlock the vault to see it."
    public static let unknownKeyNote =
        "The vault's key may still be in your Keychain. It is useless without the vault file."
    public static let keychainItemNote =
        "The Keychain item for weaker protection stays. It is useless without the vault file."
    public static let commandLineLabel = "Remove the grantpin command from \(CommandLineTool.folderDisplay)"
    public static let disconnectText = "To disconnect Claude Code, run:"
    public static let disconnectCommand = ConnectSnippets.removeCommand
    public static let trashText = "To finish, drag grantpin to the Trash."

    public init(control: ServiceControl?, secrets: Int?, grants: Int?, keystoreTier: Tier?, isDevelopment: Bool,
                vaultLocked: Bool = false,
                vaultFolder: URL = AppPaths.vaultFolder(), logsFolder: URL = AppPaths.logsFolder(),
                keychain: KeychainItemRemoval? = nil,
                daemonState: @escaping @Sendable () async -> DaemonState,
                sleep: @escaping @Sendable (TimeInterval) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) },
                unregisterLoginItem: @escaping @MainActor () -> Void = {},
                commandLine: CommandLineTool? = nil,
                externallyBusy: @escaping @MainActor () -> Bool = { false }) {
        self.commandLine = commandLine
        self.externallyBusy = externallyBusy
        self.control = control
        self.secrets = secrets
        self.grants = grants
        self.vaultLocked = vaultLocked
        self.keystoreTier = keystoreTier
        self.isDevelopment = isDevelopment
        self.vaultFolder = vaultFolder
        self.logsFolder = logsFolder
        self.keychain = keychain
        self.daemonState = daemonState
        self.sleep = sleep
        self.unregisterLoginItem = unregisterLoginItem
    }

    // MARK: the sheet

    public var deleteVaultLabel: String {
        guard let secrets, let grants else { return "Delete my vault: all its secrets, grants and the audit log" }
        return "Delete my vault: \(secrets) \(secrets == 1 ? "secret" : "secrets"), \(grants) \(grants == 1 ? "grant" : "grants") and the audit log"
    }

    /// The command-line checkbox appears only when `~/.local/bin/grantpin` is a
    /// symlink into this app. A file, or a link that points elsewhere, is never
    /// offered and never touched.
    public var offersCommandLine: Bool { commandLine?.linkState().pointsIntoThisApp == true }
    public var willRemoveCommandLine: Bool { removeCommandLine && offersCommandLine }

    /// The Keychain checkbox appears only for a vault protected by the Keychain.
    public var offersKeychainItem: Bool { keystoreTier?.rank == 1 }
    /// The hardware-key checkbox appears only for a hardware-protected vault.
    public var offersHardwareKey: Bool { keystoreTier?.rank == 2 }

    /// True when the key options are hidden because the tier is not known.
    public var tierUnknown: Bool { keystoreTier == nil }
    /// Why the key options are hidden.
    public var tierUnknownText: String { vaultLocked ? Self.tierLockedNote : Self.tierUnknownNote }

    /// A key that will be deleted (only one that is offered counts).
    public var willDeleteFallbackKey: Bool { deleteKeychainItem && offersKeychainItem }
    public var willDeleteHardwareKey: Bool { deleteHardwareKey && offersHardwareKey }
    public var willDeleteKey: Bool { willDeleteFallbackKey || willDeleteHardwareKey }

    /// Deleting the vault or a key needs the service stopped first (the
    /// helper refuses to delete a key while the daemon runs).
    public var stopIsForced: Bool { deleteVault || willDeleteKey }
    public var willStopService: Bool { stopService || stopIsForced }

    /// The vault, or a key whose loss makes the vault unreadable.
    public var needsTypedConfirmation: Bool { deleteVault || willDeleteKey }
    /// Shown when a key is ticked.
    public var showsKeyWarning: Bool { willDeleteKey }
    public var confirmationMatches: Bool { confirmationText == Self.confirmationWord }

    /// Why Remove is off, or nil. The last reason is temporary: something
    /// else (the popover's Start, a Settings action, onboarding, the
    /// automatic restore) is changing the service, and `service uninstall`
    /// must not race it (`ServiceBusy`).
    public var disabledReason: String? {
        if isDevelopment { return "In development mode nothing is removed." }
        if control == nil { return "The helper inside this app could not be found." }
        if externallyBusy() { return ServiceBusy.reason }
        return nil
    }

    public var canRemove: Bool {
        guard disabledReason == nil, phase == .choosing else { return false }
        guard willStopService || deleteLogs || willRemoveCommandLine else { return false }
        return !needsTypedConfirmation || confirmationMatches
    }

    // MARK: running

    /// Runs the chosen steps in order. A failed step stops the rest, so the
    /// vault is never deleted after a failed stop.
    public func remove() async {
        guard canRemove, let control else { return }
        var done = [String]()
        var notices = [String]()
        var problem: String?
        var vaultDeleted = false
        var fallbackGone = false
        var hardwareGone = false

        if willStopService {
            phase = .running("Stopping the background service…")
            let r = await control.uninstallService()
            if r.isSuccess {
                done.append("The background service was stopped and removed.")
                unregisterLoginItem()
            } else {
                problem = r.summary
            }
        }

        // Neither the vault nor a key is touched while the daemon may hold them.
        var daemonStopped = false
        var daemonProblem: String?
        if problem == nil, deleteVault || willDeleteKey {
            phase = .running("Waiting for grantpin to stop…")
            switch await waitForDaemonToStop() {
            case .stopped: daemonStopped = true
            case .stillRunning: break
            case .unknown(let why):
                daemonProblem = "Could not tell whether grantpin has stopped (\(DisplayText.sanitise(why, limit: 120))), so nothing was deleted."
            }
        }
        if let daemonProblem { problem = daemonProblem }

        if problem == nil, deleteVault {
            if daemonStopped {
                phase = .running("Deleting the vault…")
                if let failure = removeVaultFiles() {
                    problem = failure
                } else {
                    vaultDeleted = true
                    done.append("The vault was deleted: secrets, grants and the audit log.")
                }
            } else {
                problem = "grantpin is still running, so the vault was not deleted."
            }
        }

        if problem == nil, deleteLogs {
            phase = .running("Deleting the logs…")
            if let failure = removeLogs() { problem = failure } else { done.append("The logs were deleted.") }
        }

        if problem == nil, willDeleteFallbackKey {
            phase = .running("Deleting the Keychain item…")
            let r = await deleteKey(.fallback, daemonStopped: daemonStopped, what: "Keychain item")
            fallbackGone = r.gone
            if let line = r.done { done.append(line) }
            if let line = r.notice { notices.append(line) }
            problem = r.problem
        }

        if problem == nil, willDeleteHardwareKey {
            phase = .running("Deleting the hardware key…")
            let r = await deleteKey(.hardware, daemonStopped: daemonStopped, what: "hardware key")
            hardwareGone = r.gone
            if let line = r.done { done.append(line) }
            if let line = r.notice { notices.append(line) }
            problem = r.problem
        }

        if problem == nil, willRemoveCommandLine, let commandLine {
            phase = .running("Removing the grantpin command…")
            switch commandLine.remove() {
            case .removed(let p): done.append("The grantpin command was removed from \(DisplayText.sanitise(p, limit: 200)).")
            case .nothingToRemove: break
            case let other: problem = other.message
            }
        }

        var remains = [String]()
        if vaultDeleted {
            if keystoreTier == nil {
                remains.append(Self.unknownKeyNote)
            } else if keystoreTier?.rank == 1 {
                if !fallbackGone { remains.append(Self.keychainItemNote) }
            } else if !hardwareGone {
                remains.append(Self.hardwareKeyNote)
            }
        } else if problem == nil, willStopService {
            remains.append("Your vault is still in \(DisplayText.sanitise(vaultFolder.path, limit: 200)).")
        }
        phase = .finished(UninstallReport(done: done, notices: notices, problem: problem, remains: remains, vaultDeleted: vaultDeleted))
    }

    private struct KeyStep {
        var gone = false
        var done: String?
        var notice: String?
        var problem: String?
    }

    /// One `keystore delete` run, worded for the result sheet. "Not found" is
    /// reported as what it is: nothing was deleted.
    private func deleteKey(_ kind: VaultKeyKind, daemonStopped: Bool, what: String) async -> KeyStep {
        var step = KeyStep()
        let capital = what.prefix(1).uppercased() + what.dropFirst()
        guard daemonStopped else {
            step.problem = "grantpin is still running, so the \(what) was not deleted."
            return step
        }
        guard let keychain else {
            step.problem = "The \(what) could not be deleted: the helper inside this app could not be found."
            return step
        }
        switch await keychain.deleteKey(kind) {
        case .deleted:
            step.gone = true
            step.done = "The \(what) was deleted."
        case .notFound:
            step.gone = true
            step.notice = "\(capital) was not found, so nothing was deleted. It may have been removed already."
        case .daemonRunning:
            step.problem = "grantpin is still running, so the \(what) was not deleted."
        case .failed(let detail):
            step.problem = "The \(what) could not be deleted." + (detail.map { " \($0)" } ?? "")
        }
        return step
    }

    public enum StopWait: Equatable, Sendable {
        case stopped
        /// Still answering after 5 seconds.
        case stillRunning
        /// The state could not be read; nothing is deleted on a guess.
        case unknown(String)
    }

    /// Up to 5 seconds for the daemon to stop answering. Only "not running"
    /// counts as stopped; a timeout or any other failure ends the wait.
    func waitForDaemonToStop() async -> StopWait {
        for _ in 0..<50 {
            switch await daemonState() {
            case .stopped: return .stopped
            case .unknown(let why): return .unknown(why)
            case .answering: await sleep(0.1)
            }
        }
        switch await daemonState() {
        case .stopped: return .stopped
        case .unknown(let why): return .unknown(why)
        case .answering: return .stillRunning
        }
    }

    /// Removes the four known files, then the folder if it is empty. Returns
    /// a problem text, or nil.
    func removeVaultFiles() -> String? {
        removeFiles(Self.vaultFiles, in: vaultFolder, failure: "Some vault files could not be deleted.")
    }

    func removeLogs() -> String? {
        removeFiles(Self.logFiles, in: logsFolder, failure: "Some log files could not be deleted.")
    }

    private func removeFiles(_ names: [String], in folder: URL, failure: String) -> String? {
        let fm = FileManager.default
        for name in names {
            let url = folder.appendingPathComponent(name)
            // Never follow a symlink out of the folder: remove the link itself only.
            guard (try? fm.attributesOfItem(atPath: url.path)) != nil else { continue }
            do { try fm.removeItem(at: url) } catch { return failure }
        }
        if let rest = try? fm.contentsOfDirectory(atPath: folder.path), rest.isEmpty {
            try? fm.removeItem(at: folder)
        }
        return nil
    }
}

extension UninstallModel: Identifiable {}

/// What the Uninstall sheet shows at the end.
public struct UninstallReport: Equatable, Sendable {
    public var done: [String]
    /// Steps that found nothing to do (a key that was not there).
    public var notices: [String] = []
    public var problem: String?
    /// What stays on this Mac and why it is harmless.
    public var remains: [String]
    public var vaultDeleted: Bool

    public var succeeded: Bool { problem == nil }
}
