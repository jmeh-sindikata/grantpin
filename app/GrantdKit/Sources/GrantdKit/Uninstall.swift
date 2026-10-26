import Foundation
import Observation

/// Removes the Keychain item that holds the weaker-protection vault key
/// (service `dev.grantd`, account `vault-kek`). The Secure Enclave key is not
/// a Keychain item `security` can see, and this never touches it.
public protocol KeychainItemRemoval: Sendable {
    /// True if the item is gone afterwards (it may not have existed).
    func removeVaultKeyItem() async -> Bool
}

/// `security delete-generic-password -s dev.grantd -a vault-kek`.
public struct SecurityToolKeychain: KeychainItemRemoval {
    public static let arguments = ["delete-generic-password", "-s", "dev.grantd", "-a", "vault-kek"]
    public init() {}

    public func removeVaultKeyItem() async -> Bool {
        guard let out = try? await HelperProcess.run(
            executable: URL(fileURLWithPath: "/usr/bin/security"), arguments: Self.arguments,
            environment: ImportRunner.standardEnvironment(), standardInput: nil, timeout: 10)
        else { return false }
        // 44 is errSecItemNotFound: already gone.
        return out.exitCode == 0 || out.exitCode == 44
    }
}

/// The Uninstall sheet (docs/UI-SPEC.md 3.5).
///
/// Order of operations: `service uninstall`; wait for the daemon to stop
/// answering (up to 5 seconds); only then remove `vault.db`, `vault.db-wal`,
/// `vault.db-shm` and a leftover `grantd.sock` in the vault folder, then the
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
    public var confirmationText = ""
    public private(set) var phase: Phase = .choosing

    public let secrets: Int
    public let grants: Int
    public let keystoreTier: Tier
    public let isDevelopment: Bool

    @ObservationIgnored private let control: ServiceControl?
    @ObservationIgnored private let vaultFolder: URL
    @ObservationIgnored private let logsFolder: URL
    @ObservationIgnored private let keychain: KeychainItemRemoval
    @ObservationIgnored private let isDaemonAnswering: @Sendable () async -> Bool
    @ObservationIgnored private let sleep: @Sendable (TimeInterval) async -> Void
    @ObservationIgnored private let unregisterLoginItem: @MainActor () -> Void

    public static let vaultFiles = ["vault.db", "vault.db-wal", "vault.db-shm", "grantd.sock"]
    public static let logFiles = ["daemon.err.log", "daemon.out.log"]

    public static let stopLabel = "Stop and remove the background service"
    public static let logsLabel = "Delete logs"
    public static let keychainLabel = "Delete the Keychain item used by weaker protection"
    public static let deleteWarning =
        "Deleting the vault permanently removes all secrets, grants and the audit log. grantd does not keep a copy and this can't be undone."
    public static let confirmationPrompt = "Type \"delete\" to confirm."
    public static let confirmationWord = "delete"
    public static let removeLabel = "Remove"
    public static let hardwareKeyNote =
        "The hardware key in your Keychain stays. It can't be exported and is useless without the vault file. grantd has no command to remove it yet."
    public static let keychainItemNote =
        "The Keychain item for weaker protection stays. It is useless without the vault file."
    public static let disconnectText = "To disconnect Claude Code, run:"
    public static let disconnectCommand = ConnectSnippets.removeCommand
    public static let trashText = "To finish, drag grantd to the Trash."

    public init(control: ServiceControl?, secrets: Int, grants: Int, keystoreTier: Tier, isDevelopment: Bool,
                vaultFolder: URL = AppPaths.vaultFolder(), logsFolder: URL = AppPaths.logsFolder(),
                keychain: KeychainItemRemoval = SecurityToolKeychain(),
                isDaemonAnswering: @escaping @Sendable () async -> Bool,
                sleep: @escaping @Sendable (TimeInterval) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) },
                unregisterLoginItem: @escaping @MainActor () -> Void = {}) {
        self.control = control
        self.secrets = secrets
        self.grants = grants
        self.keystoreTier = keystoreTier
        self.isDevelopment = isDevelopment
        self.vaultFolder = vaultFolder
        self.logsFolder = logsFolder
        self.keychain = keychain
        self.isDaemonAnswering = isDaemonAnswering
        self.sleep = sleep
        self.unregisterLoginItem = unregisterLoginItem
    }

    // MARK: the sheet

    public var deleteVaultLabel: String {
        "Delete my vault: \(secrets) \(secrets == 1 ? "secret" : "secrets"), \(grants) \(grants == 1 ? "grant" : "grants") and the audit log"
    }

    /// The Keychain checkbox appears only for a vault protected by the Keychain.
    public var offersKeychainItem: Bool { keystoreTier.rank == 1 }

    /// Deleting the vault needs the service stopped first.
    public var stopIsForced: Bool { deleteVault }
    public var willStopService: Bool { stopService || deleteVault }

    public var needsTypedConfirmation: Bool { deleteVault }
    public var confirmationMatches: Bool { confirmationText == Self.confirmationWord }

    public var disabledReason: String? {
        if isDevelopment { return "In development mode nothing is removed." }
        if control == nil { return "The helper inside this app could not be found." }
        return nil
    }

    public var canRemove: Bool {
        guard disabledReason == nil, phase == .choosing else { return false }
        guard willStopService || deleteLogs || (deleteKeychainItem && offersKeychainItem) else { return false }
        return !deleteVault || confirmationMatches
    }

    // MARK: running

    /// Runs the chosen steps in order. A failed step stops the rest, so the
    /// vault is never deleted after a failed stop.
    public func remove() async {
        guard canRemove, let control else { return }
        var done = [String]()
        var problem: String?
        var vaultDeleted = false
        var keychainDeleted = false

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

        if problem == nil, deleteVault {
            phase = .running("Waiting for grantd to stop…")
            if await waitForDaemonToStop() {
                phase = .running("Deleting the vault…")
                if let failure = removeVaultFiles() {
                    problem = failure
                } else {
                    vaultDeleted = true
                    done.append("The vault was deleted: secrets, grants and the audit log.")
                }
            } else {
                problem = "grantd is still running, so the vault was not deleted."
            }
        }

        if problem == nil, deleteLogs {
            phase = .running("Deleting the logs…")
            if let failure = removeLogs() { problem = failure } else { done.append("The logs were deleted.") }
        }

        if problem == nil, deleteKeychainItem, offersKeychainItem {
            phase = .running("Deleting the Keychain item…")
            if await keychain.removeVaultKeyItem() {
                keychainDeleted = true
                done.append("The Keychain item was deleted.")
            } else {
                problem = "The Keychain item could not be deleted."
            }
        }

        var remains = [String]()
        if vaultDeleted {
            if keystoreTier.rank == 1 {
                if !keychainDeleted { remains.append(Self.keychainItemNote) }
            } else {
                remains.append(Self.hardwareKeyNote)
            }
        } else if problem == nil, willStopService {
            remains.append("Your vault is still in \(DisplayText.sanitise(vaultFolder.path, limit: 200)).")
        }
        phase = .finished(UninstallReport(done: done, problem: problem, remains: remains, vaultDeleted: vaultDeleted))
    }

    /// Up to 5 seconds for the daemon to stop answering.
    func waitForDaemonToStop() async -> Bool {
        for _ in 0..<50 {
            if await !isDaemonAnswering() { return true }
            await sleep(0.1)
        }
        return await !isDaemonAnswering()
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
    public var problem: String?
    /// What stays on this Mac and why it is harmless.
    public var remains: [String]
    public var vaultDeleted: Bool

    public var succeeded: Bool { problem == nil }
}
