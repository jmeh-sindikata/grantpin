import Foundation
import XCTest
@testable import GrantpinKit

/// An in-memory daemon for the Grants window and the standing-grant form.
final class FakeGrants: GrantsService, @unchecked Sendable {
    private let lock = NSLock()
    var grants: [GrantInfo] = []
    var secrets: [SecretInfo] = []
    var audit = AuditList.empty
    private(set) var adds = [StandingGrantRequest]()
    private(set) var revoked = [String]()
    private(set) var revokeAllCalls = 0
    var listFailure: Error?
    var revokeFailure: Error?
    var addFailure: Error?
    /// If set, `addStandingGrant` waits this long (cancellation ends the wait with CancellationError).
    var addDelay: TimeInterval = 0
    private(set) var addCancelled = false
    var addResult: GrantInfo?

    func listGrants() async throws -> [GrantInfo] {
        if let e = lock.withLock({ listFailure }) { throw e }
        return lock.withLock { grants }
    }
    func revokeGrant(id: String) async throws {
        lock.withLock { revoked.append(id) }
        if let e = lock.withLock({ revokeFailure }) { throw e }
        try lock.withLock {
            guard grants.contains(where: { $0.id == id }) else {
                throw GrantpinError.daemon(category: .notFound, reason: .grantNotFound, message: "")
            }
            grants.removeAll { $0.id == id }
        }
    }
    func revokeAllGrants() async throws {
        lock.withLock { revokeAllCalls += 1 }
        if let e = lock.withLock({ revokeFailure }) { throw e }
        lock.withLock { grants = [] }
    }
    func addStandingGrant(_ grant: StandingGrantRequest) async throws -> GrantInfo {
        lock.withLock { adds.append(grant) }
        if addDelay > 0 {
            let end = Date().addingTimeInterval(addDelay)
            while Date() < end {
                if Task.isCancelled { lock.withLock { addCancelled = true }; throw CancellationError() }
                try? await Task.sleep(nanoseconds: 5_000_000)
            }
        }
        if let e = lock.withLock({ addFailure }) { throw e }
        let g = lock.withLock { addResult } ?? GrantInfo(
            id: "new1", caller: grant.forCaller, cwdPrefix: grant.cwd, secrets: grant.secrets, cmdPrefix: grant.argv,
            expiresAt: Date().addingTimeInterval(Double(grant.ttlSeconds)), usesRemaining: grant.uses, standing: true)
        lock.withLock { grants.append(g) }
        return g
    }
    func listSecrets() async throws -> [SecretInfo] { lock.withLock { secrets } }
    func listAudit(limit: Int?) async throws -> AuditList { lock.withLock { audit } }
}

/// An audit log that answers a `limit` like the daemon: the newest rows first.
final class FakeActivity: ActivityService, @unchecked Sendable {
    private let lock = NSLock()
    /// Newest first.
    var rows: [AuditEntry] = []
    var truncateAt: Int?
    var verifyResult: AuditVerifyResult = FakeActivity.verified(0)
    var verifyFailure: Error?
    var exportResult = "id,ts\n"
    var exportFailure: Error?
    var listFailure: Error?
    private(set) var limits = [Int?]()
    private(set) var verifyCalls = 0

    static func verified(_ n: Int) -> AuditVerifyResult {
        try! JSONDecoder().decode(AuditVerifyResult.self, from: Data(#"{"ok":true,"entries":\#(n)}"#.utf8))
    }
    static func broken(at id: String) -> AuditVerifyResult {
        try! JSONDecoder().decode(AuditVerifyResult.self, from: Data(#"{"ok":false,"entries":5,"first_bad_id":"\#(id)"}"#.utf8))
    }

    func listAudit(limit: Int?) async throws -> AuditList {
        lock.withLock { limits.append(limit) }
        if let e = lock.withLock({ listFailure }) { throw e }
        let (rows, cut) = lock.withLock { (self.rows, self.truncateAt) }
        var n = min(limit ?? 100, rows.count)
        var truncated = false
        if let cut, n > cut { n = cut; truncated = true }
        return AuditList.make(Array(rows.prefix(n)), truncated: truncated)
    }
    func verifyAudit() async throws -> AuditVerifyResult {
        lock.withLock { verifyCalls += 1 }
        if let e = lock.withLock({ verifyFailure }) { throw e }
        return lock.withLock { verifyResult }
    }
    func exportAudit() async throws -> String {
        if let e = lock.withLock({ exportFailure }) { throw e }
        return lock.withLock { exportResult }
    }
}

/// A scripted helper: records what it was asked and answers from the fields.
final class FakeServiceControl: ServiceControl, @unchecked Sendable {
    private let lock = NSLock()
    var status: Result<ServiceStatus, ServiceStatus.ParseError> = .success(ServiceStatus(installed: true, loaded: true, running: true, pid: 100))
    var installResult = ActionResult(outcome: .succeeded, summary: "grantpin is running in the background.")
    var uninstallResult = ActionResult(outcome: .succeeded, summary: "The background service was stopped and removed.")
    var initResults = [ActionResult(outcome: .succeeded, summary: "Vault created. Its key is in the Secure Enclave.")]
    var version: String? = "v1"
    private(set) var installs = [String?]()
    private(set) var uninstalls = 0
    private(set) var inits = [Bool]()

    func serviceStatus() async throws -> ServiceStatus {
        try lock.withLock { status }.get()
    }
    func installService(path: String?) async -> ActionResult {
        lock.withLock { installs.append(path) }
        return lock.withLock { installResult }
    }
    func uninstallService() async -> ActionResult {
        lock.withLock { uninstalls += 1 }
        return lock.withLock { uninstallResult }
    }
    func helperVersion() async -> String? { lock.withLock { version } }
    func initVault(keychainFallback: Bool) async -> ActionResult {
        lock.withLock {
            inits.append(keychainFallback)
            return initResults.count > 1 ? initResults.removeFirst() : initResults[0]
        }
    }
}

@MainActor
final class FakeLoginItem: LoginItemControl {
    nonisolated init() {}
    var status: LoginItemStatus = .notRegistered
    var registerFailure: Error?
    private(set) var registered = 0, unregistered = 0, settingsOpened = 0
    func register() throws {
        registered += 1
        if let registerFailure { throw registerFailure }
        status = .enabled
    }
    func unregister() throws { unregistered += 1; status = .notRegistered }
    func openSystemSettings() { settingsOpened += 1 }
}

struct FakeKeychain: KeychainItemRemoval {
    var result = KeyDeletion.deleted
    final class Calls: @unchecked Sendable {
        private let lock = NSLock()
        private var kinds = [VaultKeyKind]()
        func add(_ k: VaultKeyKind) { lock.withLock { kinds.append(k) } }
        var all: [VaultKeyKind] { lock.withLock { kinds } }
        var n: Int { all.count }
    }
    let calls = Calls()
    func deleteKey(_ kind: VaultKeyKind) async -> KeyDeletion { calls.add(kind); return result }
}

func daemonError(_ category: ErrorCategory, _ reason: ErrorReason, _ message: String = "") -> GrantpinError {
    .daemon(category: category, reason: reason, message: message)
}

/// A scratch directory under /tmp removed on deinit.
final class TempDir {
    let url: URL
    init() throws {
        url = URL(fileURLWithPath: "/tmp/gdu-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    deinit { try? FileManager.default.removeItem(at: url) }
    func file(_ rel: String, _ text: String = "x") throws -> URL {
        let u = url.appendingPathComponent(rel)
        try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: u, atomically: true, encoding: .utf8)
        return u
    }
}
