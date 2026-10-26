import Foundation

/// What the Secrets screens need from the daemon. `Client` is the real one;
/// tests use a fake. All members are the protocol ops of the same name
/// (docs/PROTOCOL.md); the app never sends `show` or `run`, so neither exists here.
public protocol SecretsService: SecretsListing {
    func masked(_ name: String) async throws -> String
    @discardableResult
    func set(name: String, value: inout Data, tags: [String], url: String?, notes: String?,
             expires: Date?, minTier: Tier?, overwrite: Bool) async throws -> String
    @discardableResult
    func update(name: String, tags: [String]?, url: String?, notes: String?,
                expires: Date?, minTier: Tier?, clear: Set<ClearField>) async throws -> String
    @discardableResult
    func delete(_ name: String) async throws -> String
    func listGrants() async throws -> [GrantInfo]
}

extension Client: SecretsService {
    public func listSecrets() async throws -> [SecretInfo] { try await list() }
}

/// What the popover needs: the newest audit rows.
public protocol AuditService: Sendable {
    func listAudit(limit: Int?) async throws -> AuditList
}

extension Client: AuditService {}

/// Runs the helper's `import` (a descriptor on standard input; values never
/// enter this process).
public protocol ImportService: Sendable {
    func runImport(from file: FileHandle, dryRun: Bool, onConflict: ImportConflictMode) async throws -> HelperOutput
}

extension ImportRunner: ImportService {
    public func runImport(from file: FileHandle, dryRun: Bool, onConflict: ImportConflictMode) async throws -> HelperOutput {
        try await run(from: file, dryRun: dryRun, onConflict: onConflict)
    }
}
