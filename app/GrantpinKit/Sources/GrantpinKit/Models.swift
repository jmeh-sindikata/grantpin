import Foundation

/// A presence tier (`none`, `dialog`, `hardware`). A string underneath, so a
/// tier added later still decodes.
public struct Tier: RawRepresentable, Hashable, Codable, Sendable, ExpressibleByStringLiteral, CustomStringConvertible {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { rawValue = value }
    public init(from decoder: Decoder) throws { rawValue = try decoder.singleValueContainer().decode(String.self) }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }

    /// `"none"` on the wire. As a `min_tier` in `set`/`update` it means the
    /// vault default; as a key store or approver tier it means no protection.
    /// Not called `.none` on purpose: for an optional `Tier?` parameter
    /// `.none` would silently mean "omit".
    public static let vaultDefault: Tier = "none"
    public static let dialog: Tier = "dialog"
    public static let hardware: Tier = "hardware"

    public var description: String { rawValue }
}

/// The `status` result (internal/proto/result.go StatusResult).
public struct StatusResult: Decodable, Equatable, Sendable {
    public var version: String
    public var protoV: Int
    public var pid: Int
    public var startedAt: Date?
    public var vaultInitialized: Bool
    /// The vault exists but its key store is temporarily unavailable (screen
    /// locked, session not yet unlocked after login); the daemon is retrying.
    public var vaultLocked: Bool
    /// The last error of that retry. Display only.
    public var vaultLockedError: String
    public var keystoreTier: Tier
    public var approverTier: Tier
    public var secrets: Int
    public var activeGrants: Int
    public var tamperedGrants: Int
    public var socket: String

    enum CodingKeys: String, CodingKey {
        case version, protoV = "proto_v", pid, startedAt = "started_at"
        case vaultInitialized = "vault_initialized", vaultLocked = "vault_locked", vaultLockedError = "vault_locked_error"
        case keystoreTier = "keystore_tier", approverTier = "approver_tier"
        case secrets, activeGrants = "active_grants", tamperedGrants = "tampered_grants", socket
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        protoV = try c.decode(Int.self, forKey: .protoV)
        pid = try c.decodeIfPresent(Int.self, forKey: .pid) ?? 0
        startedAt = try c.decodeIfPresent(Date.self, forKey: .startedAt)
        vaultInitialized = try c.decode(Bool.self, forKey: .vaultInitialized)
        vaultLocked = try c.decodeIfPresent(Bool.self, forKey: .vaultLocked) ?? false
        vaultLockedError = try c.decodeIfPresent(String.self, forKey: .vaultLockedError) ?? ""
        keystoreTier = try c.decodeIfPresent(Tier.self, forKey: .keystoreTier) ?? .vaultDefault
        approverTier = try c.decodeIfPresent(Tier.self, forKey: .approverTier) ?? .vaultDefault
        secrets = try c.decodeIfPresent(Int.self, forKey: .secrets) ?? 0
        activeGrants = try c.decodeIfPresent(Int.self, forKey: .activeGrants) ?? 0
        tamperedGrants = try c.decodeIfPresent(Int.self, forKey: .tamperedGrants) ?? 0
        socket = try c.decodeIfPresent(String.self, forKey: .socket) ?? ""
    }

    /// For tests and previews.
    public init(
        version: String = "dev", protoV: Int = 1, pid: Int = 1, startedAt: Date? = nil,
        vaultInitialized: Bool = true, vaultLocked: Bool = false, vaultLockedError: String = "",
        keystoreTier: Tier = .vaultDefault, approverTier: Tier = .vaultDefault,
        secrets: Int = 0, activeGrants: Int = 0, tamperedGrants: Int = 0, socket: String = ""
    ) {
        self.version = version; self.protoV = protoV; self.pid = pid; self.startedAt = startedAt
        self.vaultInitialized = vaultInitialized; self.vaultLocked = vaultLocked; self.vaultLockedError = vaultLockedError
        self.keystoreTier = keystoreTier; self.approverTier = approverTier
        self.secrets = secrets; self.activeGrants = activeGrants; self.tamperedGrants = tamperedGrants; self.socket = socket
    }
}

/// One row of `list`. Metadata only: a value is never part of it. Every string
/// here is untrusted for display (`DisplayText`).
public struct SecretInfo: Decodable, Equatable, Sendable {
    public var name: String
    public var tags: [String]
    public var url: String
    public var notes: String
    public var expiresAt: Date?
    public var minTier: Tier
    public var createdAt: Date
    public var updatedAt: Date

    enum CodingKeys: String, CodingKey {
        case name, tags, url, notes, expiresAt = "expires_at", minTier = "min_tier", createdAt = "created_at", updatedAt = "updated_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        tags = try c.decodeIfPresent([String].self, forKey: .tags) ?? []
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        notes = try c.decodeIfPresent(String.self, forKey: .notes) ?? ""
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        minTier = try c.decodeIfPresent(Tier.self, forKey: .minTier) ?? .vaultDefault
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date(timeIntervalSince1970: 0)
        updatedAt = try c.decodeIfPresent(Date.self, forKey: .updatedAt) ?? Date(timeIntervalSince1970: 0)
    }

    /// For tests and previews.
    public init(name: String, tags: [String] = [], url: String = "", notes: String = "", expiresAt: Date? = nil,
                minTier: Tier = .dialog, createdAt: Date = Date(timeIntervalSince1970: 0), updatedAt: Date = Date(timeIntervalSince1970: 0)) {
        self.name = name; self.tags = tags; self.url = url; self.notes = notes; self.expiresAt = expiresAt
        self.minTier = minTier; self.createdAt = createdAt; self.updatedAt = updatedAt
    }
}

/// One grant of `grants list`, and the result of `grants add`. When `tampered`
/// is true every field except `id` is untrusted and must not be displayed.
public struct GrantInfo: Decodable, Equatable, Sendable {
    public var id: String
    public var caller: String
    public var cwdPrefix: String
    public var secrets: [String]
    public var cmdPrefix: [String]
    public var expiresAt: Date
    /// nil: unlimited within the lifetime.
    public var usesRemaining: Int?
    public var createdAt: Date
    public var standing: Bool
    public var tampered: Bool

    enum CodingKeys: String, CodingKey {
        case id, caller, cwdPrefix = "cwd_prefix", secrets, cmdPrefix = "cmd_prefix", expiresAt = "expires_at"
        case usesRemaining = "uses_remaining", createdAt = "created_at", standing, tampered
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        caller = try c.decodeIfPresent(String.self, forKey: .caller) ?? ""
        cwdPrefix = try c.decodeIfPresent(String.self, forKey: .cwdPrefix) ?? ""
        secrets = try c.decodeIfPresent([String].self, forKey: .secrets) ?? []
        cmdPrefix = try c.decodeIfPresent([String].self, forKey: .cmdPrefix) ?? []
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt) ?? Date(timeIntervalSince1970: 0)
        usesRemaining = try c.decodeIfPresent(Int.self, forKey: .usesRemaining)
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date(timeIntervalSince1970: 0)
        standing = try c.decodeIfPresent(Bool.self, forKey: .standing) ?? false
        tampered = try c.decodeIfPresent(Bool.self, forKey: .tampered) ?? false
    }

    /// For tests and previews.
    public init(id: String, caller: String = "claude-code", cwdPrefix: String = "/tmp", secrets: [String] = [], cmdPrefix: [String] = [],
                expiresAt: Date = Date(timeIntervalSince1970: 0), usesRemaining: Int? = nil,
                createdAt: Date = Date(timeIntervalSince1970: 0), standing: Bool = false, tampered: Bool = false) {
        self.id = id; self.caller = caller; self.cwdPrefix = cwdPrefix; self.secrets = secrets; self.cmdPrefix = cmdPrefix
        self.expiresAt = expiresAt; self.usesRemaining = usesRemaining; self.createdAt = createdAt
        self.standing = standing; self.tampered = tampered
    }
}

/// One row of `audit list`. Every string is untrusted for display.
public struct AuditEntry: Decodable, Equatable, Sendable {
    public var id: String
    public var ts: Date
    public var caller: String
    public var cwd: String
    public var argv: [String]
    /// What the request asked for (globs included).
    public var secrets: [String]
    /// The concrete names `secrets` resolved to; nil on older rows.
    public var expanded: [String]?
    public var decision: String
    public var grantID: String
    public var exitCode: Int?
    public var durationMS: Int64
    public var reason: String

    enum CodingKeys: String, CodingKey {
        case id, ts, caller, cwd, argv, secrets, expanded, decision
        case grantID = "grant_id", exitCode = "exit_code", durationMS = "duration_ms", reason
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        ts = try c.decodeIfPresent(Date.self, forKey: .ts) ?? Date(timeIntervalSince1970: 0)
        caller = try c.decodeIfPresent(String.self, forKey: .caller) ?? ""
        cwd = try c.decodeIfPresent(String.self, forKey: .cwd) ?? ""
        argv = try c.decodeIfPresent([String].self, forKey: .argv) ?? []
        secrets = try c.decodeIfPresent([String].self, forKey: .secrets) ?? []
        expanded = try c.decodeIfPresent([String].self, forKey: .expanded)
        decision = try c.decodeIfPresent(String.self, forKey: .decision) ?? ""
        grantID = try c.decodeIfPresent(String.self, forKey: .grantID) ?? ""
        exitCode = try c.decodeIfPresent(Int.self, forKey: .exitCode)
        durationMS = try c.decodeIfPresent(Int64.self, forKey: .durationMS) ?? 0
        reason = try c.decodeIfPresent(String.self, forKey: .reason) ?? ""
    }

    /// For tests and previews.
    public init(id: String, ts: Date = Date(timeIntervalSince1970: 0), caller: String = "claude-code", cwd: String = "/tmp",
                argv: [String] = [], secrets: [String] = [], expanded: [String]? = nil, decision: String,
                grantID: String = "", exitCode: Int? = nil, durationMS: Int64 = 0, reason: String = "") {
        self.id = id; self.ts = ts; self.caller = caller; self.cwd = cwd; self.argv = argv; self.secrets = secrets
        self.expanded = expanded; self.decision = decision; self.grantID = grantID; self.exitCode = exitCode
        self.durationMS = durationMS; self.reason = reason
    }
}

/// The `audit list` result, newest first.
public struct AuditList: Decodable, Equatable, Sendable {
    public var entries: [AuditEntry]
    /// True when fewer rows than asked for came back because the page would
    /// not fit in one protocol line; ask for a smaller `limit`.
    public var truncated: Bool

    enum CodingKeys: String, CodingKey { case entries, truncated }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        entries = try c.decodeIfPresent([AuditEntry].self, forKey: .entries) ?? []
        truncated = try c.decodeIfPresent(Bool.self, forKey: .truncated) ?? false
    }
}

/// The `audit verify` result. The response is `ok` either way; `ok == false`
/// here means the chain is broken at `firstBadID`.
public struct AuditVerifyResult: Decodable, Equatable, Sendable {
    public var ok: Bool
    public var entries: Int
    public var firstBadID: String?

    enum CodingKeys: String, CodingKey { case ok, entries, firstBadID = "first_bad_id" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ok = try c.decode(Bool.self, forKey: .ok)
        entries = try c.decodeIfPresent(Int.self, forKey: .entries) ?? 0
        firstBadID = try c.decodeIfPresent(String.self, forKey: .firstBadID)
    }
}

/// A field `update` can reset (the protocol's `clear` list).
public enum ClearField: String, Sendable, CaseIterable, Hashable {
    case tags, url, notes, expires
}

/// What `grants add` needs (docs/PROTOCOL.md `grants`). Validation is the
/// daemon's: nothing here clamps or corrects a value.
public struct StandingGrantRequest: Sendable, Equatable {
    /// The label the grant is for (`grant_caller`). A label, not an identity.
    public var forCaller: String
    /// Absolute folder; the daemon resolves symlinks.
    public var cwd: String
    /// Secret names or globs.
    public var secrets: [String]
    /// The command prefix.
    public var argv: [String]
    /// Lifetime in seconds (at most 90 days, or the policy's lower ceiling).
    public var ttlSeconds: Int
    /// End the grant after this many releases; nil is unlimited within the lifetime.
    public var uses: Int?

    public init(forCaller: String, cwd: String, secrets: [String], argv: [String], ttlSeconds: Int, uses: Int? = nil) {
        self.forCaller = forCaller; self.cwd = cwd; self.secrets = secrets; self.argv = argv
        self.ttlSeconds = ttlSeconds; self.uses = uses
    }
}
