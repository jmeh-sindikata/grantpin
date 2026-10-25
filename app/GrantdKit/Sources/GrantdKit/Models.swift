import Foundation

/// A request line. Only the fields the app sends are modelled; the rest of
/// the protocol is added with the screens that use it (docs/PROTOCOL.md).
public struct Request: Encodable, Sendable {
    public var v: Int = 1
    public var op: String
    public var caller: String = "grantd-app"

    public init(op: String) { self.op = op }

    public static let status = Request(op: "status")
}

/// The final response of an exchange. `result` is the op-specific payload,
/// kept as raw JSON until the caller decodes it.
public struct Response: Sendable {
    public var ok: Bool
    public var category: String
    public var reason: String
    public var message: String
    public var result: Data?

    /// Decodes `result` as `T`, with the protocol's snake_case keys and
    /// RFC 3339 times. Unknown fields are ignored.
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        guard let result else { throw DaemonError.malformedResponse("response has no result") }
        do {
            return try Wire.decoder.decode(T.self, from: result)
        } catch {
            throw DaemonError.malformedResponse("result does not decode as \(T.self)")
        }
    }
}

/// The `status` result (internal/proto/result.go StatusResult). Tiers are the
/// strings `none`, `dialog` and `hardware`.
public struct StatusResult: Decodable, Equatable, Sendable {
    public var version: String
    public var protoV: Int
    public var pid: Int
    public var startedAt: Date?
    public var vaultInitialized: Bool
    public var vaultLocked: Bool
    public var keystoreTier: String
    public var approverTier: String
    public var secrets: Int
    public var activeGrants: Int
    public var tamperedGrants: Int
    public var socket: String

    enum CodingKeys: String, CodingKey {
        case version, protoV = "proto_v", pid, startedAt = "started_at"
        case vaultInitialized = "vault_initialized", vaultLocked = "vault_locked"
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
        keystoreTier = try c.decodeIfPresent(String.self, forKey: .keystoreTier) ?? "none"
        approverTier = try c.decodeIfPresent(String.self, forKey: .approverTier) ?? "none"
        secrets = try c.decodeIfPresent(Int.self, forKey: .secrets) ?? 0
        activeGrants = try c.decodeIfPresent(Int.self, forKey: .activeGrants) ?? 0
        tamperedGrants = try c.decodeIfPresent(Int.self, forKey: .tamperedGrants) ?? 0
        socket = try c.decodeIfPresent(String.self, forKey: .socket) ?? ""
    }
}

enum Wire {
    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = fractional.date(from: s) ?? plain.date(from: s) { return d }
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "bad time \(s)"))
        }
        return d
    }()
}
