import Foundation

/// The `error` field of a failed response: the category (docs/PROTOCOL.md,
/// "Categories"). A category this build does not know is kept as `.unknown`.
public enum ErrorCategory: Equatable, Hashable, Sendable {
    case denied, refused, badRequest, notFound, failed
    case unknown(String)

    public init(wire: String) {
        switch wire {
        case "denied": self = .denied
        case "refused": self = .refused
        case "bad_request": self = .badRequest
        case "not_found": self = .notFound
        case "failed": self = .failed
        default: self = .unknown(wire)
        }
    }

    public var wire: String {
        switch self {
        case .denied: return "denied"
        case .refused: return "refused"
        case .badRequest: return "bad_request"
        case .notFound: return "not_found"
        case .failed: return "failed"
        case .unknown(let s): return s
        }
    }
}

/// The `reason` field of a failed response (docs/PROTOCOL.md, "Reasons"). A
/// reason this build does not know is kept as `.unknown`; callers then fall
/// back to the category.
public enum ErrorReason: Equatable, Hashable, Sendable {
    case userDenied, approverUnavailable, noGrant
    case policyRefused, tierUnmet, peerRejected, secretExpired, notTTY
    case badRequest, unsupportedVersion, unknownOp, secretExists
    case secretNotFound, grantNotFound
    case vaultNotInitialized, vaultLocked
    case timeout, canceled, internalError, responseTooLarge
    /// The response carried no reason.
    case absent
    case unknown(String)

    public init(wire: String) {
        switch wire {
        case "": self = .absent
        case "user_denied": self = .userDenied
        case "approver_unavailable": self = .approverUnavailable
        case "no_grant": self = .noGrant
        case "policy_refused": self = .policyRefused
        case "tier_unmet": self = .tierUnmet
        case "peer_rejected": self = .peerRejected
        case "secret_expired": self = .secretExpired
        case "not_tty": self = .notTTY
        case "bad_request": self = .badRequest
        case "unsupported_version": self = .unsupportedVersion
        case "unknown_op": self = .unknownOp
        case "secret_exists": self = .secretExists
        case "secret_not_found": self = .secretNotFound
        case "grant_not_found": self = .grantNotFound
        case "vault_not_initialized": self = .vaultNotInitialized
        case "vault_locked": self = .vaultLocked
        case "timeout": self = .timeout
        case "canceled": self = .canceled
        case "internal": self = .internalError
        case "response_too_large": self = .responseTooLarge
        default: self = .unknown(wire)
        }
    }

    public var wire: String {
        switch self {
        case .absent: return ""
        case .userDenied: return "user_denied"
        case .approverUnavailable: return "approver_unavailable"
        case .noGrant: return "no_grant"
        case .policyRefused: return "policy_refused"
        case .tierUnmet: return "tier_unmet"
        case .peerRejected: return "peer_rejected"
        case .secretExpired: return "secret_expired"
        case .notTTY: return "not_tty"
        case .badRequest: return "bad_request"
        case .unsupportedVersion: return "unsupported_version"
        case .unknownOp: return "unknown_op"
        case .secretExists: return "secret_exists"
        case .secretNotFound: return "secret_not_found"
        case .grantNotFound: return "grant_not_found"
        case .vaultNotInitialized: return "vault_not_initialized"
        case .vaultLocked: return "vault_locked"
        case .timeout: return "timeout"
        case .canceled: return "canceled"
        case .internalError: return "internal"
        case .responseTooLarge: return "response_too_large"
        case .unknown(let s): return s
        }
    }
}

/// Every way a call to the daemon can fail. The `daemon` case mirrors the
/// protocol's `error` category, `reason` and `message`; the other cases are
/// failures on this side of the socket. `message` is display only: the daemon
/// already redacted it, but it is still untrusted text (use `DisplayText`).
public enum GrantpinError: Error, Equatable, Sendable {
    /// Nothing is listening on the socket (ENOENT or ECONNREFUSED).
    case notRunning
    /// The socket path is longer than a Unix socket address allows.
    case socketPathTooLong(Int)
    /// The request line would exceed the protocol's 4 MiB limit. Nothing was sent.
    case requestTooLarge
    /// A request field this side refuses to send (for example a value that is
    /// not valid UTF-8). Nothing was sent.
    case invalidRequest(String)
    /// The daemon closed the connection without a final response.
    case noResponse
    /// No final response within the call's timeout (not the daemon's own
    /// `timeout` reason, which arrives as `daemon`).
    case timeout
    /// The process on the other end of the socket is not signed by this app's
    /// team, and the request carried a secret value. Nothing was sent.
    case peerNotGrantpin
    /// A line that is not valid protocol JSON, or a result that does not decode.
    case malformedResponse(String)
    /// A socket-level failure, with the errno text.
    case io(String)
    /// The daemon answered `ok: false`.
    case daemon(category: ErrorCategory, reason: ErrorReason, message: String)

    /// The daemon's category, if this is a daemon error.
    public var category: ErrorCategory? {
        if case .daemon(let c, _, _) = self { return c }
        return nil
    }

    /// The daemon's reason, if this is a daemon error.
    public var reason: ErrorReason? {
        if case .daemon(_, let r, _) = self { return r }
        return nil
    }

    /// The daemon's message, or "" for a local failure.
    public var message: String {
        if case .daemon(_, _, let m) = self { return m }
        return ""
    }

    public var isNotRunning: Bool { self == .notRunning }
    public var isVaultLocked: Bool { reason == .vaultLocked }
    public var isVaultNotInitialized: Bool { reason == .vaultNotInitialized }
    public var isDenied: Bool { category == .denied }
    public var isRefused: Bool { category == .refused }
    public var isNotFound: Bool { category == .notFound }
    public var isBadRequest: Bool { category == .badRequest }
    public var isResponseTooLarge: Bool { reason == .responseTooLarge }
}

/// The name the spec uses (docs/UI-SPEC.md 2.7).
public typealias DaemonError = GrantpinError

extension GrantpinError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notRunning: return "grantpin is not running."
        case .socketPathTooLong(let n): return "The socket path is \(n) bytes, over the Unix socket limit."
        case .requestTooLarge: return "The request is too large."
        case .invalidRequest(let why): return "Not sent: \(why)"
        case .peerNotGrantpin: return PeerVerifier.mismatchMessage
        case .noResponse: return "grantpin closed the connection without answering."
        case .timeout: return "grantpin took too long to answer."
        case .malformedResponse(let why): return "grantpin printed something unexpected: \(why)"
        case .io(let why): return "Socket error: \(why)"
        case .daemon(let category, let reason, let message):
            let head = reason == .absent ? category.wire : "\(category.wire): \(reason.wire)"
            let text = DisplayText.sanitise(message)
            return text.isEmpty ? head : "\(head): \(text)"
        }
    }
}
