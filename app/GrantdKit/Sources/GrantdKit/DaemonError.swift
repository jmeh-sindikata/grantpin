import Foundation

/// Every way a call to the daemon can fail. The `daemon` case carries the
/// daemon's own `error` category, `reason` and `message` (display only; the
/// daemon already redacted it).
public enum DaemonError: Error, Equatable, Sendable {
    /// Nothing is listening on the socket (ENOENT or ECONNREFUSED).
    case notRunning
    /// The socket path is longer than a Unix socket address allows.
    case socketPathTooLong(Int)
    /// The request line would exceed the protocol's 4 MiB limit.
    case requestTooLarge
    /// The daemon closed the connection without a final response.
    case noResponse
    /// No final response within the call's timeout.
    case timeout
    /// A line that is not valid protocol JSON, or a result that does not decode.
    case malformedResponse(String)
    /// A socket-level failure, with the errno text.
    case io(String)
    /// The daemon answered `ok: false`.
    case daemon(category: String, reason: String, message: String)
}

extension DaemonError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notRunning: return "grantd is not running."
        case .socketPathTooLong(let n): return "The socket path is \(n) bytes, over the Unix socket limit."
        case .requestTooLarge: return "The request is too large."
        case .noResponse: return "grantd closed the connection without answering."
        case .timeout: return "grantd took too long to answer."
        case .malformedResponse(let why): return "grantd printed something unexpected: \(why)"
        case .io(let why): return "Socket error: \(why)"
        case .daemon(let category, let reason, let message):
            return message.isEmpty ? "\(category): \(reason)" : "\(category): \(reason): \(message)"
        }
    }
}
