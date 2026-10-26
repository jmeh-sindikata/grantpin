import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A client of the daemon's Unix socket (docs/PROTOCOL.md).
///
/// One request is one connection: connect, write one request line, read stream
/// frames and exactly one final response, close. A `Client` holds only the
/// socket path and the caller label, so it is stateless and `Sendable`; there
/// is no connection pool. The write side is never shut down: the daemon treats
/// any read result, EOF included, as "client went away" and cancels the
/// request.
///
/// The blocking socket work runs on a dispatch queue, not on the Swift
/// concurrency pool, so a request that waits minutes for a human (see
/// `addStandingGrant`) does not hold a cooperative thread. Cancelling the
/// calling task closes the connection, which cancels the request in the
/// daemon.
public struct Client: Sendable {
    /// The protocol's line limit, newline included (`proto.MaxLineBytes`).
    public static let maxLineBytes = Wire.maxLineBytes

    /// Per-request timeouts (docs/UI-SPEC.md 2.4). The daemon's own deadline
    /// for a request that waits for a human is much longer.
    public enum Timeout {
        /// `status`, `list`, `exists`, `masked`, `set`, `delete`, `update`
        /// (without `min_tier`), `grants` list/revoke/revoke_all, `audit list`.
        public static let standard: TimeInterval = 10
        public static let auditExport: TimeInterval = 30
        /// Recomputes the whole chain.
        public static let auditVerify: TimeInterval = 60
        /// A request that shows a dialog and Touch ID: `grants add`, and
        /// `update` with a `min_tier` (which asks when it lowers the level).
        /// The daemon waits up to its 120 s dialog limit plus the Touch ID
        /// sheet; 11 minutes is the spec's value.
        public static let human: TimeInterval = 11 * 60
        /// Connecting to a local socket either works at once or does not.
        public static let connect: TimeInterval = 2
    }

    public let socketPath: String
    /// The `caller` label every request carries. Informational and
    /// unauthenticated (docs/UI-SPEC.md 4.3).
    public let caller: String
    /// Who may answer a request that carries a secret value (`PeerVerifier`).
    /// Read-only requests are never checked.
    public let peerCheck: PeerCheck

    public init(socketPath: String = SocketLocator.resolve().path, caller: String = "grantd-app",
                peerCheck: PeerCheck = .automatic) {
        self.socketPath = socketPath
        self.caller = caller
        self.peerCheck = peerCheck
    }

    // MARK: - Calls

    /// Sends `request` and returns the final response. Throws
    /// `GrantdError.daemon` when the daemon answers `ok: false`, and
    /// `CancellationError` when the calling task is cancelled.
    public func call(_ request: Request, timeout: TimeInterval = Timeout.standard) async throws -> Response {
        var request = request
        request.caller = caller
        return try await perform(RequestLine(request: request), timeout: timeout)
    }

    /// Sends `request` together with a secret `value` (the `set` op). The
    /// bytes are escaped straight into the request buffer, which is overwritten
    /// with zeros as soon as the request has been written, whether it succeeded
    /// or failed. The caller's `value` is overwritten with zeros too, on every
    /// path, once the call is over.
    ///
    /// Because the request carries a plaintext value, the peer's code is
    /// checked first (`PeerVerifier`); a socket that is not answered by grantd
    /// gets nothing and the call throws `GrantdError.peerNotGrantd`.
    func call(_ request: Request, value: inout Data, timeout: TimeInterval = Timeout.standard) async throws -> Response {
        defer { value.resetBytes(in: 0..<value.count) }
        var request = request
        request.caller = caller
        return try await perform(RequestLine(request: request, value: value), timeout: timeout, verifyPeer: true)
    }

    /// Connects, checks the peer's code and disconnects, sending nothing.
    /// Used before a `.env` import, whose values the helper process (not this
    /// one) sends over its own connection: the check is a pre-flight, not a
    /// guarantee about that later connection.
    public func verifyPeer() async throws {
        let path = socketPath, policy = peerCheck
        let cancel = CancelFlag()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                Client.queue.async {
                    do {
                        let fd = try Client.connect(path: path, cancel: cancel)
                        defer { close(fd) }
                        try Client.requirePeer(fd, policy)
                        cont.resume()
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            cancel.set()
        }
    }

    func perform(_ line: RequestLine, timeout: TimeInterval, verifyPeer: Bool = false) async throws -> Response {
        let path = socketPath
        let peerPolicy: PeerCheck? = verifyPeer ? peerCheck : nil
        let cancel = CancelFlag()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Response, Error>) in
                Client.queue.async {
                    defer { line.wipe() }
                    do {
                        let response = try Client.exchange(path: path, line: line, timeout: timeout, cancel: cancel, peerPolicy: peerPolicy)
                        if let error = response.error { throw error }
                        cont.resume(returning: response)
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            cancel.set()
        }
    }

    private static let queue = DispatchQueue(label: "dev.grantd.client", qos: .userInitiated, attributes: .concurrent)

    // MARK: - Transport

    final class CancelFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.lock(); value = true; lock.unlock() }
        var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    }

    /// Opens a connection to the socket at `path`. The caller closes it.
    static func connect(path: String, cancel: CancelFlag) throws -> Int32 {
        if cancel.isSet { throw CancellationError() }
        let pathBytes = Array(path.utf8)
        guard pathBytes.count <= SocketLocator.maxBytes else { throw GrantdError.socketPathTooLong(pathBytes.count) }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw GrantdError.io(String(cString: strerror(errno))) }
        do {
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &addr.sun_path) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = b }
                dst[pathBytes.count] = 0
            }
            let connected = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if connected != 0 {
                switch errno {
                case ENOENT, ECONNREFUSED: throw GrantdError.notRunning
                case EINPROGRESS, EAGAIN:
                    // A local socket normally connects at once; wait briefly if not.
                    try waitFor(fd, events: Int16(POLLOUT), deadline: Date().addingTimeInterval(Timeout.connect), cancel: cancel)
                    var err: Int32 = 0
                    var len = socklen_t(MemoryLayout<Int32>.size)
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
                    if err == ENOENT || err == ECONNREFUSED { throw GrantdError.notRunning }
                    if err != 0 { throw GrantdError.io(String(cString: strerror(err))) }
                default: throw GrantdError.io(String(cString: strerror(errno)))
                }
            }
            return fd
        } catch {
            close(fd)
            throw error
        }
    }

    /// Throws `peerNotGrantd` unless the peer of `fd` passes `policy`.
    static func requirePeer(_ fd: Int32, _ policy: PeerCheck) throws {
        if PeerVerifier.check(socket: fd, using: policy) == .mismatch { throw GrantdError.peerNotGrantd }
    }

    /// One exchange on a fresh connection. Does not wipe `line`. With a
    /// `peerPolicy` the peer's code is checked before anything is written.
    static func exchange(path: String, line: RequestLine, timeout: TimeInterval, cancel: CancelFlag,
                         peerPolicy: PeerCheck? = nil) throws -> Response {
        let fd = try connect(path: path, cancel: cancel)
        defer { close(fd) }
        if let peerPolicy { try requirePeer(fd, peerPolicy) }

        let deadline = Date().addingTimeInterval(timeout)

        // Write the request line.
        try line.withBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                if n > 0 { sent += n; continue }
                if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    try waitFor(fd, events: Int16(POLLOUT), deadline: deadline, cancel: cancel)
                    continue
                }
                if n < 0 && errno == EINTR { continue }
                if n < 0 && (errno == EPIPE || errno == ECONNRESET) { throw GrantdError.noResponse }
                throw GrantdError.io(String(cString: strerror(errno)))
            }
        }
        // The request is out: zero the buffer now, before waiting for the answer.
        line.wipe()

        // Read lines until the final response.
        var buffer = Data()
        var scanned = 0  // bytes of `buffer` already searched for a newline
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            while let nl = buffer[(buffer.startIndex + scanned)...].firstIndex(of: 0x0A) {
                let lineData = Data(buffer[buffer.startIndex..<nl])
                buffer.removeSubrange(buffer.startIndex...nl)
                scanned = 0
                if lineData.isEmpty { continue }
                if let response = try Response.parse(line: lineData) { return response }
            }
            scanned = buffer.count
            // A line, newline included, may be at most maxLineBytes.
            if buffer.count >= maxLineBytes { throw GrantdError.malformedResponse("line too long") }
            let n = read(fd, &chunk, chunk.count)
            if n > 0 { buffer.append(chunk, count: n); continue }
            if n == 0 { throw GrantdError.noResponse }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                try waitFor(fd, events: Int16(POLLIN), deadline: deadline, cancel: cancel)
                continue
            }
            if errno == EINTR { continue }
            if errno == ECONNRESET { throw GrantdError.noResponse }
            throw GrantdError.io(String(cString: strerror(errno)))
        }
    }

    /// Waits until `fd` is ready for `events`, in slices so cancellation and the
    /// deadline are noticed.
    private static func waitFor(_ fd: Int32, events: Int16, deadline: Date, cancel: CancelFlag) throws {
        while true {
            if cancel.isSet { throw CancellationError() }
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { throw GrantdError.timeout }
            var p = pollfd(fd: fd, events: events, revents: 0)
            let r = poll(&p, 1, Int32(min(remaining, 0.1) * 1000) + 1)
            if r > 0 { return }
            if r < 0 && errno != EINTR { throw GrantdError.io(String(cString: strerror(errno))) }
        }
    }
}
