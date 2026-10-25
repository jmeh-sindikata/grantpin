import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A client of the daemon's Unix socket (docs/PROTOCOL.md).
///
/// One `call` is one connection: connect, write one request line, read stream
/// frames and exactly one final response, close. A `Client` holds only the
/// socket path, so it is stateless and `Sendable`; there is no connection
/// pool. The write side is never shut down: the daemon treats any read result,
/// EOF included, as "client went away" and cancels the request.
public struct Client: Sendable {
    /// The protocol's line limit (`proto.MaxLineBytes`).
    public static let maxLineBytes = 4 << 20

    public let socketPath: String

    public init(socketPath: String = SocketPath.resolve()) {
        self.socketPath = socketPath
    }

    /// Sends `request` and returns the final response. Throws
    /// `DaemonError.daemon` when the daemon answers `ok: false`.
    /// Cancelling the calling task closes the connection, which cancels the
    /// request in the daemon.
    public func call(_ request: Request, timeout: TimeInterval = 10) async throws -> Response {
        let path = socketPath
        let line: Data
        do {
            line = try JSONEncoder().encode(request) + Data([0x0A])
        } catch {
            throw DaemonError.malformedResponse("cannot encode request")
        }
        let cancel = CancelFlag()
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
                let response = try Client.exchange(path: path, line: line, timeout: timeout, cancel: cancel)
                if !response.ok {
                    throw DaemonError.daemon(category: response.category, reason: response.reason, message: response.message)
                }
                return response
            }.value
        } onCancel: {
            cancel.set()
        }
    }

    /// `status`, decoded.
    public func status() async throws -> StatusResult {
        try await call(.status).decode(StatusResult.self)
    }

    // MARK: - Transport

    final class CancelFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.lock(); value = true; lock.unlock() }
        var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    }

    static func exchange(path: String, line: Data, timeout: TimeInterval, cancel: CancelFlag) throws -> Response {
        guard line.count <= maxLineBytes else { throw DaemonError.requestTooLarge }
        let pathBytes = Array(path.utf8)
        guard pathBytes.count <= SocketPath.maxBytes else { throw DaemonError.socketPathTooLong(pathBytes.count) }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.io(String(cString: strerror(errno))) }
        defer { close(fd) }
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
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            switch errno {
            case ENOENT, ECONNREFUSED: throw DaemonError.notRunning
            case EINPROGRESS, EAGAIN:
                // A local socket normally connects at once; wait briefly if not.
                try waitFor(fd, events: Int16(POLLOUT), deadline: Date().addingTimeInterval(2), cancel: cancel)
                var err: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
                if err == ENOENT || err == ECONNREFUSED { throw DaemonError.notRunning }
                if err != 0 { throw DaemonError.io(String(cString: strerror(err))) }
            default: throw DaemonError.io(String(cString: strerror(errno)))
            }
        }

        let deadline = Date().addingTimeInterval(timeout)

        // Write the request line.
        var sent = 0
        try line.withUnsafeBytes { raw in
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                if n > 0 { sent += n; continue }
                if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    try waitFor(fd, events: Int16(POLLOUT), deadline: deadline, cancel: cancel)
                    continue
                }
                if n < 0 && errno == EINTR { continue }
                if n < 0 && (errno == EPIPE || errno == ECONNRESET) { throw DaemonError.noResponse }
                throw DaemonError.io(String(cString: strerror(errno)))
            }
        }

        // Read lines until the final response.
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            while let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                if lineData.isEmpty { continue }
                if let response = try parseLine(Data(lineData)) { return response }
            }
            if buffer.count > maxLineBytes { throw DaemonError.malformedResponse("line too long") }
            let n = read(fd, &chunk, chunk.count)
            if n > 0 { buffer.append(chunk, count: n); continue }
            if n == 0 { throw DaemonError.noResponse }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                try waitFor(fd, events: Int16(POLLIN), deadline: deadline, cancel: cancel)
                continue
            }
            if errno == EINTR { continue }
            if errno == ECONNRESET { throw DaemonError.noResponse }
            throw DaemonError.io(String(cString: strerror(errno)))
        }
    }

    /// Waits until `fd` is ready for `events`, in slices so cancellation and the
    /// deadline are noticed.
    private static func waitFor(_ fd: Int32, events: Int16, deadline: Date, cancel: CancelFlag) throws {
        while true {
            if cancel.isSet { throw CancellationError() }
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { throw DaemonError.timeout }
            var p = pollfd(fd: fd, events: events, revents: 0)
            let r = poll(&p, 1, Int32(min(remaining, 0.1) * 1000) + 1)
            if r > 0 { return }
            if r < 0 && errno != EINTR { throw DaemonError.io(String(cString: strerror(errno))) }
        }
    }

    /// Returns the final response for a `{"ok":...}` line, nil for a stream
    /// frame (`{"stream":...}`), and throws for anything else.
    static func parseLine(_ data: Data) throws -> Response? {
        guard let obj = try? JSONSerialization.jsonObject(with: data, options: []),
              let dict = obj as? [String: Any] else {
            throw DaemonError.malformedResponse("not a JSON object")
        }
        if dict["stream"] != nil { return nil }
        guard let ok = dict["ok"] as? Bool else {
            throw DaemonError.malformedResponse("neither a stream frame nor a response")
        }
        var result: Data?
        if let r = dict["result"], !(r is NSNull) {
            result = try? JSONSerialization.data(withJSONObject: r, options: [.fragmentsAllowed])
        }
        return Response(
            ok: ok,
            category: dict["error"] as? String ?? "",
            reason: dict["reason"] as? String ?? "",
            message: dict["message"] as? String ?? "",
            result: result)
    }
}
