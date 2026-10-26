import Foundation
import XCTest
@testable import GrantpinKit

/// A Unix-socket server for canned conversations: accepts connections, reads
/// the request line, then runs `handler` with the connection's fd. Short path
/// (the macOS limit is 103 bytes and NSTemporaryDirectory() can exceed it).
final class FakeServer: @unchecked Sendable {
    /// What the server threads share; they must not hold the server itself, or
    /// it would never be deallocated (and its directory never removed).
    private final class State: @unchecked Sendable {
        let lock = NSLock()
        var seen = [String]()
    }

    let dir: String
    let path: String
    private var listener: Int32 = -1
    private let state = State()
    var requests: [String] { state.lock.withLock { state.seen } }

    init(handler: @escaping (_ fd: Int32, _ requestLine: String) -> Void) throws {
        dir = "/tmp/gdt-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        path = dir + "/s.sock"
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            for (i, b) in bytes.enumerated() { dst[i] = b }
            dst[bytes.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        precondition(rc == 0, "bind: \(String(cString: strerror(errno)))")
        precondition(listen(listener, 8) == 0)
        let l = listener
        let state = self.state
        Thread.detachNewThread {
            while true {
                let c = accept(l, nil, nil)
                if c < 0 { return }
                Thread.detachNewThread {
                    var data = Data()
                    var b = [UInt8](repeating: 0, count: 65536)
                    while !data.contains(0x0A) {
                        let n = read(c, &b, b.count)
                        if n <= 0 { close(c); return }
                        data.append(b, count: n)
                    }
                    let req = String(decoding: data, as: UTF8.self)
                    state.lock.withLock { state.seen.append(req) }
                    handler(c, req)
                    close(c)
                }
            }
        }
    }

    /// A server that answers every request with `lines` (each followed by a newline).
    convenience init(answer lines: String...) throws {
        let out = lines.map { $0 + "\n" }.joined()
        try self.init { fd, _ in FakeServer.send(fd, out) }
    }

    deinit {
        close(listener)
        try? FileManager.default.removeItem(atPath: dir)
    }

    static func send(_ fd: Int32, _ s: String) {
        let b = Array(s.utf8)
        var sent = 0
        while sent < b.count {
            let n = b.withUnsafeBytes { write(fd, $0.baseAddress! + sent, $0.count - sent) }
            if n <= 0 { return }
            sent += n
        }
    }

    var client: Client { Client(socketPath: path) }
}

final class ManagedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    func set() { lock.lock(); v = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return v }
}

/// Asserts that `body` throws a `GrantpinError` and returns it.
func expectGrantpinError<T>(_ body: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async -> GrantpinError? {
    do {
        _ = try await body()
        XCTFail("expected an error", file: file, line: line)
    } catch let e as GrantpinError {
        return e
    } catch {
        XCTFail("expected a GrantpinError, got \(error)", file: file, line: line)
    }
    return nil
}

// MARK: - The Go dev daemon

/// Base class for tests against the real Go daemon built with `-tags grantpin_dev`
/// (INSECURE, test-only backends: constant public key, tier none). `make
/// app-test` builds build/grantpin-dev and sets GRANTPIN_DEV_BIN; without it the
/// tests skip (they never skip under make). Each test gets its own temporary
/// GRANTPIN_HOME and a short socket path in /tmp, a clean environment, and the
/// approver mode of `approveMode`. Nothing of the developer's real grantpin (the
/// installed app, the launchd job, ~/Library/Application Support/grantpin) is
/// involved.
class DevDaemonCase: XCTestCase {
    /// `GRANTPIN_DEV_APPROVE` for the daemon: "allow", "allow-no-standing", or
    /// nil for the default auto-deny.
    var approveMode: String? { "allow" }

    private(set) var dir = ""
    private(set) var socket = ""
    private(set) var daemon: Process?
    var client: Client { Client(socketPath: socket) }

    var devBinary: String { ProcessInfo.processInfo.environment["GRANTPIN_DEV_BIN"] ?? "" }

    override func setUpWithError() throws {
        guard !devBinary.isEmpty else { throw XCTSkip("GRANTPIN_DEV_BIN is not set (run make app-test)") }
        dir = "/tmp/gdt-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        socket = dir + "/s.sock"
    }

    override func tearDown() {
        stopDaemon()
        if !dir.isEmpty { try? FileManager.default.removeItem(atPath: dir) }
    }

    func environment() -> [String: String] {
        // A clean environment: nothing of the developer's real grantpin leaks in.
        var env = ["GRANTPIN_HOME": dir, "HOME": dir, "PATH": "/usr/bin:/bin"]
        if let m = approveMode { env["GRANTPIN_DEV_APPROVE"] = m }
        return env
    }

    /// Runs the dev binary with `args`, waits for it and returns (status, stdout).
    @discardableResult
    func runDev(_ args: [String]) throws -> (status: Int32, stdout: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: devBinary)
        p.arguments = args
        p.environment = environment()
        p.standardInput = FileHandle.nullDevice
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// `grantpin-dev init` in the fixture's home.
    func initVault() throws {
        XCTAssertEqual(try runDev(["init"]).status, 0)
    }

    /// Starts the daemon on the fixture's socket and waits for it to answer.
    func startDaemon(initVault doInit: Bool = true) async throws {
        if doInit { try initVault() }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: devBinary)
        p.arguments = ["daemon", "--socket", socket]
        p.environment = environment()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        daemon = p
        for _ in 0..<100 {
            if (try? await client.status()) != nil { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("the dev daemon did not answer on \(socket)")
    }

    /// SIGTERM, then wait for the daemon to be gone. `Process.waitUntilExit`
    /// can miss the exit of a child that dies quickly and then waits for ever,
    /// so this reaps the child itself, and uses SIGKILL after 5 seconds.
    func stopDaemon() {
        guard let d = daemon else { return }
        daemon = nil
        d.terminate()
        let pid = d.processIdentifier
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            var status: Int32 = 0
            let r = waitpid(pid, &status, WNOHANG)
            if r == pid || (r == -1 && errno == ECHILD) { return }
            usleep(20_000)
        }
        kill(pid, SIGKILL)
        var status: Int32 = 0
        waitpid(pid, &status, 0)
    }

    /// Stores a secret with a fresh buffer, as the app would.
    @discardableResult
    func put(_ name: String, _ value: String, tags: [String] = [], overwrite: Bool = false) async throws -> String {
        var data = Data(value.utf8)
        return try await client.set(name: name, value: &data, tags: tags, overwrite: overwrite)
    }
}

// XCTAssert* autoclosures cannot await; these can.
func assertEqual<T: Equatable>(_ expression: @autoclosure () async throws -> T, _ expected: @autoclosure () -> T,
                               file: StaticString = #filePath, line: UInt = #line) async {
    do {
        let got = try await expression()
        XCTAssertEqual(got, expected(), file: file, line: line)
    } catch {
        XCTFail("unexpected error: \(error)", file: file, line: line)
    }
}

func assertTrue(_ expression: @autoclosure () async throws -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
    await assertEqual(try await expression(), true, file: file, line: line)
}

func assertFalse(_ expression: @autoclosure () async throws -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
    await assertEqual(try await expression(), false, file: file, line: line)
}

func unwrap<T>(_ expression: @autoclosure () async throws -> T?, file: StaticString = #filePath, line: UInt = #line) async throws -> T {
    guard let value = try await expression() else {
        XCTFail("unexpected nil", file: file, line: line)
        throw GrantpinError.malformedResponse("unexpected nil in a test")
    }
    return value
}
