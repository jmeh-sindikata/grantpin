import Foundation
import XCTest
@testable import GrantdKit

/// A one-shot Unix-socket server: accepts connections, reads the request line,
/// then runs `handler` with the connection's fd. Short path (the macOS limit is
/// 103 bytes and NSTemporaryDirectory() can exceed it).
final class FakeServer: @unchecked Sendable {
    let dir: String
    let path: String
    private var listener: Int32 = -1
    private let handler: (Int32, String) -> Void
    private(set) var requests = [String]()
    private let lock = NSLock()

    init(handler: @escaping (_ fd: Int32, _ requestLine: String) -> Void) throws {
        self.handler = handler
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
        Thread.detachNewThread { [self] in
            while true {
                let c = accept(l, nil, nil)
                if c < 0 { return }
                Thread.detachNewThread { [self] in
                    var data = Data()
                    var b = [UInt8](repeating: 0, count: 4096)
                    while !data.contains(0x0A) {
                        let n = read(c, &b, b.count)
                        if n <= 0 { close(c); return }
                        data.append(b, count: n)
                    }
                    let req = String(decoding: data, as: UTF8.self)
                    lock.lock(); requests.append(req); lock.unlock()
                    handler(c, req)
                    close(c)
                }
            }
        }
    }

    deinit {
        close(listener)
        try? FileManager.default.removeItem(atPath: dir)
    }

    static func send(_ fd: Int32, _ s: String) {
        let b = Array(s.utf8)
        _ = b.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    }
}

final class SocketPathTests: XCTestCase {
    func testEnvironmentWins() {
        XCTAssertEqual(SocketPath.resolve(environment: ["GRANTD_SOCKET": "/tmp/x.sock"], home: URL(fileURLWithPath: "/Users/a")), "/tmp/x.sock")
        XCTAssertTrue(SocketPath.isDevelopment(environment: ["GRANTD_SOCKET": "/tmp/x.sock"]))
    }

    func testDefaultUnderApplicationSupport() {
        let p = SocketPath.resolve(environment: [:], home: URL(fileURLWithPath: "/Users/a"))
        XCTAssertEqual(p, "/Users/a/Library/Application Support/grantd/grantd.sock")
        XCTAssertFalse(SocketPath.isDevelopment(environment: [:]))
        // an empty variable is not an override
        XCTAssertEqual(SocketPath.resolve(environment: ["GRANTD_SOCKET": ""], home: URL(fileURLWithPath: "/Users/a")), p)
        XCTAssertFalse(SocketPath.isDevelopment(environment: ["GRANTD_SOCKET": ""]))
    }
}

final class ClientTests: XCTestCase {
    static let statusJSON = #"{"ok":true,"result":{"version":"v0.1.0","proto_v":1,"pid":4242,"started_at":"2026-10-25T20:00:00.123456Z","vault_initialized":true,"keystore_tier":"hardware","approver_tier":"hardware","secrets":3,"active_grants":2,"socket":"/x/grantd.sock","future_field":[1,2]}}"#

    func testStatusDecodes() async throws {
        let server = try FakeServer { fd, _ in FakeServer.send(fd, Self.statusJSON + "\n") }
        let s = try await Client(socketPath: server.path).status()
        XCTAssertEqual(s.version, "v0.1.0")
        XCTAssertEqual(s.protoV, 1)
        XCTAssertEqual(s.pid, 4242)
        XCTAssertTrue(s.vaultInitialized)
        XCTAssertFalse(s.vaultLocked)
        XCTAssertEqual(s.keystoreTier, "hardware")
        XCTAssertEqual(s.secrets, 3)
        XCTAssertEqual(s.activeGrants, 2)
        XCTAssertEqual(s.tamperedGrants, 0)  // absent decodes to 0
        XCTAssertEqual(s.socket, "/x/grantd.sock")
        XCTAssertNotNil(s.startedAt)
        // the request is exactly one line, with the protocol version, op and caller
        XCTAssertEqual(server.requests.count, 1)
        let line = server.requests[0]
        XCTAssertTrue(line.hasSuffix("\n") && line.dropLast().firstIndex(of: "\n") == nil)
        let obj = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        XCTAssertEqual(obj?["v"] as? Int, 1)
        XCTAssertEqual(obj?["op"] as? String, "status")
        XCTAssertEqual(obj?["caller"] as? String, "grantd-app")
        XCTAssertEqual(obj?.count, 3)
    }

    func testStreamFramesBeforeTheFinalResponseAreSkipped() async throws {
        let server = try FakeServer { fd, _ in
            FakeServer.send(fd, #"{"stream":"stdout","data":"hi"}"# + "\n\n")
            FakeServer.send(fd, Self.statusJSON + "\n")
        }
        let s = try await Client(socketPath: server.path).status()
        XCTAssertEqual(s.pid, 4242)
    }

    func testResponseSplitAcrossWrites() async throws {
        let server = try FakeServer { fd, _ in
            let half = Self.statusJSON.index(Self.statusJSON.startIndex, offsetBy: 40)
            FakeServer.send(fd, String(Self.statusJSON[..<half]))
            Thread.sleep(forTimeInterval: 0.1)
            FakeServer.send(fd, String(Self.statusJSON[half...]) + "\n")
        }
        let s = try await Client(socketPath: server.path).status()
        XCTAssertEqual(s.secrets, 3)
    }

    func testDaemonErrorCarriesCategoryReasonAndMessage() async throws {
        let server = try FakeServer { fd, _ in
            FakeServer.send(fd, #"{"ok":false,"error":"failed","reason":"vault_not_initialized","message":"run grantd init"}"# + "\n")
        }
        do {
            _ = try await Client(socketPath: server.path).call(.status)
            XCTFail("expected an error")
        } catch let e as DaemonError {
            XCTAssertEqual(e, .daemon(category: "failed", reason: "vault_not_initialized", message: "run grantd init"))
        }
    }

    func testNotRunningWhenTheSocketIsMissingOrRefuses() async throws {
        let missing = "/tmp/gdt-missing-\(UUID().uuidString.prefix(6)).sock"
        do { _ = try await Client(socketPath: missing).call(.status); XCTFail() } catch let e as DaemonError { XCTAssertEqual(e, .notRunning) }

        // A socket file nobody listens on refuses the connection.
        let dir = "/tmp/gdt-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/s.sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            for (i, b) in bytes.enumerated() { dst[i] = b }
            dst[bytes.count] = 0
        }
        _ = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        close(fd)  // bound, never listened: the file stays, connect is refused
        do { _ = try await Client(socketPath: path).call(.status); XCTFail() } catch let e as DaemonError { XCTAssertEqual(e, .notRunning) }
    }

    func testClosedWithoutAResponse() async throws {
        let server = try FakeServer { _, _ in }
        do { _ = try await Client(socketPath: server.path).call(.status); XCTFail() } catch let e as DaemonError { XCTAssertEqual(e, .noResponse) }
    }

    func testTimeout() async throws {
        let server = try FakeServer { _, _ in Thread.sleep(forTimeInterval: 1.5) }
        do { _ = try await Client(socketPath: server.path).call(.status, timeout: 0.3); XCTFail() } catch let e as DaemonError { XCTAssertEqual(e, .timeout) }
    }

    func testMalformedLines() async throws {
        for bad in ["not json\n", #"{"neither":true}"# + "\n"] {
            let server = try FakeServer { fd, _ in FakeServer.send(fd, bad) }
            do { _ = try await Client(socketPath: server.path).call(.status); XCTFail() } catch let e as DaemonError {
                guard case .malformedResponse = e else { return XCTFail("\(e)") }
            }
        }
    }

    func testSocketPathTooLong() async throws {
        let long = "/tmp/" + String(repeating: "a", count: 120)
        do { _ = try await Client(socketPath: long).call(.status); XCTFail() } catch let e as DaemonError {
            XCTAssertEqual(e, .socketPathTooLong(long.utf8.count))
        }
    }

    func testClientNeverHalfClosesTheConnection() async throws {
        // The daemon cancels a request when it reads EOF. After sending the
        // request the client must keep its write side open until it has the
        // answer: the server waits, then checks a read would block (no EOF).
        let sawEOF = ManagedFlag()
        let server = try FakeServer { fd, _ in
            Thread.sleep(forTimeInterval: 0.3)
            var b = [UInt8](repeating: 0, count: 8)
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            if read(fd, &b, b.count) == 0 { sawEOF.set() }
            FakeServer.send(fd, Self.statusJSON + "\n")
        }
        _ = try await Client(socketPath: server.path).status()
        XCTAssertFalse(sawEOF.value, "client half-closed its write side before the response")
    }

    func testCancellingClosesTheConnection() async throws {
        let sawClose = ManagedFlag()
        let server = try FakeServer { fd, _ in
            var b = [UInt8](repeating: 0, count: 8)
            let deadline = Date().addingTimeInterval(3)
            while Date() < deadline {
                if read(fd, &b, b.count) == 0 { sawClose.set(); return }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        let client = Client(socketPath: server.path)
        let task = Task { try await client.call(.status, timeout: 30) }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch is CancellationError {} catch { XCTFail("\(error)") }
        try await Task.sleep(nanoseconds: 400_000_000)
        XCTAssertTrue(sawClose.value, "the server never saw the connection close")
    }
}

final class ManagedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    func set() { lock.lock(); v = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return v }
}
