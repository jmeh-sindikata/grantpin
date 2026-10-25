import Foundation
import XCTest
@testable import GrantdKit

/// Talks to the real Go daemon built with `-tags grantd_dev` (INSECURE,
/// test-only backends: constant public key, tier none). `make ci-app` builds
/// build/grantd-dev and sets GRANTD_DEV_BIN; without it these tests skip.
final class DevDaemonTests: XCTestCase {
    private var dir = ""
    private var daemon: Process?

    override func setUpWithError() throws {
        guard let bin = ProcessInfo.processInfo.environment["GRANTD_DEV_BIN"], !bin.isEmpty else {
            throw XCTSkip("GRANTD_DEV_BIN is not set (run make ci-app)")
        }
        dir = "/tmp/gdt-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        addTeardownBlock { [dir] in try? FileManager.default.removeItem(atPath: dir) }
        _ = bin
    }

    override func tearDown() {
        daemon?.terminate()
        daemon?.waitUntilExit()
    }

    private func run(_ args: [String]) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: ProcessInfo.processInfo.environment["GRANTD_DEV_BIN"]!)
        p.arguments = args
        // A clean environment: nothing of the developer's real grantd leaks in.
        p.environment = ["GRANTD_HOME": dir, "HOME": dir, "PATH": "/usr/bin:/bin", "GRANTD_DEV_APPROVE": "allow"]
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        return p
    }

    private func startDaemon(socket: String) async throws {
        daemon = try run(["daemon", "--socket", socket])
        for _ in 0..<100 {
            if FileManager.default.fileExists(atPath: socket) { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("daemon socket did not appear")
    }

    func testStatusBeforeAndAfterInit() async throws {
        let socket = dir + "/s.sock"
        try await startDaemon(socket: socket)
        let client = Client(socketPath: socket)

        var s = try await client.status()
        XCTAssertFalse(s.vaultInitialized)
        XCTAssertEqual(s.protoV, 1)
        XCTAssertEqual(s.socket, socket)
        do { _ = try await client.call(Request(op: "list")); XCTFail("list before init") } catch let e as DaemonError {
            guard case .daemon(_, let reason, _) = e else { return XCTFail("\(e)") }
            XCTAssertEqual(reason, "vault_not_initialized")
        }

        let initP = try run(["init"])
        initP.waitUntilExit()
        XCTAssertEqual(initP.terminationStatus, 0)

        s = try await client.status()
        XCTAssertTrue(s.vaultInitialized)
        XCTAssertEqual(s.keystoreTier, "none")  // the insecure dev backend
        XCTAssertEqual(s.secrets, 0)
        XCTAssertEqual(s.activeGrants, 0)
        XCTAssertGreaterThan(s.pid, 0)
        XCTAssertFalse(s.version.isEmpty)
    }
}
