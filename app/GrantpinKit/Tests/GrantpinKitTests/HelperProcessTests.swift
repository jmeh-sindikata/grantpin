import Foundation
import XCTest
@testable import GrantdKit

final class HelperProcessTests: XCTestCase {
    private let bash = URL(fileURLWithPath: "/bin/bash")
    private var env: [String: String] { ["PATH": "/usr/bin:/bin", "HOME": NSTemporaryDirectory(), "TERM": "dumb"] }

    func testAProcessThatIgnoresSIGTERMIsKilled() async throws {
        let started = Date()
        let out = try await HelperProcess.run(
            executable: bash, arguments: ["-ilc", "trap \"\" TERM; sleep 8"], environment: env,
            standardInput: nil, timeout: 0.3, killGrace: 0.3)
        let elapsed = Date().timeIntervalSince(started)
        XCTAssertTrue(out.timedOut)
        XCTAssertFalse(out.succeeded)
        XCTAssertLessThan(elapsed, 4, "SIGKILL ends it; the call does not wait for the 8 s sleep")
        XCTAssertEqual(out.exitCode, SIGKILL, "it died of SIGKILL, not of SIGTERM")
    }

    func testAProcessThatHonoursSIGTERMEndsAtTheTimeout() async throws {
        let started = Date()
        let out = try await HelperProcess.run(
            executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["8"], environment: env,
            standardInput: nil, timeout: 0.3)
        XCTAssertTrue(out.timedOut)
        XCTAssertEqual(out.exitCode, SIGTERM)
        XCTAssertLessThan(Date().timeIntervalSince(started), 4)
    }

    func testCancellingKillsAProcessThatIgnoresSIGTERM() async throws {
        let started = Date()
        let task = Task {
            try await HelperProcess.run(
                executable: bash, arguments: ["-ilc", "trap \"\" TERM; sleep 8"], environment: env,
                standardInput: nil, timeout: 60, killGrace: 0.3)
        }
        try await Task.sleep(nanoseconds: 400_000_000)
        task.cancel()
        let out = try await task.value
        XCTAssertFalse(out.timedOut)
        XCTAssertEqual(out.exitCode, SIGKILL)
        XCTAssertLessThan(Date().timeIntervalSince(started), 4)
    }

    func testAZeroTimeoutStillEndsTheProcess() async throws {
        let out = try await HelperProcess.run(
            executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["8"], environment: env,
            standardInput: nil, timeout: 0, killGrace: 0.3)
        XCTAssertTrue(out.timedOut)
    }

    func testANormalRunIsUnaffected() async throws {
        let out = try await HelperProcess.run(
            executable: bash, arguments: ["-c", "echo hi; echo oops >&2; exit 3"], environment: env,
            standardInput: nil, timeout: 5, killGrace: 0.3)
        XCTAssertFalse(out.timedOut)
        XCTAssertEqual(out.exitCode, 3)
        XCTAssertEqual(out.stdout, "hi\n")
        XCTAssertEqual(out.stderr, "oops\n")
    }

    func testAMissingExecutableThrowsAndLeavesNoTimerBehind() async {
        do {
            _ = try await HelperProcess.run(executable: URL(fileURLWithPath: "/nonexistent/x"), arguments: [], environment: env,
                                            standardInput: nil, timeout: 0.1)
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? GrantdError, .io("cannot start the helper"))
        }
    }

    func testAHungLoginShellMakesPathDetectionFallBack() async {
        // PathDetector asks the shell for its PATH; one that never answers
        // must end in the fallback list, not in a hang.
        let dir = NSTemporaryDirectory() + "gd-hung-\(UUID().uuidString.prefix(8))"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let script = dir + "/hung-shell"
        try? "#!/bin/bash\ntrap '' TERM\nsleep 8\n".write(toFile: script, atomically: true, encoding: .utf8)
        chmod(script, 0o755)
        let shells = dir + "/shells"
        try? "\(script)\n".write(toFile: shells, atomically: true, encoding: .utf8)
        let detector = PathDetector(environment: ["SHELL": script, "HOME": dir], shellsFile: shells, timeout: 0.3)
        let started = Date()
        let path = await detector.detect()
        XCTAssertEqual(path, PathDetector.fallback)
        XCTAssertLessThan(Date().timeIntervalSince(started), PathDetector.timeout + HelperProcess.killGrace + 1)
    }
}
