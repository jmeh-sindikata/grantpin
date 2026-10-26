import Foundation
import XCTest
@testable import GrantpinKit

final class PeerVerifierTests: XCTestCase {
    // MARK: the requirement string

    func testTheRequirementPinsTheTeamOnAnAppleAnchoredCertificate() {
        XCTAssertEqual(PeerVerifier.requirement(teamID: "MT2QHQX6PS"),
                       #"anchor apple generic and certificate leaf[subject.OU] = "MT2QHQX6PS""#)
    }

    func testOnlyATeamIdentifierReachesTheRequirementLanguage() {
        for bad in ["", "mt2qhqx6ps", "MT2QHQX6P", "MT2QHQX6PSX", "MT2QHQX6P\"", "MT2QHQX6P\" or anchor apple", "MT2 QHQX6PS",
                    "MT2QHQX6P\n", "MT2QHQX6PÄ"] {
            XCTAssertNil(PeerVerifier.requirement(teamID: bad), "\(bad.debugDescription)")
        }
        XCTAssertNotNil(PeerVerifier.requirement(teamID: "ABCDE12345"))
    }

    func testTheRequirementParses() {
        var req: SecRequirement?
        let text = PeerVerifier.requirement(teamID: "ABCDE12345")!
        XCTAssertEqual(SecRequirementCreateWithString(text as CFString, [], &req), errSecSuccess)
        XCTAssertNotNil(req)
    }

    func testTheMessageIsTheOneFromTheSpec() {
        XCTAssertEqual(PeerVerifier.mismatchMessage, "The process answering grantpin's socket is not grantpin. Nothing was sent.")
        XCTAssertEqual(UserMessage.from(GrantpinError.peerNotGrantpin).headline, PeerVerifier.mismatchMessage)
        XCTAssertEqual(GrantpinError.peerNotGrantpin.errorDescription, PeerVerifier.mismatchMessage)
    }

    // MARK: skipping

    func testNoTeamMeansNoCheck() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertEqual(PeerVerifier.check(socket: fds[0], using: .off), .skipped)
    }

    func testTheTestProcessIsUnsignedSoTheAutomaticCheckSkips() {
        // The dev daemon of the other tests is unsigned too: they only work if this skips.
        XCTAssertNil(PeerVerifier.ownTeamIdentifier, "run the tests from an unsigned or ad-hoc process")
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertEqual(PeerVerifier.check(socket: fds[0], using: .automatic), .skipped)
    }

    func testAnUnusableTeamIdentifierSkipsLikeNone() {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertEqual(PeerVerifier.check(socket: fds[0], using: .team("not a team")), .skipped)
    }

    // MARK: the real check

    func testThePeerPidIsReadFromTheSocket() {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertEqual(PeerVerifier.peerPID(of: fds[0]), getpid())
        XCTAssertNil(PeerVerifier.peerPID(of: -1))
    }

    func testAPeerOfAnotherTeamIsAMismatch() {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        // This process is not signed by team ABCDE12345.
        XCTAssertEqual(PeerVerifier.check(socket: fds[0], using: .team("ABCDE12345")), .mismatch)
        XCTAssertEqual(PeerVerifier.check(socket: -1, using: .team("ABCDE12345")), .mismatch, "fails closed")
    }

    func testTheCodeCheckAcceptsAnAppleSignedProcessAndRefusesAForeignTeam() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["5"]
        try child.run()
        defer { child.terminate(); child.waitUntilExit() }
        let pid = child.processIdentifier
        XCTAssertTrue(PeerVerifier.isSigned(pid: pid, requirement: "anchor apple"))
        XCTAssertFalse(PeerVerifier.isSigned(pid: pid, requirement: PeerVerifier.requirement(teamID: "ABCDE12345")!),
                       "an Apple binary has no such team")
        XCTAssertFalse(PeerVerifier.isSigned(pid: 0x7fffffff, requirement: "anchor apple"), "no such process")
        XCTAssertFalse(PeerVerifier.isSigned(pid: pid, requirement: "this is not a requirement"))
    }

    // MARK: through the client

    func testASetToAnImpostorSendsNothing() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"audit_id":"a1"}"#)
        var value = Data("hunter2".utf8)
        let client = Client(socketPath: server.path, peerCheck: .team("ABCDE12345"))
        let e = await expectGrantpinError(try await client.set(name: "k", value: &value))
        XCTAssertEqual(e, .peerNotGrantpin)
        XCTAssertTrue(value.allSatisfy { $0 == 0 }, "the value is wiped on this path too")
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(server.requests, [], "not a byte of the request reached the socket")
    }

    func testAReadOnlyRequestIsNotChecked() async throws {
        let server = try FakeServer(answer: ClientTests.statusJSON)
        let client = Client(socketPath: server.path, peerCheck: .team("ABCDE12345"))
        let s = try await client.status()
        XCTAssertEqual(s.pid, 4242, "status goes through; only a request with a value is checked")
        XCTAssertEqual(server.requests.count, 1)
    }

    func testASetWithTheCheckSkippedStillWorks() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"audit_id":"a1"}"#)
        var value = Data("hunter2".utf8)
        let id = try await Client(socketPath: server.path, peerCheck: .off).set(name: "k", value: &value)
        XCTAssertEqual(id, "a1")
        XCTAssertEqual(server.requests.count, 1)
        // the default (automatic) is a skip in an unsigned process
        var again = Data("hunter2".utf8)
        _ = try await server.client.set(name: "k", value: &again)
    }

    func testThePreflightForImportsChecksAndSendsNothing() async throws {
        let server = try FakeServer(answer: ClientTests.statusJSON)
        let e = await expectGrantpinError(try await Client(socketPath: server.path, peerCheck: .team("ABCDE12345")).verifyPeer())
        XCTAssertEqual(e, .peerNotGrantpin)
        try await Client(socketPath: server.path, peerCheck: .off).verifyPeer()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(server.requests, [])
        let gone = await expectGrantpinError(try await Client(socketPath: server.path + ".none", peerCheck: .off).verifyPeer())
        XCTAssertEqual(gone, .notRunning)
    }

    func testAnImportToAnImpostorNeverStartsTheHelper() async throws {
        let server = try FakeServer(answer: ClientTests.statusJSON)
        let marker = NSTemporaryDirectory() + "gd-imp-\(UUID().uuidString.prefix(8))"
        let script = marker + ".sh"
        try "#!/bin/sh\ntouch '\(marker)'\n".write(toFile: script, atomically: true, encoding: .utf8)
        chmod(script, 0o755)
        defer { try? FileManager.default.removeItem(atPath: script); try? FileManager.default.removeItem(atPath: marker) }
        let runner = ImportRunner(executable: URL(fileURLWithPath: script), socketPath: server.path,
                                  environment: ["PATH": "/usr/bin:/bin"], peerCheck: .team("ABCDE12345"))
        let file = FileHandle(forReadingAtPath: "/dev/null")!
        defer { try? file.close() }
        let e = await expectGrantpinError(try await runner.run(from: file, dryRun: false, onConflict: .skip))
        XCTAssertEqual(e, .peerNotGrantpin)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker), "the helper did not run")
        // a dry run sends no values, so it is not checked
        let dry = try await runner.run(from: file, dryRun: true, onConflict: .skip)
        XCTAssertEqual(dry.exitCode, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker))
    }
}
