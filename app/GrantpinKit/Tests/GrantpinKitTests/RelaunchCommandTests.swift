import Foundation
import XCTest
@testable import GrantpinKit

/// The pure part: what the helper is told. Nothing is started.
final class RelaunchCommandTests: XCTestCase {
    private let nasty = "/tmp/My Apps/it's \"x\" $(touch pwned) `id` ; $HOME\nline2/grantpin.app"

    func testRunsTheFixedScriptWithBinSh() {
        let c = RelaunchCommand(pid: 4242, target: URL(fileURLWithPath: "/Applications/grantpin.app"))
        XCTAssertEqual(c.executable, "/bin/sh")
        XCTAssertEqual(c.arguments, ["-c", RelaunchCommand.script, "sh", "4242", "/Applications/grantpin.app"])
    }

    func testPidAndPathAreSeparatePositionalArguments() {
        let c = RelaunchCommand(pid: 77, target: URL(fileURLWithPath: nasty))
        XCTAssertEqual(c.arguments.count, 5)
        XCTAssertEqual(c.arguments[3], "77")
        XCTAssertEqual(c.arguments[4], nasty, "verbatim, as one argument")
    }

    func testThePathIsNeverPartOfTheScriptText() {
        let a = RelaunchCommand(pid: 1, target: URL(fileURLWithPath: "/Applications/grantpin.app"))
        let b = RelaunchCommand(pid: 987654, target: URL(fileURLWithPath: nasty))
        XCTAssertEqual(a.arguments[1], b.arguments[1], "the script is a constant")
        XCTAssertEqual(a.arguments[1], RelaunchCommand.script)
        XCTAssertFalse(b.arguments[1].contains("pwned"))
        XCTAssertFalse(b.arguments[1].contains("My Apps"))
        XCTAssertFalse(b.arguments[1].contains("987654"), "not even the pid")
    }

    func testTheScriptOpensTheExactPathOnly() {
        let s = RelaunchCommand.script
        XCTAssertTrue(s.contains("exec \"${3:-/usr/bin/open}\" -- \"$2\""), "the default is /usr/bin/open, with the path only")
        for flag in [" -n", " -b", "dev.grantpin"] { XCTAssertFalse(s.contains(flag), flag) }
    }

    func testTestOnlyOverridesAreExtraArgumentsAfterThePath() {
        let c = RelaunchCommand(pid: 5, target: URL(fileURLWithPath: "/x/grantpin.app"), openBinary: "/tmp/stub", polls: 3)
        XCTAssertEqual(Array(c.arguments.suffix(2)), ["/tmp/stub", "3"])
        XCTAssertEqual(c.arguments[1], RelaunchCommand.script)
    }
}

/// Runs the real helper command against a shell stub in place of `/usr/bin/open`
/// and short-lived `sleep` processes as the "app". No real app is opened.
final class RelaunchCommandRunTests: XCTestCase {
    private var temp: TempDir!
    private var started = [Process]()
    private var logURL: URL { temp.url.appendingPathComponent("open.log") }

    override func setUpWithError() throws { temp = try TempDir() }

    override func tearDown() {
        for p in started where p.isRunning { p.terminate() }
        started = []
    }

    /// A stub that records how many arguments it got and each of them.
    private func makeStub() throws -> URL {
        let stub = try temp.file("stub-open.sh", """
            #!/bin/sh
            { printf '%s\\n' "$#"; for a in "$@"; do printf '[%s]\\n' "$a"; done; } >> "\(logURL.path)"
            """)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: stub.path)
        return stub
    }

    private func startSleep() throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sleep")
        p.arguments = ["30"]
        try p.run()
        started.append(p)
        return p
    }

    private func startHelper(pid: Int32, target: URL, stub: URL, polls: Int) throws -> Process {
        let p = RelaunchCommand(pid: pid, target: target, openBinary: stub.path, polls: polls).makeProcess()
        try p.run()
        started.append(p)
        return p
    }

    private func wait(_ p: Process, seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while p.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        return !p.isRunning
    }

    private func log() -> String? { try? String(contentsOf: logURL, encoding: .utf8) }

    func testOpensTheExactPathOnlyAfterTheAppHasExited() throws {
        let stub = try makeStub()
        let target = URL(fileURLWithPath: "/tmp/My Apps/it's $(touch pwned)\nline2/grantpin.app")
        let app = try startSleep()
        let helper = try startHelper(pid: app.processIdentifier, target: target, stub: stub, polls: 600)

        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertTrue(helper.isRunning, "still waiting for the app")
        XCTAssertNil(log(), "nothing is opened while the app is alive")

        app.terminate()
        app.waitUntilExit()
        XCTAssertTrue(wait(helper, seconds: 5), "the helper finishes once the app is gone")
        XCTAssertEqual(helper.terminationStatus, 0)
        XCTAssertEqual(log(), "2\n[--]\n[\(target.path)]\n", "open gets `--` and the exact path, nothing else")
        XCTAssertFalse(FileManager.default.fileExists(atPath: "pwned"))
    }

    func testGivesUpWithoutOpeningWhenTheAppNeverExits() throws {
        let stub = try makeStub()
        let app = try startSleep()
        let helper = try startHelper(pid: app.processIdentifier, target: URL(fileURLWithPath: "/tmp/x/grantpin.app"),
                                     stub: stub, polls: 3)
        XCTAssertTrue(wait(helper, seconds: 5), "the helper stops waiting by itself")
        XCTAssertTrue(app.isRunning)
        XCTAssertEqual(helper.terminationStatus, 1)
        XCTAssertNil(log(), "the stub is never called")
    }

    func testAnAppThatIsAlreadyGoneIsOpenedAtOnce() throws {
        let stub = try makeStub()
        let app = try startSleep()
        let pid = app.processIdentifier
        app.terminate()
        app.waitUntilExit()
        let helper = try startHelper(pid: pid, target: URL(fileURLWithPath: "/tmp/x/grantpin.app"), stub: stub, polls: 50)
        XCTAssertTrue(wait(helper, seconds: 5))
        XCTAssertEqual(log(), "2\n[--]\n[/tmp/x/grantpin.app]\n")
    }

    func testARefusedPidDoesNothing() throws {
        let stub = try makeStub()
        for bad: Int32 in [0, -1] {
            let helper = try startHelper(pid: bad, target: URL(fileURLWithPath: "/tmp/x/grantpin.app"), stub: stub, polls: 3)
            XCTAssertTrue(wait(helper, seconds: 5))
            XCTAssertEqual(helper.terminationStatus, 2)
        }
        XCTAssertNil(log())
    }
}
