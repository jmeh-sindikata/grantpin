import Foundation
import XCTest
@testable import GrantdKit

/// A scratch directory with small executable scripts standing in for the helper and the shell.
final class ScriptDir {
    let url: URL
    init() throws {
        url = URL(fileURLWithPath: "/tmp/gdh-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    deinit { try? FileManager.default.removeItem(at: url) }

    @discardableResult
    func script(_ name: String, _ body: String) throws -> URL {
        let u = url.appendingPathComponent(name)
        try ("#!/bin/sh\n" + body + "\n").write(to: u, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: u.path)
        return u
    }
}

final class HelperLocatorTests: XCTestCase {
    func makeBundle(in dir: ScriptDir) throws -> URL {
        let app = dir.url.appendingPathComponent("grantd.app")
        let bin = app.appendingPathComponent(HelperLocator.relativePath)
        try FileManager.default.createDirectory(at: bin.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "#!/bin/sh\n".write(to: bin, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.path)
        return app
    }

    func testFindsTheHelper() throws {
        let d = try ScriptDir()
        let app = try makeBundle(in: d)
        let h = try HelperLocator.resolve(bundleURL: app)
        XCTAssertTrue(h.path.hasSuffix("grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd"))
    }

    func testMissingHelper() throws {
        let d = try ScriptDir()
        let app = d.url.appendingPathComponent("grantd.app")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: app)) {
            XCTAssertEqual($0 as? HelperLocator.Failure, .missing("grantd"))
        }
    }

    func testASymlinkedHelperIsRefused() throws {
        let d = try ScriptDir()
        let app = try makeBundle(in: d)
        let real = app.appendingPathComponent(HelperLocator.relativePath)
        let elsewhere = d.url.appendingPathComponent("evil")
        try FileManager.default.moveItem(at: real, to: elsewhere)
        try FileManager.default.createSymbolicLink(at: real, withDestinationURL: elsewhere)
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: app)) {
            XCTAssertEqual($0 as? HelperLocator.Failure, .symlink)
        }
    }

    func testASymlinkedDirectoryInThePathIsRefused() throws {
        let d = try ScriptDir()
        let app = try makeBundle(in: d)
        let helpers = app.appendingPathComponent("Contents/Helpers")
        let moved = d.url.appendingPathComponent("Helpers")
        try FileManager.default.moveItem(at: helpers, to: moved)
        try FileManager.default.createSymbolicLink(at: helpers, withDestinationURL: moved)
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: app)) {
            XCTAssertEqual($0 as? HelperLocator.Failure, .symlink)
        }
    }

    func testAnAppReachedThroughASymlinkIsFine() throws {
        let d = try ScriptDir()
        let app = try makeBundle(in: d)
        let link = d.url.appendingPathComponent("link.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: app)
        XCTAssertNoThrow(try HelperLocator.resolve(bundleURL: link))
    }

    func testANonExecutableHelperIsRefused() throws {
        let d = try ScriptDir()
        let app = try makeBundle(in: d)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: app.appendingPathComponent(HelperLocator.relativePath).path)
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: app)) {
            XCTAssertEqual($0 as? HelperLocator.Failure, .notExecutable)
        }
    }

    func testDevelopmentOverride() throws {
        let d = try ScriptDir()
        let s = try d.script("fake-grantd", "exit 0")
        XCTAssertEqual(try HelperLocator.resolve(bundleURL: URL(fileURLWithPath: "/nowhere.app"), developmentOverride: s.path).path, s.path)
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: URL(fileURLWithPath: "/nowhere.app"), developmentOverride: "relative"))
        XCTAssertThrowsError(try HelperLocator.resolve(bundleURL: URL(fileURLWithPath: "/nowhere.app"), developmentOverride: "/nonexistent/x"))
    }
}

final class PathDetectorTests: XCTestCase {
    func testExtractIgnoresNoiseAroundTheMarkers() {
        XCTAssertEqual(PathDetector.extract(from: "welcome!\n__GD_BEGIN__/a:/b__GD_END__\nbye"), "/a:/b")
        XCTAssertNil(PathDetector.extract(from: "no markers"))
        XCTAssertNil(PathDetector.extract(from: "__GD_BEGIN____GD_END__"))
        XCTAssertNil(PathDetector.extract(from: "__GD_END__/a__GD_BEGIN__"))
    }

    func testShellMustBeListedAndExecutable() throws {
        let d = try ScriptDir()
        let sh = try d.script("myshell", "exit 0")
        let shells = d.url.appendingPathComponent("shells")
        try "/bin/zsh\n\(sh.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        XCTAssertEqual(PathDetector(environment: ["SHELL": sh.path], shellsFile: shells.path).shell(), sh.path)
        XCTAssertEqual(PathDetector(environment: ["SHELL": "/bin/bash"], shellsFile: shells.path).shell(), "/bin/zsh", "not listed")
        XCTAssertEqual(PathDetector(environment: ["SHELL": "relative/sh"], shellsFile: shells.path).shell(), "/bin/zsh")
        XCTAssertEqual(PathDetector(environment: [:], shellsFile: shells.path).shell(), "/bin/zsh")
        XCTAssertEqual(PathDetector(environment: ["SHELL": sh.path], shellsFile: "/nonexistent").shell(), "/bin/zsh")
    }

    func testDetectRunsTheLoginShellAndReadsItsPath() async throws {
        let d = try ScriptDir()
        // A "shell" that prints rc noise and then the markers around a PATH.
        let sh = try d.script("myshell", #"echo "motd noise"; printf '__GD_BEGIN__%s__GD_END__' "/opt/homebrew/bin:/usr/bin""#)
        let shells = d.url.appendingPathComponent("shells")
        try "\(sh.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        let p = await PathDetector(environment: ["SHELL": sh.path, "HOME": "/tmp"], shellsFile: shells.path).detect()
        XCTAssertEqual(p, "/opt/homebrew/bin:/usr/bin")
    }

    func testDetectFallsBackWhenTheShellFailsOrPrintsNothing() async throws {
        let d = try ScriptDir()
        let bad = try d.script("bad", "exit 3")
        let silent = try d.script("silent", "echo hello")
        let relative = try d.script("rel", #"printf '__GD_BEGIN__%s__GD_END__' "bin:usr/bin""#)
        let shells = d.url.appendingPathComponent("shells")
        try "\(bad.path)\n\(silent.path)\n\(relative.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        for s in [bad, silent, relative] {
            let p = await PathDetector(environment: ["SHELL": s.path], shellsFile: shells.path).detect()
            XCTAssertEqual(p, PathDetector.fallback, s.lastPathComponent)
        }
    }

    func testAGrandchildHoldingThePipeDoesNotHangDetection() async throws {
        let d = try ScriptDir()
        // The rc file starts a background process that keeps stdout open for 4 s.
        let sh = try d.script("daemonizing", "(sleep 4) &\nprintf '__GD_BEGIN__/opt/x/bin__GD_END__'")
        let shells = d.url.appendingPathComponent("shells")
        try "\(sh.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        let started = Date()
        let p = await PathDetector(environment: ["SHELL": sh.path], shellsFile: shells.path).detect()
        XCTAssertEqual(p, "/opt/x/bin")
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    func testDetectFallsBackOnTimeout() async throws {
        let d = try ScriptDir()
        let slow = try d.script("slow", "sleep 5; printf '__GD_BEGIN__/x__GD_END__'")
        let shells = d.url.appendingPathComponent("shells")
        try "\(slow.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        let started = Date()
        let p = await PathDetector(environment: ["SHELL": slow.path], shellsFile: shells.path, timeout: 0.3).detect()
        XCTAssertEqual(p, PathDetector.fallback)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        XCTAssertEqual(PathDetector.timeout, 5)
    }
}

final class HelperActionsTests: XCTestCase {
    func recorder(_ d: ScriptDir, exit code: Int = 0, stdout: String = "", stderr: String = "") throws -> (URL, URL) {
        let log = d.url.appendingPathComponent("args.log")
        let h = try d.script("grantd", """
        for a in "$@"; do printf '%s\\n' "$a" >> "\(log.path)"; done
        printf '%s' 'ENV:'"$(env | sort | tr '\\n' ' ')" > "\(log.path).env"
        printf '%s' '\(stdout)'
        printf '%s' '\(stderr)' >&2
        exit \(code)
        """)
        return (h, log)
    }

    func detector(_ d: ScriptDir, path: String = "/opt/homebrew/bin:/usr/bin") throws -> PathDetector {
        let sh = try d.script("shell", "printf '__GD_BEGIN__%s__GD_END__' '\(path)'")
        let shells = d.url.appendingPathComponent("shells")
        try "\(sh.path)\n".write(to: shells, atomically: true, encoding: .utf8)
        return PathDetector(environment: ["SHELL": sh.path], shellsFile: shells.path)
    }

    func testStartRunsServiceInstallWithTheOuterAppAndThePath() async throws {
        let d = try ScriptDir()
        let (helper, log) = try recorder(d, stdout: "service installed and started\n")
        let app = URL(fileURLWithPath: "/Users/x/Applications/grantd.app")
        let actions = HelperActions(helper: helper, appBundle: app, pathDetector: try detector(d), environment: ["HOME": "/tmp", "PATH": "/usr/bin:/bin"])
        let r = await actions.startService()
        XCTAssertEqual(r.outcome, .succeeded)
        XCTAssertEqual(r.summary, "grantd is running in the background.")
        let args = try String(contentsOf: log, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(args, ["service", "install", "--exe", "/Users/x/Applications/grantd.app", "--path", "/opt/homebrew/bin:/usr/bin"])
        XCTAssertEqual(HelperActions.installArguments(appBundle: app, path: "/p"), ["service", "install", "--exe", app.path, "--path", "/p"])
    }

    func testTheHelperGetsOnlyTheMinimalEnvironment() async throws {
        let d = try ScriptDir()
        let (helper, log) = try recorder(d)
        setenv("GRANTD_TEST_LEAK", "1", 1)
        defer { unsetenv("GRANTD_TEST_LEAK") }
        let actions = HelperActions(helper: helper, appBundle: URL(fileURLWithPath: "/a.app"), pathDetector: try detector(d),
                                    environment: ImportRunner.standardEnvironment(from: ["HOME": "/h", "USER": "u", "GRANTD_TEST_LEAK": "1", "SECRET": "x"]))
        _ = await actions.createVault()
        let env = try String(contentsOfFile: log.path + ".env", encoding: .utf8)
        XCTAssertTrue(env.contains("HOME=/h"))
        XCTAssertTrue(env.contains("PATH=/usr/bin:/bin"))
        XCTAssertFalse(env.contains("GRANTD_TEST_LEAK"))
        XCTAssertFalse(env.contains("SECRET"))
    }

    func testCreateVaultRunsInit() async throws {
        let d = try ScriptDir()
        let (helper, log) = try recorder(d, stdout: "vault created at /x/vault.db (keystore tier: hardware)\n")
        let actions = HelperActions(helper: helper, appBundle: URL(fileURLWithPath: "/a.app"), pathDetector: try detector(d))
        let r = await actions.createVault()
        XCTAssertEqual(r.outcome, .succeeded)
        XCTAssertEqual(r.summary, "Vault created. Its key is in the Secure Enclave.")
        XCTAssertEqual(try String(contentsOf: log, encoding: .utf8), "init\n")
    }

    func testInstallInterpretation() {
        func out(_ code: Int32, _ so: String = "", _ se: String = "", timedOut: Bool = false) -> HelperOutput {
            HelperOutput(exitCode: code, stdout: so, stderr: se, timedOut: timedOut)
        }
        XCTAssertEqual(HelperActions.interpretInstall(out(0, "service installed and started\n")).outcome, .succeeded)
        let warn = HelperActions.interpretInstall(out(0, "service installed and started\nWARNING:   service installed, but the daemon did not become ready\n"))
        XCTAssertEqual(warn.outcome, .startedNotAnswering)
        XCTAssertEqual(warn.summary, "Started, but grantd has not answered yet.")
        XCTAssertTrue(warn.isSuccess)
        let fail = HelperActions.interpretInstall(out(1, "", "Error: service: refusing temporary directory\n"))
        XCTAssertEqual(fail.outcome, .failed)
        XCTAssertEqual(fail.summary, "grantd could not be started.")
        XCTAssertEqual(fail.detail, "Error: service: refusing temporary directory")
        XCTAssertEqual(HelperActions.interpretInstall(out(15, timedOut: true)).summary, "grantd took too long to start.")
    }

    func testFailureDetailIsTheSanitisedTailOfStderr() {
        let long = String(repeating: "a", count: 700) + "\u{1B}[31mEND\u{202E}"
        let r = HelperActions.interpretInstall(HelperOutput(exitCode: 1, stdout: "", stderr: long, timedOut: false))
        XCTAssertLessThanOrEqual(r.detail!.count, 600)
        XCTAssertFalse(r.detail!.unicodeScalars.contains("\u{1B}"))
        XCTAssertFalse(r.detail!.unicodeScalars.contains("\u{202E}"))
        XCTAssertTrue(r.detail!.contains("END"))
    }

    func testInitInterpretation() {
        func out(_ code: Int32, _ so: String = "", _ se: String = "") -> HelperOutput { HelperOutput(exitCode: code, stdout: so, stderr: se, timedOut: false) }
        XCTAssertEqual(HelperActions.interpretInit(out(0, "vault created at /x (keystore tier: dialog)\n")).summary, "Vault created. Its key is protected by the Keychain only.")
        XCTAssertEqual(HelperActions.interpretInit(out(0, "vault created at /x\n")).summary, "Vault created.")
        let se = HelperActions.interpretInit(out(1, "", "Error: the Secure Enclave is not available\n"))
        XCTAssertEqual(se.outcome, .failed)
        XCTAssertTrue(se.secureEnclaveUnavailable)
        XCTAssertFalse(HelperActions.interpretInit(out(1, "", "vault already exists")).secureEnclaveUnavailable)
    }

    func testAMissingHelperFailsCleanly() async throws {
        let d = try ScriptDir()
        let actions = HelperActions(helper: URL(fileURLWithPath: "/nonexistent/grantd"), appBundle: URL(fileURLWithPath: "/a.app"), pathDetector: try detector(d))
        let r = await actions.startService()
        XCTAssertEqual(r.outcome, .failed)
        XCTAssertEqual(r.summary, "grantd could not be started: the helper did not run.")
        let c = await actions.createVault()
        XCTAssertEqual(c.outcome, .failed)
    }
}
