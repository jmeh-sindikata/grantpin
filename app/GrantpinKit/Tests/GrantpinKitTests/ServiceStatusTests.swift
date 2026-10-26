import Foundation
import XCTest
@testable import GrantpinKit

final class ServiceStatusParserTests: XCTestCase {
    func testRunning() throws {
        let out = """
        label:     dev.grantpin.daemon
        installed: yes
        plist:     /Users/me/Library/LaunchAgents/dev.grantpin.daemon.plist
        loaded:    yes
        running:   yes (pid 4242)
        exe:       /Applications/grantpin.app/Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin

        """
        let s = try ServiceStatus.parse(stdout: out, exitCode: 0)
        XCTAssertEqual(s.label, "dev.grantpin.daemon")
        XCTAssertTrue(s.installed); XCTAssertTrue(s.loaded); XCTAssertTrue(s.running)
        XCTAssertEqual(s.pid, 4242)
        XCTAssertEqual(s.plistPath, "/Users/me/Library/LaunchAgents/dev.grantpin.daemon.plist")
        XCTAssertTrue(s.exePath!.hasSuffix("grantpin-daemon.app/Contents/MacOS/grantpin"))
        XCTAssertFalse(s.exeMissing)
        XCTAssertNil(s.warning)
        XCTAssertFalse(s.usesLegacyBundlePath)
    }

    func testInstalledButStopped() throws {
        let out = "label:     dev.grantpin.daemon\ninstalled: yes\nplist:     /p.plist\nloaded:    no\nrunning:   no\nexe:       /x/grantpin\n"
        let s = try ServiceStatus.parse(stdout: out, exitCode: 0)
        XCTAssertTrue(s.installed); XCTAssertFalse(s.loaded); XCTAssertFalse(s.running)
        XCTAssertNil(s.pid)
    }

    func testMissingExecutableWarning() throws {
        let out = "label:     dev.grantpin.daemon\ninstalled: yes\nplist:     /p\nloaded:    yes\nrunning:   no\nexe:       /Applications/grantpin.app/Contents/MacOS/grantpin\nwarning:   executable no longer exists; re-run `grantpin service install`\n"
        let s = try ServiceStatus.parse(stdout: out, exitCode: 0)
        XCTAssertTrue(s.exeMissing)
        XCTAssertEqual(s.warning, "executable no longer exists; re-run `grantpin service install`")
        XCTAssertTrue(s.usesLegacyBundlePath)
    }

    func testNotInstalledIsExitCodeThree() throws {
        let s = try ServiceStatus.parse(stdout: "label:     dev.grantpin.daemon\ninstalled: no\n", exitCode: 3)
        XCTAssertFalse(s.installed)
        // exit 3 wins even when the text is missing
        XCTAssertFalse(try ServiceStatus.parse(stdout: "", exitCode: 3).installed)
    }

    func testOtherFailuresAndGarbage() {
        XCTAssertThrowsError(try ServiceStatus.parse(stdout: "boom", exitCode: 1)) {
            XCTAssertEqual($0 as? ServiceStatus.ParseError, .failed(exitCode: 1))
        }
        XCTAssertThrowsError(try ServiceStatus.parse(stdout: "hello\nworld\n", exitCode: 0)) {
            XCTAssertEqual($0 as? ServiceStatus.ParseError, .unexpected)
        }
        XCTAssertThrowsError(try ServiceStatus.parse(stdout: "", exitCode: 0))
    }

    func testUnknownKeysAndHostileValuesAreHarmless() throws {
        let out = "label: dev.grantpin.daemon\ninstalled: yes\nfuture: thing\nrunning: yes (pid notanumber)\nexe: \u{1B}[31m/x\n"
        let s = try ServiceStatus.parse(stdout: out, exitCode: 0)
        XCTAssertTrue(s.running)
        XCTAssertNil(s.pid)
        // displayed through DisplayText by the views; the raw value is kept
        XCTAssertTrue(s.exePath!.contains("\u{1B}"))
    }
}

final class ServiceDiagnosisTests: XCTestCase {
    func testOrder() {
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: false), keepsStopping: false), .notInstalled)
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: false), keepsStopping: true), .notInstalled)
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: true, exeMissing: true), keepsStopping: true), .exeMissing)
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: true, running: true, pid: 7), keepsStopping: true), .keepsStopping)
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: true, running: true, pid: 7), keepsStopping: false), .notAnswering(pid: 7))
        XCTAssertEqual(ServiceDiagnosis.derive(ServiceStatus(installed: true), keepsStopping: false), .notRunning)
    }

    func testPopoverLinesAndButtons() {
        func line(_ d: ServiceDiagnosis) -> StatusLine { StatusLine.from(.notRunning, service: d) }
        XCTAssertEqual(line(.notInstalled).headline, "grantpin is not set up to run in the background")
        XCTAssertEqual(line(.notInstalled).button, .startService)
        XCTAssertEqual(line(.exeMissing).headline, "The background service points to a file that no longer exists")
        XCTAssertEqual(line(.exeMissing).button, .repair)
        XCTAssertEqual(line(.notRunning).headline, "grantpin is not running")
        XCTAssertEqual(line(.notRunning).button, .startService)
        XCTAssertEqual(line(.notAnswering(pid: 5)).headline, "grantpin is running but not answering")
        XCTAssertEqual(line(.notAnswering(pid: 5)).button, .restart)
        XCTAssertEqual(line(.notAnswering(pid: 5)).secondButton, .openLogs)
        XCTAssertEqual(line(.keepsStopping).headline, "grantpin keeps stopping")
        XCTAssertEqual(line(.keepsStopping).button, .openLogs)
        for d in [ServiceDiagnosis.notInstalled, .exeMissing, .notRunning, .notAnswering(pid: 1), .keepsStopping] {
            XCTAssertEqual(line(d).level, .error)
            XCTAssertFalse(d.detail.isEmpty)
        }
    }

    func testUnknownServiceStateKeepsTheGenericLine() {
        let l = StatusLine.from(.notRunning)
        XCTAssertEqual(l.headline, "Daemon not running")
        XCTAssertEqual(l.button, .startService)
    }

    func testReadyStateWarnings() {
        let proto = StatusLine.from(.ready(StatusResult(protoV: 2)))
        XCTAssertEqual(proto.button, .repair)
        XCTAssertEqual(proto.detail, "This app and the background service are out of step.")
        let version = StatusLine.from(.ready(StatusResult(version: "v1")), helperVersion: "v2")
        XCTAssertEqual(version.button, .restart)
        XCTAssertEqual(version.detail, "grantpin was updated. Restart the background service to finish.")
        XCTAssertNil(StatusLine.from(.ready(StatusResult(version: "v1")), helperVersion: "v1").button)
        XCTAssertNil(StatusLine.from(.ready(StatusResult(version: "v1")), helperVersion: nil).button)
        let tampered = StatusLine.from(.ready(StatusResult(tamperedGrants: 2)))
        XCTAssertEqual(tampered.button, .review)
        XCTAssertEqual(StatusLine.from(.notInitialized).button, .setUp)
        // proto trouble wins over a tampered grant
        XCTAssertEqual(StatusLine.from(.ready(StatusResult(protoV: 3, tamperedGrants: 1))).button, .repair)
    }
}

@MainActor
final class ServiceWatcherTests: XCTestCase {
    func testDiagnosesFromTheHelper() async {
        let c = FakeServiceControl()
        c.status = .success(ServiceStatus(installed: false))
        let w = ServiceWatcher(control: c)
        await w.poll()
        XCTAssertEqual(w.diagnosis, .notInstalled)
        c.status = .success(ServiceStatus(installed: true, running: true, pid: 9))
        await w.poll()
        XCTAssertEqual(w.diagnosis, .notAnswering(pid: 9))
        w.reset()
        XCTAssertNil(w.diagnosis)
    }

    func testKeepsStoppingNeedsThreePidChangesInAMinute() async {
        let c = FakeServiceControl()
        var clock = Date(timeIntervalSince1970: 1_000)
        let w = ServiceWatcher(control: c, now: { clock })
        for (i, pid) in [10, 11, 12].enumerated() {
            c.status = .success(ServiceStatus(installed: true, running: true, pid: pid))
            await w.poll()
            clock = clock.addingTimeInterval(5)
            // a poll in between that finds the job stopped does not reset the memory
            c.status = .success(ServiceStatus(installed: true))
            await w.poll()
            clock = clock.addingTimeInterval(5)
            if i < 2 { XCTAssertNotEqual(w.diagnosis, .keepsStopping, "after \(i + 1) pids") }
        }
        // 10 -> 11 -> 12 is two changes
        XCTAssertNotEqual(w.diagnosis, .keepsStopping)
        c.status = .success(ServiceStatus(installed: true, running: true, pid: 13))
        await w.poll()
        XCTAssertEqual(w.diagnosis, .keepsStopping, "three changes within a minute")
    }

    func testOldChangesExpireAndASteadyPidIsFine() async {
        let c = FakeServiceControl()
        var clock = Date(timeIntervalSince1970: 1_000)
        let w = ServiceWatcher(control: c, now: { clock })
        for pid in [1, 2, 3, 4] {
            c.status = .success(ServiceStatus(installed: true, running: true, pid: pid))
            await w.poll()
            clock = clock.addingTimeInterval(30)
        }
        // 3 changes happened 30 s apart: only the last two are within 60 s now
        clock = clock.addingTimeInterval(61)
        c.status = .success(ServiceStatus(installed: true, running: true, pid: 4))
        await w.poll()
        XCTAssertEqual(w.diagnosis, .notAnswering(pid: 4))
        XCTAssertFalse(w.keepsStopping)
    }

    func testAnUnreadableStatusIsRemembered() async {
        let c = FakeServiceControl()
        c.status = .failure(.unexpected)
        let w = ServiceWatcher(control: c)
        await w.poll()
        XCTAssertTrue(w.failed)
        XCTAssertNil(w.diagnosis)
    }

    func testNoHelperDoesNothing() async {
        let w = ServiceWatcher(control: nil)
        await w.poll()
        XCTAssertNil(w.status)
        XCTAssertFalse(w.failed)
    }
}

final class HelperServiceActionsTests: XCTestCase {
    func actions(_ d: ScriptDir, _ helperBody: String) throws -> HelperActions {
        let script = try d.script("grantpin", helperBody)
        return HelperActions(helper: script, appBundle: URL(fileURLWithPath: "/Applications/grantpin.app"),
                             pathDetector: PathDetector(environment: [:], shellsFile: "/nonexistent"),
                             environment: ["PATH": "/usr/bin:/bin"])
    }

    func testVersionIsParsed() {
        XCTAssertEqual(HelperActions.parseVersion("grantpin version 0.2.0\n"), "0.2.0")
        XCTAssertEqual(HelperActions.parseVersion("grantpin version 55c4e71-dirty"), "55c4e71-dirty")
        XCTAssertNil(HelperActions.parseVersion("something else"))
        XCTAssertNil(HelperActions.parseVersion("grantpin version "))
        XCTAssertNil(HelperActions.parseVersion(""))
    }

    func testHelperVersionRunsTheHelper() async throws {
        let d = try ScriptDir()
        let a = try actions(d, #"[ "$1" = "--version" ] && echo "grantpin version 9.9" && exit 0; exit 2"#)
        let v = await a.helperVersion()
        XCTAssertEqual(v, "9.9")
        let broken = try actions(d, "exit 1")
        let none = await broken.helperVersion()
        XCTAssertNil(none)
    }

    func testServiceStatusExitCodeThree() async throws {
        let d = try ScriptDir()
        let a = try actions(d, #"echo "label:     dev.grantpin.daemon"; echo "installed: no"; exit 3"#)
        let s = try await a.serviceStatus()
        XCTAssertFalse(s.installed)
    }

    func testServiceStatusFailureThrows() async throws {
        let d = try ScriptDir()
        let a = try actions(d, "echo oops >&2; exit 1")
        do {
            _ = try await a.serviceStatus()
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? ServiceStatus.ParseError, .failed(exitCode: 1))
        }
    }

    func testInstallPassesExeAndPathAndUninstallArguments() async throws {
        let d = try ScriptDir()
        let log = d.url.appendingPathComponent("args.log").path
        let a = try actions(d, #"echo "$@" >> '\#(log)'; echo "service installed and started"; exit 0"#)
        let r = await a.installService(path: "/opt/homebrew/bin:/usr/bin")
        XCTAssertEqual(r.outcome, .succeeded)
        let u = await a.uninstallService()
        XCTAssertEqual(u.outcome, .succeeded)
        XCTAssertEqual(u.summary, "The background service was stopped and removed.")
        _ = await a.initVault(keychainFallback: true)
        _ = await a.initVault(keychainFallback: false)
        let lines = try String(contentsOfFile: log, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(lines, [
            "service install --exe /Applications/grantpin.app --path /opt/homebrew/bin:/usr/bin",
            "service uninstall",
            "init --keychain-fallback",
            "init",
        ])
    }

    func testUninstallFailureCarriesStderr() async throws {
        let d = try ScriptDir()
        let a = try actions(d, "echo 'launchctl: nope' >&2; exit 1")
        let r = await a.uninstallService()
        XCTAssertEqual(r.outcome, .failed)
        XCTAssertEqual(r.detail, "launchctl: nope")
    }

    func testInitFailureOffersTheWeakerRetryOnlyForTheSecureEnclave() async throws {
        let d = try ScriptDir()
        let se = try actions(d, "echo 'keystore: Secure Enclave unavailable' >&2; exit 1")
        let r = await se.initVault(keychainFallback: false)
        XCTAssertTrue(r.secureEnclaveUnavailable)
        let other = try actions(d, "echo 'vault already exists' >&2; exit 1")
        let o = await other.initVault(keychainFallback: false)
        XCTAssertFalse(o.secureEnclaveUnavailable)
    }
}
