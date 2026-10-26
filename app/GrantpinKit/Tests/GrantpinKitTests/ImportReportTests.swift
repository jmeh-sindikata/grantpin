import Foundation
import XCTest
@testable import GrantpinKit

final class ImportReportTests: XCTestCase {
    func testParsesTheDocumentedLines() throws {
        let r = try ImportReport.parse("added: 3 (A, B, C)\noverwritten: 1 (D)\nskipped (exists): 2 (E, F)\nignored (empty value): 1 (G)\n")
        XCTAssertFalse(r.dryRun)
        XCTAssertEqual(r.added, ["A", "B", "C"])
        XCTAssertEqual(r.overwritten, ["D"])
        XCTAssertEqual(r.skipped, ["E", "F"])
        XCTAssertEqual(r.ignoredEmpty, ["G"])
    }

    func testParsesADryRun() throws {
        let r = try ImportReport.parse("(dry run) would be added: 1 (NEW)\n(dry run) would be skipped (exists): 1 (OLD)\n")
        XCTAssertTrue(r.dryRun)
        XCTAssertEqual(r.added, ["NEW"])
        XCTAssertEqual(r.skipped, ["OLD"])
    }

    func testNothingToImport() throws {
        XCTAssertTrue(try ImportReport.parse("nothing to import\n").nothingToImport)
    }

    func testAnythingUnexpectedFailsLoudly() {
        for bad in ["", "hello\n", "added: 2 (A)\n", "added: x (A)\n", "frobnicated: 1 (A)\n", "added: 1 ()\n", "added 1 (A)\n",
                    "added: 1 (A)\nand then something else\n", "added: 1 (A, )\n", "added: 1 (A\n"] {
            XCTAssertThrowsError(try ImportReport.parse(bad), bad.debugDescription) { e in
                guard case GrantpinError.malformedResponse = e else { return XCTFail("\(e)") }
            }
        }
    }

    func testArgumentsPutNoValueAndNoFilePathOnTheCommandLine() {
        let args = ImportRunner.arguments(dryRun: true, onConflict: .overwrite, socketPath: "/tmp/s.sock")
        XCTAssertEqual(args, ["import", "-", "--dry-run", "--on-conflict", "overwrite", "--socket", "/tmp/s.sock"])
        XCTAssertEqual(ImportRunner.arguments(dryRun: false, onConflict: .skip, socketPath: "/s").contains("--dry-run"), false)
    }

    func testTheEnvironmentIsReplacedNotInherited() {
        let env = ImportRunner.standardEnvironment(from: ["HOME": "/Users/a", "USER": "a", "SECRET_TOKEN": "x", "PATH": "/evil", "DYLD_INSERT_LIBRARIES": "/x", "LANG": "en_US.UTF-8"])
        XCTAssertEqual(env, ["HOME": "/Users/a", "USER": "a", "LANG": "en_US.UTF-8", "PATH": "/usr/bin:/bin"])
    }
}

/// The process plumbing, with small shell scripts standing in for the helper.
final class ImportRunnerProcessTests: XCTestCase {
    private func script(_ body: String) throws -> URL {
        let url = URL(fileURLWithPath: "/tmp/gdt-helper-\(UUID().uuidString.prefix(8)).sh")
        try ("#!/bin/sh\n" + body + "\n").write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func file(_ content: String) throws -> FileHandle {
        let url = URL(fileURLWithPath: "/tmp/gdt-file-\(UUID().uuidString.prefix(8)).env")
        try content.write(to: url, atomically: true, encoding: .utf8)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        let fh = try FileHandle(forReadingFrom: url)
        addTeardownBlock { try? fh.close() }
        return fh
    }

    func testTheFileDescriptorIsTheHelpersStandardInput() async throws {
        let helper = try script("cat; echo \"args: $*\" >&2; exit 3")
        let runner = ImportRunner(executable: helper, socketPath: "/tmp/s.sock", environment: ["PATH": "/usr/bin:/bin"])
        let out = try await runner.run(from: try file("A=1\nB=two words\n"), dryRun: true, onConflict: .skip)
        XCTAssertEqual(out.stdout, "A=1\nB=two words\n")  // came through the descriptor, untouched by this process
        XCTAssertEqual(out.exitCode, 3)
        XCTAssertFalse(out.succeeded)
        XCTAssertFalse(out.timedOut)
        XCTAssertEqual(out.stderr, "args: import - --dry-run --on-conflict skip --socket /tmp/s.sock\n")
    }

    func testTheHelperGetsAMinimalEnvironment() async throws {
        let helper = try script("env | sort")
        let runner = ImportRunner(executable: helper, socketPath: "/tmp/s.sock")
        let out = try await runner.run(from: FileHandle.nullDevice, dryRun: false, onConflict: .error)
        let names = Set(out.stdout.split(separator: "\n").compactMap { $0.split(separator: "=", maxSplits: 1).first.map(String.init) })
        XCTAssertTrue(names.isSubset(of: ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"]), "\(names)")
        XCTAssertTrue(out.stdout.contains("PATH=/usr/bin:/bin\n"))
        XCTAssertFalse(names.contains("GRANTPIN_SOCKET") || names.contains("DYLD_INSERT_LIBRARIES"))
    }

    func testOutputIsCapped() async throws {
        let helper = try script("head -c 300000 /dev/zero | tr '\\0' 'x'")
        let runner = ImportRunner(executable: helper, socketPath: "/tmp/s.sock", environment: ["PATH": "/usr/bin:/bin"])
        let out = try await runner.run(from: FileHandle.nullDevice, dryRun: true, onConflict: .skip)
        XCTAssertEqual(out.stdout.utf8.count, ImportRunner.outputCap)
        XCTAssertEqual(out.exitCode, 0)
    }

    func testTimeoutStopsTheHelper() async throws {
        let helper = try script("sleep 30")
        let runner = ImportRunner(executable: helper, socketPath: "/tmp/s.sock", environment: ["PATH": "/usr/bin:/bin"])
        let started = Date()
        let out = try await runner.run(from: FileHandle.nullDevice, dryRun: true, onConflict: .skip, timeout: 0.4)
        XCTAssertTrue(out.timedOut)
        XCTAssertFalse(out.succeeded)
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }

    func testCancellingStopsTheHelper() async throws {
        let helper = try script("sleep 30")
        let runner = ImportRunner(executable: helper, socketPath: "/tmp/s.sock", environment: ["PATH": "/usr/bin:/bin"])
        let started = Date()
        let task = Task { try await runner.run(from: FileHandle.nullDevice, dryRun: true, onConflict: .skip) }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        let out = try await task.value  // terminated by SIGTERM: a result, not a hang
        XCTAssertFalse(out.succeeded)
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }
}
