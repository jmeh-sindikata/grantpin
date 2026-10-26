import Foundation
import XCTest
@testable import GrantpinKit

/// Answers the helper from a script, one reply per run, and records how it was called.
final class FakeImportService: ImportService, @unchecked Sendable {
    struct Call: Equatable { var dryRun: Bool; var mode: ImportConflictMode }
    private let lock = NSLock()
    private var replies: [Result<HelperOutput, Error>]
    private(set) var calls = [Call]()
    init(_ replies: [Result<HelperOutput, Error>]) { self.replies = replies }

    func runImport(from file: FileHandle, dryRun: Bool, onConflict: ImportConflictMode) async throws -> HelperOutput {
        let next: Result<HelperOutput, Error> = lock.withLock {
            calls.append(Call(dryRun: dryRun, mode: onConflict))
            return replies.count > 1 ? replies.removeFirst() : replies[0]
        }
        return try next.get()
    }

    static func ok(_ stdout: String) -> Result<HelperOutput, Error> {
        .success(HelperOutput(exitCode: 0, stdout: stdout, stderr: "", timedOut: false))
    }
    static func fail(_ stderr: String, code: Int32 = 1) -> Result<HelperOutput, Error> {
        .success(HelperOutput(exitCode: code, stdout: "", stderr: stderr, timedOut: false))
    }
}

@MainActor
final class ImportViewModelTests: XCTestCase {
    func model(_ svc: FakeImportService, finished: @escaping @MainActor () async -> Void = {}) -> ImportViewModel {
        ImportViewModel(service: svc, fileName: ".env", openFile: { FileHandle.nullDevice }, onImported: finished)
    }

    func testPreviewThenImportWithTheDefaultSkipMode() async {
        let svc = FakeImportService([
            FakeImportService.ok("(dry run) would be added: 2 (A, B)\n(dry run) would be skipped (exists): 1 (C)\n(dry run) would be ignored (empty value): 1 (D)\n"),
            FakeImportService.ok("added: 2 (A, B)\nskipped (exists): 1 (C)\nignored (empty value): 1 (D)\n"),
        ])
        var finished = 0
        let m = model(svc) { finished += 1 }
        XCTAssertEqual(m.mode, .skip)
        await m.preview()
        let r = try! XCTUnwrap(m.report)
        XCTAssertEqual([r.addedCount, r.overwrittenCount, r.skippedCount, r.emptyCount], [2, 0, 1, 1])
        XCTAssertEqual(r.added, ["A", "B"])
        XCTAssertTrue(m.canImport)
        XCTAssertNil(m.overwriteConfirmation)
        XCTAssertEqual(finished, 0)

        await m.performImport()
        guard case .done(let done) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(done.summary, "Added 2, skipped 1, ignored 1 empty. Nothing was overwritten.")
        XCTAssertEqual(svc.calls, [.init(dryRun: true, mode: .skip), .init(dryRun: false, mode: .skip)])
        XCTAssertEqual(finished, 1, "the list reloads after the real run")
    }

    func testDryRunIsAlwaysFirst() async {
        let svc = FakeImportService([FakeImportService.ok("(dry run) would be added: 1 (A)\n")])
        let m = model(svc)
        await m.performImport()  // no preview yet: nothing happens
        XCTAssertTrue(svc.calls.isEmpty)
        await m.preview()
        XCTAssertEqual(svc.calls.first?.dryRun, true)
    }

    func testChangingTheModeRerunsTheDryRunWithThatMode() async {
        let svc = FakeImportService([
            FakeImportService.ok("(dry run) would be skipped (exists): 1 (A)\n"),
            FakeImportService.ok("(dry run) would be overwritten: 1 (A)\n"),
        ])
        let m = model(svc)
        await m.preview()
        XCTAssertFalse(m.canImport, "everything exists and Skip is chosen")
        await m.setMode(.overwrite)
        XCTAssertEqual(svc.calls.last, .init(dryRun: true, mode: .overwrite))
        XCTAssertTrue(m.canImport)
        XCTAssertEqual(m.overwriteConfirmation, Confirmation.importOverwrite(names: ["A"]))
        await m.setMode(.overwrite)
        XCTAssertEqual(svc.calls.count, 2, "same mode: no rerun")
    }

    func testStopIfAnyExistReportsTheConflicts() async {
        let svc = FakeImportService([FakeImportService.fail("already exist (use --on-conflict skip|overwrite): A, B\n")])
        let m = model(svc)
        await m.preview()
        guard case .failed(let f) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertEqual(f.conflicts, ["A", "B"])
        XCTAssertEqual(f.headline, "Some of these secrets already exist.")
        XCTAssertFalse(m.canImport)
    }

    func testParseErrorsShowTheLineNumber() async {
        let svc = FakeImportService([FakeImportService.fail("vault: dotenv line 7: invalid key\n")])
        let m = model(svc)
        await m.preview()
        guard case .failed(let f) = m.phase else { return XCTFail() }
        XCTAssertEqual(f.headline, "Line 7: invalid key")
        XCTAssertFalse(f.partial)
        let other = ImportFailure.parse(stderr: "Error: vault: dotenv line 12: unterminated quote", partial: false)
        XCTAssertEqual(other.headline, "Line 12: unterminated quote")
        XCTAssertEqual(ImportFailure.parse(stderr: "vault: dotenv line 3: expected KEY=value", partial: false).headline, "Line 3: expected KEY=value")
    }

    func testUnknownHelperErrorIsSanitisedAndShortened() async {
        let evil = "boom \u{1B}[31m\u{202E}" + String(repeating: "x", count: 2000)
        let f = ImportFailure.parse(stderr: evil, partial: false)
        XCTAssertEqual(f.headline, "grantpin could not import that file.")
        XCTAssertFalse(f.detail!.unicodeScalars.contains("\u{1B}"))
        XCTAssertFalse(f.detail!.unicodeScalars.contains("\u{202E}"))
        XCTAssertLessThanOrEqual(f.detail!.count, 500)
    }

    func testAFailedRealRunSaysSomeSecretsMayHaveBeenImported() async {
        let svc = FakeImportService([
            FakeImportService.ok("(dry run) would be added: 2 (A, B)\n"),
            FakeImportService.fail("importing B: grantpin: internal\n"),
        ])
        var finished = 0
        let m = model(svc) { finished += 1 }
        await m.preview()
        await m.performImport()
        guard case .failed(let f) = m.phase else { return XCTFail() }
        XCTAssertTrue(f.partial)
        XCTAssertEqual(ImportFailure.partialNote, "Some secrets may have been imported. Review the list.")
        XCTAssertEqual(finished, 1, "reload even after a failure: some names may exist now")
    }

    func testGarbageOutputIsRefused() async {
        let m = model(FakeImportService([FakeImportService.ok("hello\n")]))
        await m.preview()
        guard case .failed(let f) = m.phase else { return XCTFail() }
        XCTAssertEqual(f.headline, "grantpin printed something unexpected.")
    }

    func testTimeoutAndLaunchFailure() async {
        let t = model(FakeImportService([.success(HelperOutput(exitCode: 15, stdout: "", stderr: "", timedOut: true))]))
        await t.preview()
        guard case .failed(let f) = t.phase else { return XCTFail() }
        XCTAssertEqual(f.headline, "The import took too long.")
        let l = model(FakeImportService([.failure(GrantpinError.io("x"))]))
        await l.preview()
        guard case .failed(let g) = l.phase else { return XCTFail() }
        XCTAssertEqual(g.headline, "The helper could not be started.")
    }

    func testTheFileIsReopenedForEveryRun() async {
        let svc = FakeImportService([FakeImportService.ok("(dry run) would be added: 1 (A)\n"), FakeImportService.ok("added: 1 (A)\n")])
        let opens = Counter()
        let m = ImportViewModel(service: svc, fileName: ".env", openFile: { opens.bump(); return FileHandle.nullDevice })
        await m.preview()
        await m.performImport()
        XCTAssertEqual(opens.value, 2)
    }

    func testAFileThatCannotBeOpened() async {
        let m = ImportViewModel(service: FakeImportService([FakeImportService.ok("nothing to import\n")]), fileName: ".env",
                                openFile: { throw CocoaError(.fileReadNoPermission) })
        await m.preview()
        guard case .failed(let f) = m.phase else { return XCTFail() }
        XCTAssertEqual(f.headline, "That file could not be opened.")
    }

    func testNothingToImport() async {
        let m = model(FakeImportService([FakeImportService.ok("nothing to import\n")]))
        await m.preview()
        XCTAssertFalse(m.canImport)
        XCTAssertEqual(m.report?.summary, "Nothing to import.")
    }

    func testSummaryWording() throws {
        XCTAssertEqual(try ImportReport.parse("added: 3 (A, B, C)\nskipped (exists): 1 (D)\n").summary, "Added 3, skipped 1. Nothing was overwritten.")
        XCTAssertEqual(try ImportReport.parse("overwritten: 2 (A, B)\n").summary, "Overwrote 2.")
        XCTAssertEqual(try ImportReport.parse("skipped (exists): 1 (A)\n").summary, "Skipped 1. Nothing was overwritten.")
    }

    func testFileNameIsSanitised() {
        let m = ImportViewModel(service: FakeImportService([FakeImportService.ok("nothing to import\n")]), fileName: "a\u{202E}.env", openFile: { .nullDevice })
        XCTAssertFalse(m.fileName.unicodeScalars.contains("\u{202E}"))
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func bump() { lock.withLock { n += 1 } }
    var value: Int { lock.withLock { n } }
}
