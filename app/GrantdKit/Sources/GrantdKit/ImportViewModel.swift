import Foundation
import Observation

/// The Import .env sheet (docs/UI-SPEC.md 3.2).
///
/// The app never reads the file's bytes. For each run it opens the file again
/// (`openFile`), hands the open descriptor to the helper as standard input and
/// parses only the names the helper prints. Values never enter this process.
/// A dry run always comes first; the real run is a separate step, after the
/// person has seen the preview, chosen what happens to names that already
/// exist and, for Overwrite, confirmed.
@Observable
@MainActor
public final class ImportViewModel {
    public enum Phase: Equatable, Sendable {
        /// Running a dry run.
        case previewing
        /// The dry run's result.
        case preview(ImportReport)
        /// The dry run (or the import) failed.
        case failed(ImportFailure)
        /// Running the real import.
        case importing
        /// The real run's report.
        case done(ImportReport)
    }

    public private(set) var phase: Phase = .previewing
    public private(set) var mode: ImportConflictMode = .skip
    /// The file's name, for the title (sanitised).
    public let fileName: String

    @ObservationIgnored private let service: ImportService
    @ObservationIgnored private let openFile: @Sendable () throws -> FileHandle
    @ObservationIgnored private let onImported: @MainActor () async -> Void

    /// - Parameters:
    ///   - openFile: opens the user's file for reading. Called once per run;
    ///     the model closes the handle it gets.
    ///   - onImported: called after a real run finished (successfully or not),
    ///     so the secrets list can reload.
    public init(service: ImportService, fileName: String, openFile: @escaping @Sendable () throws -> FileHandle,
                onImported: @escaping @MainActor () async -> Void = {}) {
        self.service = service
        self.fileName = DisplayText.sanitise(fileName)
        self.openFile = openFile
        self.onImported = onImported
    }

    public var isBusy: Bool { phase == .previewing || phase == .importing }

    public var report: ImportReport? {
        switch phase {
        case .preview(let r), .done(let r): return r
        default: return nil
        }
    }

    // MARK: steps

    /// Step 1: the dry run with the current conflict mode (the first one is
    /// Skip existing).
    public func preview() async {
        phase = .previewing
        phase = await run(dryRun: true)
    }

    /// Choosing another conflict mode re-runs the dry run, so the preview lists
    /// exactly what that mode would do.
    public func setMode(_ new: ImportConflictMode) async {
        guard new != mode else { return }
        mode = new
        await preview()
    }

    /// The preview allows importing: there is something to add or overwrite,
    /// and no unresolved conflict.
    public var canImport: Bool {
        guard case .preview(let r) = phase else { return false }
        return !r.added.isEmpty || !r.overwritten.isEmpty
    }

    /// Non-nil when Import must be confirmed first: Overwrite with names that exist.
    public var overwriteConfirmation: Confirmation? {
        guard mode == .overwrite, case .preview(let r) = phase, !r.overwritten.isEmpty else { return nil }
        return Confirmation.importOverwrite(names: r.overwritten)
    }

    /// Step 2: the real run. The report it prints is the truth, even if the
    /// file changed after the preview.
    public func performImport() async {
        guard canImport else { return }
        phase = .importing
        phase = await run(dryRun: false)
        await onImported()
    }

    private func run(dryRun: Bool) async -> Phase {
        let handle: FileHandle
        do { handle = try openFile() } catch {
            return .failed(ImportFailure(headline: "That file could not be opened.", detail: nil, partial: false))
        }
        defer { try? handle.close() }
        let out: HelperOutput
        do {
            out = try await service.runImport(from: handle, dryRun: dryRun, onConflict: mode)
        } catch GrantdError.peerNotGrantd {
            // Checked before the helper started: nothing was read or sent.
            return .failed(ImportFailure(headline: PeerVerifier.mismatchMessage, detail: nil, partial: false))
        } catch {
            return .failed(ImportFailure(headline: "The helper could not be started.", detail: nil, partial: !dryRun))
        }
        if out.timedOut {
            return .failed(ImportFailure(headline: "The import took too long.", detail: nil, partial: !dryRun))
        }
        guard out.exitCode == 0 else {
            return .failed(ImportFailure.parse(stderr: out.stderr, partial: !dryRun))
        }
        do {
            return dryRun ? .preview(try ImportReport.parse(out.stdout)) : .done(try ImportReport.parse(out.stdout))
        } catch {
            return .failed(ImportFailure(headline: "grantd printed something unexpected.", detail: nil, partial: !dryRun))
        }
    }
}

/// Why an import step failed, worded for the sheet.
public struct ImportFailure: Equatable, Sendable {
    public var headline: String
    /// Names that already exist, when the mode was "Stop if any exist".
    public var conflicts: [String] = []
    public var detail: String?
    /// The real run failed: some secrets may have been imported already.
    public var partial: Bool

    public init(headline: String, conflicts: [String] = [], detail: String?, partial: Bool) {
        self.headline = headline
        self.conflicts = conflicts
        self.detail = detail
        self.partial = partial
    }

    /// The sentence shown below a failed real run.
    public static let partialNote = "Some secrets may have been imported. Review the list."

    /// Reads the helper's stderr:
    ///
    ///     vault: dotenv line 7: invalid key        -> "Line 7: invalid key"
    ///     already exist (use --on-conflict ...): A, B   -> the conflict list
    ///
    /// Anything else is shown sanitised, cut to its last 500 characters.
    static func parse(stderr: String, partial: Bool) -> ImportFailure {
        let text = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = text.range(of: "dotenv line ") {
            let rest = text[range.upperBound...]
            let digits = rest.prefix(while: { $0.isASCII && $0.isNumber })
            if !digits.isEmpty {
                var tail = rest.dropFirst(digits.count)
                if tail.hasPrefix(":") { tail = tail.dropFirst() }
                let reason = DisplayText.sanitise(String(tail.prefix(while: { $0 != "\n" })).trimmingCharacters(in: .whitespaces))
                return ImportFailure(headline: reason.isEmpty ? "Line \(digits)" : "Line \(digits): \(reason)",
                                     detail: nil, partial: partial)
            }
        }
        if let range = text.range(of: "already exist (use --on-conflict skip|overwrite): ") {
            let names = text[range.upperBound...].prefix(while: { $0 != "\n" })
                .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            return ImportFailure(headline: "Some of these secrets already exist.", conflicts: names, detail: nil, partial: partial)
        }
        let detail = text.isEmpty ? nil : DisplayText.sanitise(String(text.suffix(500)), limit: 500, allowNewlines: true)
        return ImportFailure(headline: "grantd could not import that file.", detail: detail, partial: partial)
    }
}

extension ImportReport {
    public var addedCount: Int { added.count }
    public var overwrittenCount: Int { overwritten.count }
    public var skippedCount: Int { skipped.count }
    public var emptyCount: Int { ignoredEmpty.count }

    /// After the real run: `Added 3, skipped 1. Nothing was overwritten.`
    public var summary: String {
        if nothingToImport { return "Nothing to import." }
        var parts = [String]()
        if addedCount > 0 { parts.append(parts.isEmpty ? "Added \(addedCount)" : "added \(addedCount)") }
        if overwrittenCount > 0 { parts.append(parts.isEmpty ? "Overwrote \(overwrittenCount)" : "overwrote \(overwrittenCount)") }
        if skippedCount > 0 { parts.append(parts.isEmpty ? "Skipped \(skippedCount)" : "skipped \(skippedCount)") }
        if emptyCount > 0 { parts.append(parts.isEmpty ? "Ignored \(emptyCount) empty" : "ignored \(emptyCount) empty") }
        var text = parts.joined(separator: ", ") + "."
        if overwrittenCount == 0 { text += " Nothing was overwritten." }
        return text
    }
}
