import Foundation

/// How `grantpin import` treats a name that already exists (`--on-conflict`).
public enum ImportConflictMode: String, Sendable, CaseIterable {
    case skip, overwrite, error
}

/// What the helper CLI printed and how it ended. Both streams are capped.
public struct HelperOutput: Equatable, Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    /// True when the helper was stopped because it ran past its timeout.
    public var timedOut: Bool

    public var succeeded: Bool { exitCode == 0 && !timedOut }
}

/// Imports a `.env` file by running the helper CLI,
/// `grantpin import - [--dry-run] --on-conflict MODE --socket PATH`, with the
/// file's open descriptor as its standard input (docs/UI-SPEC.md 3.2).
///
/// **The Swift process never reads the file.** The descriptor goes straight to
/// the helper, whose Go parser is the only one; the values never enter this
/// process. The helper then sends each value to the daemon over the socket,
/// like any `grantpin set`. No value is ever put in the arguments or the
/// environment.
///
/// The environment is replaced, not inherited: `HOME`, `USER`, `LOGNAME`,
/// `TMPDIR` and `LANG` from this process and `PATH=/usr/bin:/bin`.
public struct ImportRunner: Sendable {
    /// Standard timeout of an import (docs/UI-SPEC.md 2.6).
    public static let timeout: TimeInterval = 120
    /// Each of stdout and stderr is kept up to this many bytes.
    public static let outputCap = 64 * 1024

    public let executable: URL
    public let socketPath: String
    let environmentOverride: [String: String]?
    let peerCheck: PeerCheck

    /// - Parameters:
    ///   - executable: the helper, `grantpin` inside `grantpin-daemon.app`
    ///     (or the dev binary in tests). Must be an absolute file URL.
    ///   - socketPath: the daemon socket the helper should use, passed as
    ///     `--socket`, so it needs no environment for that.
    ///   - environment: replaces the standard minimal environment (tests).
    public init(executable: URL, socketPath: String = SocketLocator.resolve().path, environment: [String: String]? = nil,
                peerCheck: PeerCheck = .automatic) {
        self.executable = executable
        self.socketPath = socketPath
        self.environmentOverride = environment
        self.peerCheck = peerCheck
    }

    /// The minimal environment of a helper process.
    public static func standardEnvironment(from source: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var env = ["PATH": "/usr/bin:/bin"]
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG"] {
            if let v = source[key] { env[key] = v }
        }
        return env
    }

    /// The arguments for one run, `-` meaning standard input.
    public static func arguments(dryRun: Bool, onConflict: ImportConflictMode, socketPath: String) -> [String] {
        var args = ["import", "-"]
        if dryRun { args.append("--dry-run") }
        args += ["--on-conflict", onConflict.rawValue, "--socket", socketPath]
        return args
    }

    /// Runs the import with `file` (opened by the caller, for example with
    /// `FileHandle(forReadingFrom:)`) as standard input. The caller keeps
    /// ownership of `file` and closes it. A non-zero exit is a normal result
    /// (`HelperOutput.exitCode`), not a thrown error; the helper's stderr says
    /// why. Cancelling the task terminates the helper.
    ///
    /// A real import (not a dry run) first checks who answers on the socket
    /// (`Client.verifyPeer`), because the helper is about to send the file's
    /// values there. The helper connects on its own afterwards, so this is a
    /// pre-flight check and not a guarantee about that connection.
    ///
    /// - Throws: `GrantpinError.io` if the helper cannot be started, and
    ///   `GrantpinError.peerNotGrantpin` if the socket is not answered by grantpin
    ///   (the helper is then not started and the file is not read).
    public func run(from file: FileHandle, dryRun: Bool, onConflict: ImportConflictMode,
                    timeout: TimeInterval = ImportRunner.timeout) async throws -> HelperOutput {
        if !dryRun {
            do {
                try await Client(socketPath: socketPath, peerCheck: peerCheck).verifyPeer()
            } catch GrantpinError.peerNotGrantpin {
                throw GrantpinError.peerNotGrantpin
            } catch {
                // Not running, a long path, a timeout: the helper reports those itself.
            }
        }
        return try await HelperProcess.run(
            executable: executable,
            arguments: Self.arguments(dryRun: dryRun, onConflict: onConflict, socketPath: socketPath),
            environment: environmentOverride ?? Self.standardEnvironment(),
            standardInput: file,
            timeout: timeout,
            outputCap: Self.outputCap)
    }
}

/// The names the helper reported, parsed from its stdout (docs/UI-SPEC.md 3.2).
/// Names only: a value never reaches this process.
public struct ImportReport: Equatable, Sendable {
    public var added: [String] = []
    public var overwritten: [String] = []
    public var skipped: [String] = []
    public var ignoredEmpty: [String] = []
    public var dryRun = false
    /// The helper printed `nothing to import`.
    public var nothingToImport = false

    /// Parses stdout such as
    ///
    ///     (dry run) would be added: 3 (A, B, C)
    ///     skipped (exists): 1 (D)
    ///
    /// Anything else (an unknown label, a count that disagrees with the
    /// names, a stray line) is `malformedResponse`: the contract with the CLI
    /// is exact, and a change to its wording must fail loudly.
    public static func parse(_ stdout: String) throws -> ImportReport {
        var report = ImportReport()
        var sawLine = false
        for rawLine in stdout.split(separator: "\n", omittingEmptySubsequences: true) {
            var line = Substring(rawLine)
            sawLine = true
            if line == "nothing to import" {
                report.nothingToImport = true
                continue
            }
            let dryPrefix = "(dry run) would be "
            let isDry = line.hasPrefix(dryPrefix)
            if isDry { line = line.dropFirst(dryPrefix.count) }
            if report.dryRun != isDry, report.hasEntries { throw unexpected() }
            report.dryRun = isDry

            guard let colon = line.firstIndex(of: ":") else { throw unexpected() }
            let label = String(line[..<colon])
            let rest = line[line.index(after: colon)...].drop(while: { $0 == " " })
            guard let open = rest.firstIndex(of: "("), rest.last == ")",
                  let count = Int(rest[..<open].trimmingCharacters(in: .whitespaces))
            else { throw unexpected() }
            let inner = rest[rest.index(after: open)..<rest.index(before: rest.endIndex)]
            let names = inner.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            guard count == names.count, !names.contains(where: \.isEmpty) else { throw unexpected() }
            switch label {
            case "added": report.added = names
            case "overwritten": report.overwritten = names
            case "skipped (exists)": report.skipped = names
            case "ignored (empty value)": report.ignoredEmpty = names
            default: throw unexpected()
            }
        }
        guard sawLine else { throw unexpected() }
        return report
    }

    private var hasEntries: Bool {
        !added.isEmpty || !overwritten.isEmpty || !skipped.isEmpty || !ignoredEmpty.isEmpty
    }

    private static func unexpected() -> GrantpinError {
        .malformedResponse("grantpin printed something unexpected")
    }
}
