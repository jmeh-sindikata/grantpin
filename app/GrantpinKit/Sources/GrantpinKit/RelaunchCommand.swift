import Foundation

/// The detached helper behind "Move to Applications and Relaunch".
///
/// The app declares `LSMultipleInstancesProhibited`, so the copy cannot be
/// started while this process is alive: the system would hand back the running
/// instance. Instead a small `/bin/sh` process waits for this app's pid to
/// exit and then opens the **exact path** of the copy with `/usr/bin/open`
/// (never by bundle id, which could pick another copy on disk).
///
/// The pid and the path are positional arguments of a fixed script
/// (`sh -c SCRIPT sh PID TARGET`), never part of the script text, so a path
/// with spaces, quotes, `$`, backticks or a newline is passed through as is.
public struct RelaunchCommand: Equatable, Sendable {
    public static let defaultOpenBinary = "/usr/bin/open"
    /// 100 polls of 0.1 s: give up after about ten seconds.
    public static let defaultPolls = 100

    /// `$1` pid, `$2` target path, `$3` open binary, `$4` number of polls.
    /// `$3` and `$4` are only passed by tests; the defaults apply otherwise.
    public static let script = """
        case "$1" in ''|*[!0-9]*|0) exit 2 ;; esac
        n="${4:-100}"
        while kill -0 "$1" 2>/dev/null; do
          n=$((n - 1))
          [ "$n" -gt 0 ] || exit 1
          sleep 0.1
        done
        exec "${3:-/usr/bin/open}" -- "$2"
        """

    public let executable: String
    public let arguments: [String]

    /// - Parameters:
    ///   - pid: the process to wait for (this app).
    ///   - target: the copy to open.
    ///   - openBinary: replaces `/usr/bin/open`; for tests only.
    ///   - polls: how many 0.1 s checks before giving up; for tests only.
    public init(pid: Int32, target: URL, openBinary: String = RelaunchCommand.defaultOpenBinary,
                polls: Int = RelaunchCommand.defaultPolls) {
        executable = "/bin/sh"
        var args = ["-c", Self.script, "sh", String(pid), target.standardizedFileURL.path]
        if openBinary != Self.defaultOpenBinary || polls != Self.defaultPolls {
            args += [openBinary, String(polls)]
        }
        arguments = args
    }

    /// The process, not yet started: no input or output, a minimal
    /// environment (nothing of this app's is passed on).
    public func makeProcess() -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        return process
    }

    /// Starts the helper and does not wait for it. Throws when it cannot be
    /// started, in which case nothing is running and the caller must not quit.
    @discardableResult
    public func start() throws -> Process {
        let process = makeProcess()
        try process.run()
        return process
    }
}
