import Foundation

/// Where the Go helper (`grantpin`) lives inside the app (docs/UI-SPEC.md 2.6).
public enum HelperLocator {
    public enum Failure: Error, Equatable, Sendable {
        case missing(String)
        case notExecutable
        case symlink
        case outsideBundle
    }

    /// `Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin`, relative to the app.
    public static let relativePath = "Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin"

    /// The helper of the app bundle at `bundleURL`. The path is resolved once;
    /// a symlink anywhere on it is refused, and so is anything that does not
    /// end up inside the bundle.
    ///
    /// - Parameter developmentOverride: a helper path to use instead (the
    ///   `GRANTPIN_HELPER` variable). Honoured only in development mode, where
    ///   the app talks to the insecure dev daemon; an unsigned build has no
    ///   usable embedded helper.
    public static func resolve(bundleURL: URL, developmentOverride: String? = nil) throws -> URL {
        if let override = developmentOverride, !override.isEmpty {
            guard override.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: override) else {
                throw Failure.notExecutable
            }
            return URL(fileURLWithPath: override)
        }
        let bundle = bundleURL.standardizedFileURL
        let candidate = bundle.appendingPathComponent(relativePath)
        let fm = FileManager.default
        guard fm.fileExists(atPath: candidate.path) else { throw Failure.missing(candidate.lastPathComponent) }
        let real = candidate.resolvingSymlinksInPath()
        let realBundle = bundle.resolvingSymlinksInPath()
        // No symlink between the bundle and the binary: the resolved path is
        // the bundle's resolved path plus the same relative path.
        guard real.path == realBundle.appendingPathComponent(relativePath).path else { throw Failure.symlink }
        guard real.path.hasPrefix(realBundle.path + "/") else { throw Failure.outsideBundle }
        guard fm.isExecutableFile(atPath: real.path) else { throw Failure.notExecutable }
        return real
    }
}

/// Finds the PATH to record for the background service (docs/UI-SPEC.md 2.5).
///
/// The daemon, and every command it runs for an agent, gets only the PATH
/// stored in the launchd job. A Finder-launched app has just
/// `/usr/bin:/bin:/usr/sbin:/sbin`, so Homebrew tools would be "command not
/// found" for someone who never opens a terminal. The login shell knows the
/// real one.
public struct PathDetector: Sendable {
    public static let fallback = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    public static let beginMarker = "__GD_BEGIN__"
    public static let endMarker = "__GD_END__"
    public static let timeout: TimeInterval = 5

    let environment: [String: String]
    let shellsFile: String
    let timeout: TimeInterval

    public init(environment: [String: String] = ProcessInfo.processInfo.environment, shellsFile: String = "/etc/shells",
                timeout: TimeInterval = PathDetector.timeout) {
        self.environment = environment
        self.shellsFile = shellsFile
        self.timeout = timeout
    }

    /// `$SHELL` if it is an absolute path to an executable listed in
    /// /etc/shells, else /bin/zsh.
    public func shell() -> String {
        guard let s = environment["SHELL"], s.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: s),
              let listed = try? String(contentsOfFile: shellsFile, encoding: .utf8),
              listed.split(separator: "\n").contains(where: { $0.trimmingCharacters(in: .whitespaces) == s })
        else { return "/bin/zsh" }
        return s
    }

    /// The text between the markers, or nil. Other output of the shell's rc
    /// files before or after is ignored.
    public static func extract(from output: String) -> String? {
        guard let b = output.range(of: beginMarker),
              let e = output.range(of: endMarker, range: b.upperBound..<output.endIndex)
        else { return nil }
        let path = String(output[b.upperBound..<e.lowerBound])
        return path.isEmpty ? nil : path
    }

    /// Whether `path` is a plausible PATH: absolute, no whitespace (fish
    /// joins a quoted `$PATH` with spaces, which is not a PATH) and at least
    /// one element that is an existing directory.
    public static func isPlausible(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains(where: { $0.isWhitespace }) else { return false }
        return path.split(separator: ":").contains { dir in
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: String(dir), isDirectory: &isDir) && isDir.boolValue
        }
    }

    /// Runs `$SHELL -ilc` and returns its PATH; the fallback list when that
    /// fails, times out or prints nothing usable.
    public func detect() async -> String {
        let shell = self.shell()
        var env = ["TERM": "dumb"]
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG"] {
            if let v = environment[key] { env[key] = v }
        }
        env["SHELL"] = shell
        // The login shell only sets up the environment; /bin/sh prints PATH,
        // so the quoting of "$PATH" does not depend on the shell (fish expands
        // it with spaces, not colons).
        let script = "exec /bin/sh -c 'printf \"\(Self.beginMarker)%s\(Self.endMarker)\" \"$PATH\"'"
        do {
            let out = try await HelperProcess.run(
                executable: URL(fileURLWithPath: shell), arguments: ["-ilc", script], environment: env,
                standardInput: nil, timeout: timeout, outputCap: 64 * 1024)
            if out.succeeded, let p = Self.extract(from: out.stdout), Self.isPlausible(p) { return p }
        } catch {}
        return Self.fallback
    }
}

/// What a helper action did, worded for the popover.
public struct ActionResult: Equatable, Sendable {
    public enum Outcome: Equatable, Sendable {
        case succeeded
        /// The job was started but the daemon has not answered yet.
        case startedNotAnswering
        case failed
    }

    public var outcome: Outcome
    /// One sentence for the person.
    public var summary: String
    /// The tail of stderr (or stdout), sanitised, for a disclosure. Nil if there is nothing.
    public var detail: String?
    /// `init` failed because the Secure Enclave is unavailable; the weaker
    /// Keychain protection would work (the retry belongs to onboarding).
    public var secureEnclaveUnavailable = false

    public var isSuccess: Bool { outcome != .failed }
}

/// The two things the popover can make the helper do when the daemon is
/// down or the vault is missing.
public protocol DaemonActions: Sendable {
    /// Installs and starts the background service.
    func startService() async -> ActionResult
    /// Creates the vault.
    func createVault() async -> ActionResult
}

/// Everything the Settings, onboarding and uninstall screens make the helper
/// do (docs/UI-SPEC.md 2.6). `HelperActions` is the real one; tests use a fake.
public protocol ServiceControl: Sendable {
    /// `service status`. Throws `ServiceStatus.ParseError` when it fails.
    func serviceStatus() async throws -> ServiceStatus
    /// `service install --exe <app> --path <PATH>`. A nil `path` detects the
    /// login shell's PATH first.
    func installService(path: String?) async -> ActionResult
    /// `service uninstall`.
    func uninstallService() async -> ActionResult
    /// `--version`, the text after "grantpin version ", or nil.
    func helperVersion() async -> String?
    /// `init`, or `init --keychain-fallback` (the weaker Keychain protection).
    func initVault(keychainFallback: Bool) async -> ActionResult
}

/// One service action at a time (docs/UI-SPEC.md 3.1). The app tells each
/// screen's model whether something else is changing the background service
/// right now (their `externallyBusy`): the popover's Start, a Settings action,
/// onboarding's Install, the open Uninstall sheet or the automatic restore.
/// The model then refuses its own action and shows this reason.
public enum ServiceBusy {
    public static let reason = "grantpin is changing its background service right now. Wait a moment."
}

/// Runs the signed helper bundled in the app.
///
/// **This is the only way the app starts the daemon** (docs/UI-SPEC.md 2.2):
/// `grantpin service install --exe <outer app> --path <PATH>` writes the
/// LaunchAgent and has launchd start it. The app never runs `grantpin daemon`
/// itself, and never `grantpin mcp`. `--exe` names the outer `grantpin.app`; the
/// service layer resolves it to `Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin`
/// (change G1), the binary the bundle's signature and profile apply to.
///
/// The environment of the helper is replaced, not inherited (`HOME`, `USER`,
/// `LOGNAME`, `TMPDIR`, `LANG`, `PATH=/usr/bin:/bin`).
public struct HelperActions: DaemonActions, ServiceControl {
    public static let installTimeout: TimeInterval = 20
    public static let initTimeout: TimeInterval = 30
    public static let shortTimeout: TimeInterval = 10

    public let helper: URL
    public let appBundle: URL
    public let pathDetector: PathDetector
    let environment: [String: String]

    public init(helper: URL, appBundle: URL, pathDetector: PathDetector = PathDetector(),
                environment: [String: String]? = nil) {
        self.helper = helper
        self.appBundle = appBundle
        self.pathDetector = pathDetector
        self.environment = environment ?? ImportRunner.standardEnvironment()
    }

    /// The arguments of `startService`: `service install --exe <app> --path <PATH>`.
    public static func installArguments(appBundle: URL, path: String) -> [String] {
        ["service", "install", "--exe", appBundle.path, "--path", path]
    }

    public func startService() async -> ActionResult { await installService(path: nil) }

    public func createVault() async -> ActionResult { await initVault(keychainFallback: false) }

    public func installService(path: String?) async -> ActionResult {
        let resolved: String
        if let path { resolved = path } else { resolved = await pathDetector.detect() }
        let args = Self.installArguments(appBundle: appBundle, path: resolved)
        let out: HelperOutput
        do {
            out = try await HelperProcess.run(executable: helper, arguments: args, environment: environment,
                                              standardInput: nil, timeout: Self.installTimeout)
        } catch {
            return ActionResult(outcome: .failed, summary: "grantpin could not be started: the helper did not run.")
        }
        return Self.interpretInstall(out)
    }

    public func uninstallService() async -> ActionResult {
        let out: HelperOutput
        do {
            out = try await HelperProcess.run(executable: helper, arguments: ["service", "uninstall"], environment: environment,
                                              standardInput: nil, timeout: Self.shortTimeout)
        } catch {
            return ActionResult(outcome: .failed, summary: "The background service could not be stopped: the helper did not run.")
        }
        return Self.interpretUninstall(out)
    }

    public func serviceStatus() async throws -> ServiceStatus {
        let out = try await HelperProcess.run(executable: helper, arguments: ["service", "status"], environment: environment,
                                              standardInput: nil, timeout: Self.shortTimeout)
        if out.timedOut { throw ServiceStatus.ParseError.failed(exitCode: -1) }
        return try ServiceStatus.parse(stdout: out.stdout, exitCode: out.exitCode)
    }

    public func helperVersion() async -> String? {
        guard let out = try? await HelperProcess.run(executable: helper, arguments: ["--version"], environment: environment,
                                                     standardInput: nil, timeout: Self.shortTimeout),
              out.succeeded else { return nil }
        return Self.parseVersion(out.stdout)
    }

    public func initVault(keychainFallback: Bool) async -> ActionResult {
        let args = keychainFallback ? ["init", "--keychain-fallback"] : ["init"]
        let out: HelperOutput
        do {
            out = try await HelperProcess.run(executable: helper, arguments: args, environment: environment,
                                              standardInput: nil, timeout: Self.initTimeout)
        } catch {
            return ActionResult(outcome: .failed, summary: "The vault could not be created: the helper did not run.")
        }
        return Self.interpretInit(out)
    }

    // MARK: reading the helper's answer

    static func interpretInstall(_ out: HelperOutput) -> ActionResult {
        if out.timedOut {
            return ActionResult(outcome: .failed, summary: "grantpin took too long to start.", detail: tail(out.stderr))
        }
        guard out.exitCode == 0 else {
            return ActionResult(outcome: .failed, summary: "grantpin could not be started.", detail: tail(out.stderr.isEmpty ? out.stdout : out.stderr))
        }
        if out.stdout.contains("WARNING:") {
            return ActionResult(outcome: .startedNotAnswering, summary: "Started, but grantpin has not answered yet.")
        }
        return ActionResult(outcome: .succeeded, summary: "grantpin is running in the background.")
    }

    static func interpretUninstall(_ out: HelperOutput) -> ActionResult {
        if out.timedOut {
            return ActionResult(outcome: .failed, summary: "Stopping the background service took too long.", detail: tail(out.stderr))
        }
        guard out.exitCode == 0 else {
            return ActionResult(outcome: .failed, summary: "The background service could not be stopped.",
                                detail: tail(out.stderr.isEmpty ? out.stdout : out.stderr))
        }
        return ActionResult(outcome: .succeeded, summary: "The background service was stopped and removed.")
    }

    /// `grantpin version 0.2.0` -> `0.2.0`.
    static func parseVersion(_ text: String) -> String? {
        let line = text.split(whereSeparator: \.isNewline).first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
        let prefix = "grantpin version "
        guard line.hasPrefix(prefix) else { return nil }
        let v = String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        return v.isEmpty ? nil : v
    }

    static func interpretInit(_ out: HelperOutput) -> ActionResult {
        if out.timedOut {
            return ActionResult(outcome: .failed, summary: "Creating the vault took too long.", detail: tail(out.stderr))
        }
        guard out.exitCode == 0 else {
            var r = ActionResult(outcome: .failed, summary: "The vault could not be created.", detail: tail(out.stderr.isEmpty ? out.stdout : out.stderr))
            r.secureEnclaveUnavailable = out.stderr.localizedCaseInsensitiveContains("Secure Enclave")
            return r
        }
        var summary = "Vault created."
        if out.stdout.contains("keystore tier: hardware") {
            summary = "Vault created. Its key is in the Secure Enclave."
        } else if out.stdout.contains("keystore tier: dialog") {
            summary = "Vault created. Its key is protected by the Keychain only."
        }
        return ActionResult(outcome: .succeeded, summary: summary)
    }

    /// The last 500 characters of helper output, sanitised; nil when empty.
    static func tail(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return nil }
        return DisplayText.sanitise(String(t.suffix(500)), limit: 500, allowNewlines: true)
    }
}
