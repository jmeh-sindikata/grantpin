import Foundation
import Observation

/// What `grantd service status` printed (cmd/grantd/cmd_service.go
/// `printServiceStatus`), parsed.
///
///     label:     dev.grantd.daemon
///     installed: yes
///     plist:     /Users/x/Library/LaunchAgents/dev.grantd.daemon.plist
///     loaded:    yes
///     running:   yes (pid 4242)
///     exe:       /Applications/grantd.app/Contents/Helpers/…/grantd
///     warning:   executable no longer exists; re-run `grantd service install`
///
/// Exit code 3 means "not installed" (only `label:` and `installed: no` are
/// printed). Every string is untrusted for display (`DisplayText`).
public struct ServiceStatus: Equatable, Sendable {
    public var label = ""
    public var installed = false
    public var plistPath: String?
    public var loaded = false
    public var running = false
    public var pid: Int?
    public var exePath: String?
    /// The text after `warning:`, if any.
    public var warning: String?
    /// The recorded executable no longer exists (the app was moved, replaced
    /// or upgraded to the nested-helper layout).
    public var exeMissing = false

    public init() {}

    public init(installed: Bool, loaded: Bool = false, running: Bool = false, pid: Int? = nil, exePath: String? = nil,
                plistPath: String? = nil, exeMissing: Bool = false, label: String = "dev.grantd.daemon", warning: String? = nil) {
        self.label = label; self.installed = installed; self.loaded = loaded; self.running = running; self.pid = pid
        self.exePath = exePath; self.plistPath = plistPath; self.exeMissing = exeMissing
        self.warning = warning ?? (exeMissing ? "executable no longer exists" : nil)
    }

    /// `service status` exits with this when no service is installed.
    public static let notInstalledExitCode: Int32 = 3

    public enum ParseError: Error, Equatable, Sendable {
        /// The helper failed in some other way (exit code, stderr tail).
        case failed(exitCode: Int32)
        /// Exit 0 but nothing recognisable.
        case unexpected
    }

    /// The legacy layout: the job still runs `Contents/MacOS/grantd` of a
    /// pre-0.2 bundle, which a Claude Code registration may name too.
    public var usesLegacyBundlePath: Bool {
        guard let p = exePath else { return false }
        return p.contains(".app/Contents/MacOS/grantd") && !p.contains("/Contents/Helpers/")
    }

    /// Parses the helper's answer.
    public static func parse(stdout: String, exitCode: Int32) throws -> ServiceStatus {
        var s = ServiceStatus()
        var sawKey = false
        for raw in stdout.split(whereSeparator: \.isNewline) {
            guard let colon = raw.firstIndex(of: ":") else { continue }
            let key = raw[raw.startIndex..<colon].trimmingCharacters(in: .whitespaces)
            let value = raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "label": s.label = value; sawKey = true
            case "installed": s.installed = value == "yes"; sawKey = true
            case "plist": s.plistPath = value.isEmpty ? nil : value
            case "loaded": s.loaded = value == "yes"
            case "running":
                if value.hasPrefix("yes") {
                    s.running = true
                    if let open = value.range(of: "(pid "), let close = value.range(of: ")", range: open.upperBound..<value.endIndex) {
                        s.pid = Int(value[open.upperBound..<close.lowerBound])
                    }
                }
            case "exe": s.exePath = value.isEmpty ? nil : value
            case "warning":
                s.warning = value
                if value.contains("no longer exists") { s.exeMissing = true }
            default: break
            }
        }
        if exitCode == notInstalledExitCode {
            s.installed = false
            return s
        }
        guard exitCode == 0 else { throw ParseError.failed(exitCode: exitCode) }
        guard sawKey else { throw ParseError.unexpected }
        return s
    }
}

/// What the popover says when the daemon does not answer, from `service
/// status` (docs/UI-SPEC.md 2.5).
public enum ServiceDiagnosis: Equatable, Sendable {
    /// The job is not installed.
    case notInstalled
    /// Installed, but the file it runs is gone.
    case exeMissing
    /// Installed and not running.
    case notRunning
    /// The process runs but the socket refuses.
    case notAnswering(pid: Int)
    /// The process id changed three times within a minute.
    case keepsStopping

    public static func derive(_ status: ServiceStatus, keepsStopping: Bool) -> ServiceDiagnosis {
        if !status.installed { return .notInstalled }
        if status.exeMissing { return .exeMissing }
        if keepsStopping { return .keepsStopping }
        if status.running { return .notAnswering(pid: status.pid ?? 0) }
        return .notRunning
    }

    public var headline: String {
        switch self {
        case .notInstalled: return "grantd is not set up to run in the background"
        case .exeMissing: return "The background service points to a file that no longer exists"
        case .notRunning: return "grantd is not running"
        case .notAnswering: return "grantd is running but not answering"
        case .keepsStopping: return "grantd keeps stopping"
        }
    }

    public var detail: String {
        switch self {
        case .notInstalled: return "Start it to use your secrets."
        case .exeMissing: return "The app was moved or replaced. Repair points the service at this app."
        case .notRunning: return "The service is installed but stopped. Start it to use your secrets."
        case .notAnswering: return "Restart the service. If it happens again, the log folder has the reason."
        case .keepsStopping: return "The service started and stopped again and again. The log folder has the reason."
        }
    }
}

/// Watches `service status` while the daemon is down and notices a service
/// that keeps exiting: the process id changed three times within 60 seconds
/// between polls (docs/UI-SPEC.md 2.5).
@Observable
@MainActor
public final class ServiceWatcher {
    public private(set) var status: ServiceStatus?
    public private(set) var diagnosis: ServiceDiagnosis?
    /// The helper could not be run or printed something unexpected.
    public private(set) var failed = false

    @ObservationIgnored private let control: ServiceControl?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var lastPID: Int?
    @ObservationIgnored private var changes = [Date]()

    /// 3 changes within 60 seconds is "keeps stopping".
    public nonisolated static let changeLimit = 3
    public nonisolated static let window: TimeInterval = 60

    public init(control: ServiceControl?, now: @escaping () -> Date = Date.init) {
        self.control = control
        self.now = now
    }

    /// Asks the helper for the service status and updates the diagnosis.
    public func poll() async {
        guard let control else { return }
        do {
            let s = try await control.serviceStatus()
            failed = false
            record(pid: s.running ? s.pid : nil)
            status = s
            diagnosis = ServiceDiagnosis.derive(s, keepsStopping: keepsStopping)
        } catch is CancellationError {
            return
        } catch {
            failed = true
            status = nil
            diagnosis = nil
        }
    }

    /// The daemon answers again: forget everything.
    public func reset() {
        status = nil; diagnosis = nil; failed = false; lastPID = nil; changes = []
    }

    public var keepsStopping: Bool {
        let cutoff = now().addingTimeInterval(-Self.window)
        return changes.filter { $0 >= cutoff }.count >= Self.changeLimit
    }

    private func record(pid: Int?) {
        let t = now()
        changes.removeAll { $0 < t.addingTimeInterval(-Self.window) }
        guard let pid else { return }
        if let last = lastPID, last != pid { changes.append(t) }
        lastPID = pid
    }
}
