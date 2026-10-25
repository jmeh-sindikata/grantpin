import Foundation

/// Where the daemon's socket is (docs/UI-SPEC.md section 2.3).
public enum SocketPath {
    /// The environment variable that overrides the default. When it is set the
    /// app is in development mode.
    public static let environmentKey = "GRANTD_SOCKET"

    /// The longest path a Unix socket address holds (sun_path is 104 bytes,
    /// including the terminating NUL).
    public static let maxBytes = 103

    /// `GRANTD_SOCKET` if set and non-empty, else
    /// `~/Library/Application Support/grantd/grantd.sock`.
    ///
    /// Not yet implemented: the `GRANTD_SOCKET` recorded in the LaunchAgent
    /// plist (UI-SPEC 2.3 rule 2); it arrives with the Monitor.
    public static func resolve(environment: [String: String] = ProcessInfo.processInfo.environment,
                               home: URL = FileManager.default.homeDirectoryForCurrentUser) -> String {
        if let p = environment[environmentKey], !p.isEmpty { return p }
        return home.appendingPathComponent("Library/Application Support/grantd/grantd.sock").path
    }

    /// True when the path comes from the environment (development mode).
    public static func isDevelopment(environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
        !(environment[environmentKey] ?? "").isEmpty
    }
}
