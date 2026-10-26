import Foundation

/// Where the daemon's socket is (docs/UI-SPEC.md section 2.3).
///
/// A Finder-launched app has none of the user's shell environment, and the
/// launchd job defines only `PATH` and optionally `GRANTD_SOCKET`, so the rule
/// order is:
///
/// 1. `GRANTD_SOCKET` in the app's own environment (tests, the development
///    scheme). When it decides the result, the app is in development mode.
/// 2. `EnvironmentVariables.GRANTD_SOCKET` in
///    `~/Library/LaunchAgents/dev.grantd.daemon.plist`, if the file exists and
///    defines a non-empty absolute path. It is the only file the app reads
///    that it did not write; it is parsed with `PropertyListSerialization`
///    and nothing else in it is used.
/// 3. `~/Library/Application Support/grantd/grantd.sock`.
///
/// `XDG_RUNTIME_DIR` is never consulted.
public enum SocketLocator {
    /// The environment variable that overrides the default.
    public static let environmentKey = "GRANTD_SOCKET"

    /// The LaunchAgent's label, and so its plist's file name.
    public static let launchAgentLabel = "dev.grantd.daemon"

    /// The longest path a Unix socket address holds (`sun_path` is 104 bytes,
    /// including the terminating NUL).
    public static let maxBytes = 103

    public enum Source: Equatable, Sendable {
        case environment
        case launchAgentPlist
        case defaultPath
    }

    public struct Resolution: Equatable, Sendable {
        public var path: String
        public var source: Source

        /// True when `GRANTD_SOCKET` in the app's environment decided the
        /// path: the app must not touch the real launchd job or vault.
        public var isDevelopment: Bool { source == .environment }

        /// True when the path is longer than a Unix socket address allows
        /// (a very long account name makes the default too long).
        public var isTooLong: Bool { path.utf8.count > SocketLocator.maxBytes }
    }

    /// `~/Library/LaunchAgents/dev.grantd.daemon.plist` under `home`.
    public static func launchAgentPlistURL(home: URL) -> URL {
        home.appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    /// The default socket path under `home`.
    public static func defaultPath(home: URL) -> String {
        home.appendingPathComponent("Library/Application Support/grantd/grantd.sock").path
    }

    /// Applies the rules in order. `plist` is read only when rule 1 does not
    /// decide; a missing, unreadable or malformed plist, or one without a
    /// usable value, falls through to the default.
    public static func resolve(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        plist: URL? = nil
    ) -> Resolution {
        if let p = environment[environmentKey], !p.isEmpty {
            return Resolution(path: p, source: .environment)
        }
        if let p = socketFromPlist(at: plist ?? launchAgentPlistURL(home: home)) {
            return Resolution(path: p, source: .launchAgentPlist)
        }
        return Resolution(path: defaultPath(home: home), source: .defaultPath)
    }

    /// `EnvironmentVariables.GRANTD_SOCKET` of the plist at `url`, if it is a
    /// non-empty absolute path.
    static func socketFromPlist(at url: URL) -> String? {
        guard let data = try? Data(contentsOf: url),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let root = object as? [String: Any],
              let env = root["EnvironmentVariables"] as? [String: Any],
              let path = env[environmentKey] as? String,
              path.hasPrefix("/")
        else { return nil }
        return path
    }
}
