import Foundation

/// The texts of the Connect panel (docs/UI-SPEC.md 3.5): the exact `claude
/// mcp add` commands, the `.mcp.json` snippet and the test prompt.
///
/// `helper` is the absolute path of the helper binary (inside the signed
/// bundle). It is shell-quoted in the commands and JSON-escaped in the
/// snippet, so a folder name with a space or an apostrophe still works.
public enum ConnectSnippets {
    public enum Scope: String, CaseIterable, Sendable {
        /// `--scope user`: every project (the default).
        case allProjects
        /// Run inside one project's folder.
        case oneProject
    }

    /// The four tools `/mcp` should list (README "Quick start" step 5).
    public static let toolNames = ["secret_list", "secret_exists", "secret_masked", "secret_run"]

    public static let testPrompt = "Use grantd's secret_list tool and tell me the names of my secrets."
    public static let testPromptCaption = "Claude will see names only, never values. To see an approval, ask it to run a command with a secret."
    public static let restartNote = "Claude Code must be restarted, or run /mcp, to pick up the new server."
    public static let jsonCaption = "Put this in a file named .mcp.json in your project's folder. It contains a path on your Mac, so don't commit it to a shared repository."
    public static let oldPathCallout = "Already connected with an older path? Run claude mcp remove grantd first, then the command above."
    public static let removeCommand = "claude mcp remove grantd"
    public static let projectHint = "Run this inside your project's folder."

    /// Single-quotes `path` unless it only has `[A-Za-z0-9_./-]`; an embedded
    /// `'` becomes `'\''`.
    public static func shellQuote(_ path: String) -> String {
        let safe = !path.isEmpty && path.utf8.allSatisfy { b in
            (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                || b == 0x5F || b == 0x2E || b == 0x2F || b == 0x2D
        }
        if safe { return path }
        return "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// `claude mcp add --scope user grantd -- {HELPER} mcp` or, for one
    /// project, `claude mcp add grantd -- {HELPER} mcp`.
    public static func command(scope: Scope, helper: String) -> String {
        let quoted = shellQuote(helper)
        switch scope {
        case .allProjects: return "claude mcp add --scope user grantd -- \(quoted) mcp"
        case .oneProject: return "claude mcp add grantd -- \(quoted) mcp"
        }
    }

    /// The `.mcp.json` text, pretty-printed, the path JSON-escaped. There is
    /// deliberately no password or environment variable in it.
    public static func mcpJSON(helper: String) -> String {
        """
        {
          "mcpServers": {
            "grantd": {
              "command": \(jsonString(helper)),
              "args": ["mcp"]
            }
          }
        }
        """
    }

    static func jsonString(_ s: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        guard let data = try? encoder.encode(s) else { return "\"\"" }
        return String(decoding: data, as: UTF8.self)
    }

    /// Where the helper is, for the default install location, when the app
    /// has no resolvable helper (an unsigned development build).
    public static func defaultHelperPath(bundleURL: URL) -> String {
        bundleURL.standardizedFileURL.appendingPathComponent(HelperLocator.relativePath).path
    }
}

/// Anything that can answer `exists`. `Client` does.
public protocol ExistsService: Sendable {
    func exists(_ name: String) async throws -> Bool
}

extension Client: ExistsService {}

/// The Connect panel's "Test connection": asks the daemon whether a secret
/// exists, the same question `secret_exists` sends, through the same socket
/// Claude Code's `grantd mcp` uses. It proves the background service answers
/// and the vault is open. It cannot tell whether Claude Code has the server
/// registered (the app does not read another tool's configuration).
public enum ConnectionTest {
    public enum Result: Equatable, Sendable {
        case answered
        case failed(UserMessage)

        public var text: String {
            switch self {
            case .answered:
                return "grantd answered. Claude Code asks it the same way."
            case .failed(let m):
                return m.text
            }
        }
    }

    /// The name asked about. Valid, and not one a person would store.
    public static let probeName = "grantd.connection-test"

    public static func run(_ service: ExistsService) async -> Result {
        do {
            _ = try await service.exists(probeName)
            return .answered
        } catch {
            return .failed(UserMessage.from(error))
        }
    }
}

/// Where the running app lives (docs/UI-SPEC.md 2.5 "Where the app may run
/// from"): `service install` refuses temporary directories and a translocated
/// app runs from a randomised read-only path, so the service and vault
/// actions need the app in an Applications folder.
public enum AppLocation: Equatable, Sendable {
    case ok
    /// Gatekeeper moved it to a random read-only path.
    case translocated
    case elsewhere

    public static let blockedMessage = "Move grantd to your Applications folder first"
    public static let moveButton = "Move to Applications and Relaunch"

    public static func check(bundleURL: URL, home: URL = FileManager.default.homeDirectoryForCurrentUser) -> AppLocation {
        let path = bundleURL.standardizedFileURL.path
        if path.contains("/AppTranslocation/") { return .translocated }
        let user = home.standardizedFileURL.appendingPathComponent("Applications").path
        for root in ["/Applications", user] where path.hasPrefix(root + "/") {
            return .ok
        }
        return .elsewhere
    }

    public var isOK: Bool { self == .ok }

    /// Candidate destinations for the move, best first.
    public static func destinations(bundleName: String, home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [URL] {
        [URL(fileURLWithPath: "/Applications").appendingPathComponent(bundleName),
         home.appendingPathComponent("Applications").appendingPathComponent(bundleName)]
    }

    public enum MoveError: Error, Equatable, Sendable {
        case alreadyThere(String)
        case failed
    }

    /// Copies the app to the first destination that works and returns it. The
    /// original is left where it is (a translocated or disk-image copy cannot
    /// be moved out), and an existing app of the same name is never replaced.
    public static func copyToApplications(
        bundleURL: URL, home: URL = FileManager.default.homeDirectoryForCurrentUser,
        destinations: [URL]? = nil, fileManager fm: FileManager = .default
    ) throws -> URL {
        let targets = destinations ?? Self.destinations(bundleName: bundleURL.lastPathComponent, home: home)
        var lastExisting: String?
        for target in targets {
            if fm.fileExists(atPath: target.path) { lastExisting = target.path; continue }
            do {
                try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
                try fm.copyItem(at: bundleURL, to: target)
                return target
            } catch {
                continue
            }
        }
        if let lastExisting { throw MoveError.alreadyThere(lastExisting) }
        throw MoveError.failed
    }
}
