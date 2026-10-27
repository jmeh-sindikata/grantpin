import Foundation
import Observation

/// The `grantpin` command for a Terminal, for someone who installed from the
/// disk image (the Homebrew cask links it by itself).
///
/// The tool is one symlink, `~/.local/bin/grantpin`, to the helper's real
/// executable inside the app bundle that is running. Nothing else is written:
/// no `/usr/local/bin`, no `sudo`, no shell profile. An existing file or a
/// link that points anywhere else is never replaced.
///
/// Every input is injected (the home folder, the bundle, the helper, the PATH)
/// so the tests run in a temporary folder.
public struct CommandLineTool: Sendable {
    public static let linkName = "grantpin"
    public static let folderComponents = [".local", "bin"]
    public static let folderDisplay = "~/.local/bin"

    public let home: URL
    public let bundleURL: URL
    /// The helper's real executable inside `bundleURL`, or nil when it was not found.
    public let helper: URL?
    /// The PATH to look at, or nil when it is not known.
    public let searchPath: String?

    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser, bundleURL: URL, helper: URL?, searchPath: String? = nil) {
        self.home = home
        self.bundleURL = bundleURL
        self.helper = helper
        self.searchPath = searchPath
    }

    public func with(searchPath: String?) -> CommandLineTool {
        CommandLineTool(home: home, bundleURL: bundleURL, helper: helper, searchPath: searchPath)
    }

    /// `~/.local/bin`
    public var folder: URL {
        Self.folderComponents.reduce(home) { $0.appendingPathComponent($1, isDirectory: true) }
    }

    /// `~/.local/bin/grantpin`
    public var link: URL { folder.appendingPathComponent(Self.linkName) }

    // MARK: what is at the link path

    public enum LinkState: Equatable, Sendable {
        case absent
        /// A symlink to this app's helper.
        case ours
        /// A symlink to another file inside this app bundle (an older layout).
        case otherInBundle(String)
        /// A symlink to somewhere else.
        case elsewhere(String)
        /// A regular file, a folder, or anything that could not be read.
        case notALink

        /// A link that goes away with this app: the Uninstall sheet and Remove may delete it.
        public var pointsIntoThisApp: Bool {
            switch self {
            case .ours, .otherInBundle: return true
            case .absent, .elsewhere, .notALink: return false
            }
        }
    }

    /// Looks at the link path without following it.
    public func linkState() -> LinkState {
        var st = stat()
        if lstat(link.path, &st) != 0 {
            return (errno == ENOENT || errno == ENOTDIR) ? .absent : .notALink
        }
        guard (st.st_mode & S_IFMT) == S_IFLNK,
              let written = try? FileManager.default.destinationOfSymbolicLink(atPath: link.path)
        else { return .notALink }
        // A relative destination is relative to the folder of the link; ".."
        // is folded away before anything is compared, so a path such as
        // "<bundle>/../x" does not count as inside the bundle.
        let destination = (written.hasPrefix("/")
            ? URL(fileURLWithPath: written)
            : URL(fileURLWithPath: written, relativeTo: folder)).standardizedFileURL.path
        if let helper, Self.same(destination, helper) { return .ours }
        if inBundle(destination) { return .otherInBundle(destination) }
        return .elsewhere(destination)
    }

    private static func same(_ path: String, _ other: URL) -> Bool {
        path == other.standardizedFileURL.path || path == other.resolvingSymlinksInPath().path
    }

    private func inBundle(_ path: String) -> Bool {
        let roots = [bundleURL.standardizedFileURL.path, bundleURL.resolvingSymlinksInPath().path]
        return roots.contains { path.hasPrefix($0 + "/") }
    }

    // MARK: the PATH

    private static func resolved(_ url: URL) -> String { url.standardizedFileURL.resolvingSymlinksInPath().path }

    private var searchFolders: [URL]? {
        guard let searchPath else { return nil }
        return searchPath.split(separator: ":", omittingEmptySubsequences: true)
            .filter { $0.hasPrefix("/") }
            .map { URL(fileURLWithPath: String($0), isDirectory: true) }
    }

    /// Whether `~/.local/bin` is one of the PATH's folders; nil when the PATH is not known.
    public var folderIsOnPath: Bool? {
        guard let folders = searchFolders else { return nil }
        let wanted = Self.resolved(folder)
        return folders.contains { Self.resolved($0) == wanted }
    }

    public enum OnPath: Equatable, Sendable {
        /// A `grantpin` on the PATH that ends at this app's helper (the Homebrew cask's link).
        case thisApp(String)
        /// Any other executable called `grantpin`.
        case another(String)

        public var path: String {
            switch self {
            case .thisApp(let p), .another(let p): return p
            }
        }
    }

    /// The first executable called `grantpin` on the PATH, as the shell would find it.
    public func firstOnPath() -> OnPath? {
        let fm = FileManager.default
        for dir in searchFolders ?? [] {
            let candidate = dir.appendingPathComponent(Self.linkName)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: candidate.path, isDirectory: &isDir), !isDir.boolValue,
                  fm.isExecutableFile(atPath: candidate.path) else { continue }
            let shown = candidate.standardizedFileURL.path
            if let helper, Self.resolved(candidate) == Self.resolved(helper) { return .thisApp(shown) }
            return .another(shown)
        }
        return nil
    }

    // MARK: status

    public enum Status: Equatable, Sendable {
        case notInstalled
        /// Our link, at this path.
        case installed(String)
        /// Something else is at the link path; it is left alone.
        case blocked(path: String, state: LinkState)
        /// No link of ours, but a `grantpin` is on the PATH already.
        case onPath(OnPath)
    }

    public func status() -> Status {
        let path = link.path
        switch linkState() {
        case .ours: return .installed(path)
        case .absent:
            if let found = firstOnPath() { return .onPath(found) }
            return .notInstalled
        case let state: return .blocked(path: path, state: state)
        }
    }

    // MARK: install and remove

    public enum Outcome: Equatable, Sendable {
        case installed(String)
        case alreadyInstalled(String)
        case removed(String)
        case nothingToRemove
        /// Something is in the way, or the helper is missing. Nothing was changed.
        case refused(String)
        case failed(String)

        public var isSuccess: Bool {
            switch self {
            case .installed, .alreadyInstalled, .removed, .nothingToRemove: return true
            case .refused, .failed: return false
            }
        }

        public var message: String {
            switch self {
            case .installed(let p): return "The grantpin command is installed at \(Self.shown(p))."
            case .alreadyInstalled(let p): return "The grantpin command is already installed at \(Self.shown(p))."
            case .removed(let p): return "The grantpin command was removed from \(Self.shown(p))."
            case .nothingToRemove: return "There is no grantpin command in \(CommandLineTool.folderDisplay)."
            case .refused(let text), .failed(let text): return text
            }
        }

        static func shown(_ path: String) -> String { DisplayText.sanitise(path, limit: 300) }
    }

    /// Creates the link. Never replaces anything: a file, a folder or a link
    /// that is not ours stops the install with a message that names it.
    public func install() -> Outcome {
        guard let helper else { return .refused("The helper inside this app could not be found.") }
        let path = link.path
        switch linkState() {
        case .ours: return .alreadyInstalled(path)
        case .absent: break
        case let other: return .refused(Self.inTheWay(path, other))
        }
        let fm = FileManager.default
        do {
            try ensureFolders(fm)
            // symlink(2) fails with EEXIST rather than replacing anything.
            try fm.createSymbolicLink(atPath: path, withDestinationPath: helper.path)
        } catch {
            // Something appeared meanwhile: report what is there, not a bare failure.
            switch linkState() {
            case .ours: return .alreadyInstalled(path)
            case .absent: return .failed("grantpin could not create \(Outcome.shown(path)).")
            case let other: return .refused(Self.inTheWay(path, other))
            }
        }
        return .installed(path)
    }

    /// `~/.local` and `~/.local/bin`, mode 0755, created only when missing.
    private func ensureFolders(_ fm: FileManager) throws {
        var current = home
        for part in Self.folderComponents {
            current = current.appendingPathComponent(part, isDirectory: true)
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: current.path, isDirectory: &isDir) {
                if isDir.boolValue { continue }
                throw CocoaError(.fileWriteFileExists)
            }
            try fm.createDirectory(at: current, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: current.path)
        }
    }

    static func inTheWay(_ path: String, _ state: LinkState) -> String {
        let p = Outcome.shown(path)
        switch state {
        case .elsewhere(let to), .otherInBundle(let to):
            return "\(p) is already a link to \(Outcome.shown(to)), so grantpin left it alone. "
                + "Move or delete it yourself if you want grantpin to use that name."
        default:
            return "\(p) already exists and is not a link to this app, so grantpin left it alone. "
                + "Move or delete it yourself if you want grantpin to use that name."
        }
    }

    /// Deletes the link, only when it points into this app. The file it points
    /// to is not touched.
    public func remove() -> Outcome {
        let path = link.path
        let state = linkState()
        switch state {
        case .absent: return .nothingToRemove
        case .elsewhere, .notALink:
            return .refused("\(Outcome.shown(path)) is not a link to this app, so grantpin left it alone.")
        case .ours, .otherInBundle:
            do {
                try FileManager.default.removeItem(atPath: path)
                return .removed(path)
            } catch {
                return .failed("grantpin could not remove \(Outcome.shown(path)).")
            }
        }
    }

    // MARK: the line to add to the shell

    /// The line that puts `~/.local/bin` on the PATH. grantpin shows it and
    /// offers to copy it; it never writes to a shell profile.
    public static func pathLine(forShell shell: String) -> String {
        isFish(shell) ? "fish_add_path ~/.local/bin" : "export PATH=\"$HOME/.local/bin:$PATH\""
    }

    public static func isFish(_ shell: String) -> Bool {
        URL(fileURLWithPath: shell).lastPathComponent == "fish"
    }
}

/// The "Command line tool" part of Settings > General.
@Observable
@MainActor
public final class CommandLineToolModel {
    public private(set) var tool: CommandLineTool
    public private(set) var status: CommandLineTool.Status
    /// What the last Install or Remove did.
    public private(set) var result: CommandLineTool.Outcome?
    /// True once the login shell's PATH has been read.
    public private(set) var pathKnown = false
    public let shell: String
    public let location: AppLocation
    public let isDevelopment: Bool

    @ObservationIgnored private let detectPath: @Sendable () async -> String

    public static let title = "Command line tool"
    public static let notInstalledText = "Not installed"
    public static let help = "Lets you and your scripts run grantpin from a Terminal. It adds one link, in \(CommandLineTool.folderDisplay), to the program inside this app."
    public static let temporaryLocationWarning =
        "grantpin is not in your Applications folder, so the link would point to a temporary location and stop working. Move grantpin to Applications first."
    public static let developmentNote = "In development mode the command line tool is not installed."
    public static let noHelperNote = "The helper inside this app could not be found."
    public static let onPathThisAppNote = "It points to this app, so there is nothing to install."
    public static let onPathAnotherNote =
        "It is not this app's program. If you install the link too, the one that comes first on your PATH wins."
    public static let pathMissingText = "\(CommandLineTool.folderDisplay) is not on your PATH, so a Terminal will not find the command yet."
    public static let pathStepsBash = "Add this line to your shell's startup file (for zsh, ~/.zshrc), then open a new Terminal window."
    public static let pathStepsFish = "Run this line once in a fish Terminal. fish remembers it."
    public static let pathNever = "grantpin never edits your shell's startup files."

    public init(tool: CommandLineTool, location: AppLocation, isDevelopment: Bool, shell: String = "/bin/zsh",
                detectPath: @escaping @Sendable () async -> String = { await PathDetector().detect() }) {
        self.tool = tool
        self.location = location
        self.isDevelopment = isDevelopment
        self.shell = shell
        self.detectPath = detectPath
        self.status = tool.status()
    }

    /// The shell whose PATH is read: `$SHELL` when listed in /etc/shells, else zsh.
    public static func loginShell() -> String { PathDetector().shell() }

    // MARK: what is allowed

    /// Why Install is off, or nil.
    public var disabledReason: String? {
        if isDevelopment { return Self.developmentNote }
        if tool.helper == nil { return Self.noHelperNote }
        if !location.isOK { return Self.temporaryLocationWarning }
        return nil
    }

    /// Install is offered when nothing of ours is there and nothing blocks the
    /// name; a `grantpin` that already resolves to this app needs no link.
    public var canInstall: Bool {
        guard disabledReason == nil else { return false }
        switch status {
        case .notInstalled, .onPath(.another): return true
        case .installed, .blocked, .onPath(.thisApp): return false
        }
    }

    public var canRemove: Bool {
        if isDevelopment { return false }
        if case .installed = status { return true }
        return false
    }

    // MARK: text

    /// The status line.
    public var statusText: String {
        switch status {
        case .notInstalled: return Self.notInstalledText
        case .installed(let p): return "Installed at \(DisplayText.sanitise(p, limit: 300))"
        case .onPath(let found): return "Another grantpin is already on your PATH at \(DisplayText.sanitise(found.path, limit: 300))"
        case .blocked(let p, let state): return CommandLineTool.inTheWay(p, state)
        }
    }

    /// A sentence under the status, or nil.
    public var statusNote: String? {
        switch status {
        case .onPath(.thisApp): return Self.onPathThisAppNote
        case .onPath(.another): return Self.onPathAnotherNote
        default: return nil
        }
    }

    /// True when the status is good news (shown with a check mark).
    public var statusIsOK: Bool {
        switch status {
        case .installed, .onPath(.thisApp): return true
        default: return false
        }
    }

    public var statusIsProblem: Bool {
        if case .blocked = status { return true }
        return false
    }

    /// The PATH hint: only for an installed link while `~/.local/bin` is not on the PATH.
    public var pathMissing: Bool {
        guard case .installed = status, pathKnown else { return false }
        return tool.folderIsOnPath == false
    }

    public var pathLine: String { CommandLineTool.pathLine(forShell: shell) }
    public var pathSteps: String { CommandLineTool.isFish(shell) ? Self.pathStepsFish : Self.pathStepsBash }

    // MARK: actions

    /// Reads the link and the login shell's PATH (not in development mode:
    /// no login shell is started for a screen that cannot act). Called each
    /// time Settings opens, so a PATH fixed in the meantime is noticed.
    public func refresh() async {
        if !isDevelopment {
            let path = await detectPath()
            tool = tool.with(searchPath: path)
            pathKnown = true
        }
        status = tool.status()
    }

    public func install() {
        guard canInstall else { return }
        result = tool.install()
        status = tool.status()
    }

    public func remove() {
        guard canRemove else { return }
        result = tool.remove()
        status = tool.status()
    }
}
