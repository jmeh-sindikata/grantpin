import Foundation
import Observation
#if canImport(Darwin)
import Darwin
#endif

/// The lifetime presets of the standing-grant form (docs/UI-SPEC.md 3.3).
public enum StandingTTL: String, CaseIterable, Hashable, Sendable {
    case hour1, day1, days7, days30, days90, custom

    /// The ceiling the daemon enforces (`grant.MaxStandingGrantTTL`). A repo
    /// `.grantd.yml` may lower it; the daemon then answers with the limit and
    /// the form shows that answer as it is, never clamping.
    public static let maxSeconds = 90 * 86_400

    public var title: String {
        switch self {
        case .hour1: return "1 hour"
        case .day1: return "1 day"
        case .days7: return "7 days"
        case .days30: return "30 days"
        case .days90: return "90 days"
        case .custom: return "Custom…"
        }
    }

    /// The lifetime a new form starts with when nothing usable is remembered.
    public static let defaultPreset = StandingTTL.days30

    /// The remembered lifetime from a stored string. The stored value sits in
    /// `UserDefaults`, which any program running as the user can write, so
    /// only one of the preset values counts; anything else (a custom
    /// lifetime, an unknown or hostile string) is the default.
    public static func remembered(_ stored: String?) -> StandingTTL {
        guard let stored, let ttl = StandingTTL(rawValue: stored), ttl != .custom, ttl.seconds != nil else { return defaultPreset }
        return ttl
    }

    /// nil for `.custom`.
    public var seconds: Int? {
        switch self {
        case .hour1: return 3600
        case .day1: return 86_400
        case .days7: return 7 * 86_400
        case .days30: return 30 * 86_400
        case .days90: return Self.maxSeconds
        case .custom: return nil
        }
    }

    public enum CustomIssue: Error, Equatable, Sendable {
        case empty, invalid, notPositive, tooLong

        public var message: String {
            switch self {
            case .empty: return "Enter a time such as 12h, 7d or 1d12h."
            case .invalid: return "Use numbers with d, h or m: 7d, 12h, 90m."
            case .notPositive: return "Must be longer than zero."
            case .tooLong: return "A standing grant lasts 90 days at most."
            }
        }
    }

    /// Parses `7d`, `12h`, `90m` and sums like `1d12h`. Case-insensitive,
    /// whitespace around is ignored.
    public static func parseCustom(_ text: String) -> Result<Int, CustomIssue> {
        let s = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.isEmpty { return .failure(.empty) }
        var total = 0
        var digits = ""
        var sawUnit = false
        for ch in s {
            if ch.isASCII, ch.isNumber {
                digits.append(ch)
            } else if let scale = ["d": 86_400, "h": 3600, "m": 60][String(ch)], !digits.isEmpty {
                guard let n = Int(digits), n <= 10_000_000 else { return .failure(.tooLong) }
                total += n * scale
                digits = ""
                sawUnit = true
            } else {
                return .failure(.invalid)
            }
        }
        if !digits.isEmpty || !sawUnit { return .failure(.invalid) }
        if total <= 0 { return .failure(.notPositive) }
        if total > maxSeconds { return .failure(.tooLong) }
        return .success(total)
    }

    /// `1 hour`, `7 days`, `1 day 12 hours`, `45 minutes`.
    public static func durationText(seconds: Int) -> String {
        var rest = seconds
        var parts = [String]()
        for (unit, scale) in [("day", 86_400), ("hour", 3600), ("minute", 60)] {
            let n = rest / scale
            rest %= scale
            if n > 0 { parts.append("\(n) \(unit)\(n == 1 ? "" : "s")") }
        }
        if parts.isEmpty { return "\(max(seconds, 0)) seconds" }
        return parts.joined(separator: " ")
    }
}

/// The command prefix field: whitespace separated, single and double quotes
/// honoured, nothing else expanded (docs/UI-SPEC.md 3.3).
public enum CommandTokenizer {
    public enum Failure: Error, Equatable, Sendable {
        case unterminatedQuote
    }

    /// `php artisan "my cmd" 'a b'` -> `["php", "artisan", "my cmd", "a b"]`.
    /// A backslash escapes the next character outside quotes and `"` or `\`
    /// inside double quotes. An empty pair of quotes is an empty token (the
    /// daemon refuses it; the form says so).
    public static func tokenize(_ text: String) -> Result<[String], Failure> {
        var tokens = [String]()
        var current = ""
        var inToken = false
        var quote: Character?
        var escaped = false
        for ch in text {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }
            if let q = quote {
                if ch == q {
                    quote = nil
                } else if ch == "\\", q == "\"" {
                    escaped = true
                } else {
                    current.append(ch)
                }
                continue
            }
            if ch == "\\" {
                escaped = true; inToken = true
            } else if ch == "'" || ch == "\"" {
                quote = ch; inToken = true
            } else if ch.isWhitespace {
                if inToken { tokens.append(current); current = ""; inToken = false }
            } else {
                current.append(ch); inToken = true
            }
        }
        if quote != nil { return .failure(.unterminatedQuote) }
        if escaped { current.append("\\") }
        if inToken { tokens.append(current) }
        return .success(tokens)
    }

    /// Single words that run arbitrary code (THREAT-MODEL 4.7: "never for a
    /// shell or interpreter prefix").
    public static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "ksh", "env", "sudo", "python", "python3", "node", "deno", "bun",
        "ruby", "perl", "php", "npx", "npm", "yarn", "pnpm",
    ]

    /// A one-token command that is a shell or interpreter. `/bin/bash` counts.
    public static func isInterpreterPrefix(_ argv: [String]) -> Bool {
        guard argv.count == 1, let first = argv.first else { return false }
        let base = first.split(separator: "/").last.map(String.init) ?? first
        return interpreters.contains(base)
    }
}

/// `realpath(3)`: the path the daemon will see. `URL.resolvingSymlinksInPath`
/// turns `/private/tmp/x` back into `/tmp/x` and so disagrees with the daemon.
public enum RealPath {
    public static func resolve(_ path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        var buffer = [Int8](repeating: 0, count: Int(PATH_MAX) + 1)
        guard realpath(path, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }

    public static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}

/// Splits the "Pattern…" field: commas, spaces and newlines separate, except
/// commas inside `{…}` (a glob alternation).
public enum SecretPatterns {
    public static func split(_ text: String) -> [String] {
        var out = [String]()
        var current = ""
        var depth = 0
        for ch in text {
            if ch == "{" { depth += 1 }
            if ch == "}" { depth = max(0, depth - 1) }
            if (ch == "," && depth == 0) || ch.isWhitespace {
                if !current.isEmpty { out.append(current); current = "" }
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { out.append(current) }
        return out
    }

    /// A problem with one entry (name or glob), or nil. The daemon validates
    /// the glob syntax itself (`malformed glob`).
    public static func issue(_ entry: String) -> String? {
        let bytes = Array(entry.utf8)
        if bytes.isEmpty { return "A secret name can't be empty." }
        if bytes.count > Limits.nameBytes { return "\"\(DisplayText.sanitise(entry, limit: 24))\" is too long (256 characters max)." }
        var depth = 0
        for b in bytes {
            if b == 0x7B { depth += 1 }
            if b == 0x7D { depth = max(0, depth - 1) }
            // A comma is the separator of a glob alternation inside braces.
            if allowed(b) || (b == 0x2C && depth > 0) { continue }
            return "\"\(DisplayText.sanitise(entry, limit: 24))\": use letters, numbers, _ . - / and the glob characters * ? [ ] { } only."
        }
        return nil
    }

    private static func allowed(_ b: UInt8) -> Bool {
        (b >= 0x61 && b <= 0x7A) || (b >= 0x41 && b <= 0x5A) || (b >= 0x30 && b <= 0x39)
            || b == 0x5F || b == 0x2F || b == 0x2E || b == 0x2D
            || b == 0x2A || b == 0x3F || b == 0x5B || b == 0x5D || b == 0x7B || b == 0x7D
    }

    public static func isGlob(_ entry: String) -> Bool {
        entry.contains { "*?[]{}".contains($0) }
    }
}

/// The "New standing grant" form (docs/UI-SPEC.md 3.3).
///
/// **The confirmation is the daemon's.** `submit()` sends exactly one `grants
/// add`; the daemon then validates, applies the folder's policy, shows its own
/// "Create a standing grant?" dialog and, after the person chose "Create
/// standing grant", the Touch ID sheet. Nothing is stored before both
/// succeed. This model never retries, never sends a second `add` while one is
/// pending, and has no way to approve anything itself. `cancel()` cancels the
/// request, which closes the connection and makes the daemon withdraw its
/// dialog.
@Observable
@MainActor
public final class StandingGrantFormModel: Identifiable {
    public enum Phase: Equatable, Sendable {
        case editing
        /// The request is open: the daemon waits for the human.
        case waiting
        /// Created; the message is the toast text.
        case created(String)
    }

    public nonisolated let id = UUID()

    // fields
    public var forCaller = StandingGrantFormModel.defaultCaller
    public private(set) var knownCallers: [String] = [StandingGrantFormModel.defaultCaller]
    public private(set) var folder: String?
    public private(set) var availableSecrets: [String] = []
    public var selectedSecrets: Set<String> = []
    public var patternsText = ""
    public var commandText = ""
    public var ttl: StandingTTL
    public var customTTL = ""
    public var usesText = ""
    public var understood = false

    // state
    public private(set) var phase: Phase = .editing
    public var error: UserMessage?
    public private(set) var isLoadingChoices = false
    public private(set) var choicesFailed = false

    public static let defaultCaller = "claude-code"
    /// The text shown while the daemon waits.
    public static let waitingText = "Waiting for you to confirm in the grantd dialog, then Touch ID."
    public static let explanation =
        "grantd shows its own dialog next, then Touch ID. Nothing is created unless you approve both."
    public static let callerHelp =
        "Use the name the tool reports. For Claude Code this is claude-code. It is a label, not proof of who is asking."
    public static let commandHelp = "php artisan also covers php artisan migrate."
    public static let globHelp = "A pattern also covers matching secrets you add later."

    @ObservationIgnored private let service: GrantsService
    @ObservationIgnored private let resolvePath: (String) -> String?
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var task: Task<Void, Never>?

    public init(service: GrantsService, initialFolder: String? = nil, initialTTL: StandingTTL = .days30,
                resolvePath: @escaping (String) -> String? = RealPath.resolve, now: @escaping () -> Date = Date.init) {
        self.service = service
        self.resolvePath = resolvePath
        self.now = now
        self.ttl = initialTTL
        if let initialFolder { self.folder = initialFolder }
    }

    // MARK: choices

    /// Loads the secrets for the checklist and the callers seen in the audit
    /// log. A failure leaves the lists empty; the form still works with typed
    /// patterns.
    public func loadChoices() async {
        isLoadingChoices = true
        defer { isLoadingChoices = false }
        do {
            availableSecrets = try await service.listSecrets().map(\.name)
            choicesFailed = false
        } catch {
            if error is CancellationError { return }
            choicesFailed = true
        }
        if let audit = try? await service.listAudit(limit: 500) {
            knownCallers = Self.callers(from: audit.entries)
        }
    }

    /// `claude-code` first, then the other labels seen (newest first, up to 12),
    /// without the app's own and the daemon's placeholders.
    public static func callers(from entries: [AuditEntry]) -> [String] {
        var seen = Set([defaultCaller])
        var out = [defaultCaller]
        for e in entries {
            let c = e.caller
            if ["grantd-app", "cli", "(none)", "(invalid)", "mcp", ""].contains(c) { continue }
            if callerIssue(c) != nil { continue }
            if seen.insert(c).inserted { out.append(c) }
            if out.count >= 12 { break }
        }
        return out
    }

    public func chooseFolder(_ path: String) {
        folder = path
        error = nil
    }

    // MARK: validation

    public static func callerIssue(_ caller: String) -> String? {
        let t = caller.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return "Enter who this grant is for." }
        if t.utf8.count > 64 { return "Too long (64 characters max)." }
        for s in t.unicodeScalars {
            if s == " " { continue }
            switch s.properties.generalCategory {
            case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter,
                 .nonspacingMark, .spacingMark, .enclosingMark, .decimalNumber, .letterNumber, .otherNumber,
                 .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation, .initialPunctuation,
                 .finalPunctuation, .otherPunctuation, .mathSymbol, .currencySymbol, .modifierSymbol, .otherSymbol:
                continue
            default:
                return "Use printable characters only."
            }
        }
        return nil
    }

    public var callerMessage: String? { Self.callerIssue(forCaller) }
    public var trimmedCaller: String { forCaller.trimmingCharacters(in: .whitespaces) }

    public var folderResolved: String? {
        guard let folder else { return nil }
        return resolvePath(folder)
    }

    public var folderMessage: String? {
        guard let folder else { return "Choose the folder this grant covers." }
        guard folder.hasPrefix("/") else { return "The folder must be an absolute path." }
        guard let real = resolvePath(folder), RealPath.isDirectory(real) else { return "That folder doesn't exist." }
        return nil
    }

    /// The names ticked in the checklist (in list order) followed by the typed
    /// patterns, without duplicates.
    public var secretEntries: [String] {
        var out = availableSecrets.filter { selectedSecrets.contains($0) }
        // A ticked name that vanished from the list is still sent: the daemon decides.
        out += selectedSecrets.subtracting(availableSecrets).sorted()
        for p in SecretPatterns.split(patternsText) where !out.contains(p) { out.append(p) }
        return out
    }

    public var secretsMessage: String? {
        let entries = secretEntries
        if entries.isEmpty { return "Choose at least one secret, or type a pattern such as aws/*." }
        if entries.count > 256 { return "Too many secrets (256 max)." }
        for e in entries { if let i = SecretPatterns.issue(e) { return i } }
        return nil
    }

    public var hasGlob: Bool { secretEntries.contains(where: SecretPatterns.isGlob) }

    public var commandTokens: [String] {
        if case .success(let t) = CommandTokenizer.tokenize(commandText) { return t }
        return []
    }

    public var commandMessage: String? {
        switch CommandTokenizer.tokenize(commandText) {
        case .failure: return "Close the quote."
        case .success(let t):
            if t.isEmpty { return "Enter the command this grant allows, such as php artisan." }
            if t.contains("") { return "The command can't contain an empty part." }
            if t.count > 4096 { return "Too many parts (4,096 max)." }
            if t.reduce(0, { $0 + $1.utf8.count }) > 256 << 10 { return "The command is too long." }
            if t.contains(where: { $0.unicodeScalars.contains { $0.value < 0x20 && $0 != "\t" && $0 != "\n" && $0 != "\r" } }) {
                return "The command can't contain control characters."
            }
            return nil
        }
    }

    /// A shell or interpreter on its own lets the caller run anything.
    public var isRisky: Bool { CommandTokenizer.isInterpreterPrefix(commandTokens) }

    public var riskText: String { "This lets \(DisplayText.sanitise(trimmedCaller, limit: 64)) run any code with these secrets" }

    public var ttlSeconds: Int? {
        if let s = ttl.seconds { return s }
        if case .success(let n) = StandingTTL.parseCustom(customTTL) { return n }
        return nil
    }

    public var ttlMessage: String? {
        guard ttl == .custom else { return nil }
        if case .failure(let i) = StandingTTL.parseCustom(customTTL) { return i.message }
        return nil
    }

    public var uses: Int? {
        let t = usesText.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? nil : Int(t)
    }

    public var usesMessage: String? {
        let t = usesText.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        guard t.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let n = Int(t) else { return "Enter a whole number, or leave it empty." }
        return n >= 1 ? nil : "At least 1."
    }

    public var isValid: Bool {
        callerMessage == nil && folderMessage == nil && secretsMessage == nil && commandMessage == nil
            && ttlSeconds != nil && ttlMessage == nil && usesMessage == nil && (!isRisky || understood)
    }

    public var isWaiting: Bool { phase == .waiting }
    public var canSubmit: Bool { phase == .editing && isValid }

    /// The sentence under the form: what the grant will allow, in plain words.
    public var summary: String {
        let who = DisplayText.sanitise(trimmedCaller.isEmpty ? "…" : trimmedCaller, limit: 64)
        let cmd = DisplayText.sanitise(commandTokens.joined(separator: " "), limit: 120)
        let secrets = DisplayText.sanitise(secretEntries.joined(separator: ", "), limit: 160)
        let place = DisplayText.sanitise(folderResolved ?? folder ?? "…", limit: 160)
        let duration = ttlSeconds.map(StandingTTL.durationText(seconds:)) ?? "…"
        var text = "\(who) will be able to run \"\(cmd.isEmpty ? "…" : cmd) …\" with \(secrets.isEmpty ? "…" : secrets) in \(place) and its subfolders for \(duration), without asking you again."
        if let n = uses, usesMessage == nil { text += " It stops after \(n) \(n == 1 ? "run" : "runs")." }
        return text
    }

    // MARK: submit

    /// The request as it would be sent now, nil while the form is invalid.
    public func request() -> StandingGrantRequest? {
        guard isValid, let ttl = ttlSeconds, let cwd = folder else { return nil }
        return StandingGrantRequest(forCaller: trimmedCaller, cwd: cwd, secrets: secretEntries, argv: commandTokens,
                                    ttlSeconds: ttl, uses: uses)
    }

    /// Starts the one `grants add` request and returns at once; see `cancel()`.
    /// Does nothing while a request is pending.
    @discardableResult
    public func start() -> Task<Void, Never>? {
        guard canSubmit, task == nil else { return task }
        // Waiting starts now, not when the task first runs: a second click in
        // between must find the form busy.
        error = nil
        phase = .waiting
        let t = Task { await self.run() }
        task = t
        return t
    }

    /// Sends the request and waits for the human's answer.
    public func submit() async {
        guard let t = start() else { return }
        await t.value
    }

    /// Cancels the pending request: the connection closes and the daemon
    /// withdraws its dialog. Nothing is created.
    public func cancel() {
        task?.cancel()
    }

    private func run() async {
        defer { task = nil }
        guard let req = request() else { phase = .editing; return }
        do {
            let g = try await service.addStandingGrant(req)
            phase = .created(Self.createdMessage(g, now: now()))
        } catch is CancellationError {
            phase = .editing
        } catch {
            phase = .editing
            self.error = Self.message(for: error)
        }
    }

    /// `Standing grant created. {caller} can run "{command}" with {secrets} in
    /// {folder} until {date, time}.`
    public static func createdMessage(_ g: GrantInfo, now: Date = Date()) -> String {
        let caller = DisplayText.sanitise(g.caller, limit: 64)
        let cmd = DisplayText.argvLine(g.cmdPrefix, limit: 120)
        let secrets = DisplayText.sanitise(g.secrets.joined(separator: ", "), limit: 160)
        let folder = DisplayText.sanitise(g.cwdPrefix, limit: 160)
        let until = g.expiresAt.formatted(date: .abbreviated, time: .shortened)
        return "Standing grant created. \(caller) can run \"\(cmd)\" with \(secrets) in \(folder) until \(until)."
    }

    /// The outcomes of `grants add` (docs/UI-SPEC.md 3.3), worded for the form.
    public static func message(for error: Error) -> UserMessage {
        guard let e = error as? GrantdError, case .daemon(_, let reason, let raw) = e else {
            return UserMessage.from(error)
        }
        let detail = raw.isEmpty ? nil : DisplayText.sanitise(raw)
        switch reason {
        case .userDenied:
            return UserMessage("Not created. You cancelled the confirmation.", severity: .info)
        case .policyRefused:
            return UserMessage("A .grantd.yml in that folder does not allow this:", detail: detail)
        case .secretNotFound:
            var m = UserMessage.from(e)
            m.headline = "One of those secrets doesn't exist."
            m.detail = detail
            return m
        case .badRequest:
            // The message names the lifetime ceiling and where it comes from.
            return UserMessage(detail ?? "grantd rejected the request.")
        default:
            return UserMessage.from(e)
        }
    }
}
