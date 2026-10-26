import Foundation
import Observation

/// What the Activity window needs from the daemon.
public protocol ActivityService: Sendable {
    func listAudit(limit: Int?) async throws -> AuditList
    func verifyAudit() async throws -> AuditVerifyResult
    func exportAudit() async throws -> String
}

extension Client: ActivityService {}

/// The filter control of the Activity window (docs/UI-SPEC.md 3.4).
public enum ActivityFilter: String, CaseIterable, Hashable, Sendable {
    case all, runs, denied, changes

    public var title: String {
        switch self {
        case .all: return "All"
        case .runs: return "Runs"
        case .denied: return "Denied or blocked"
        case .changes: return "Changes"
        }
    }

    public func matches(_ e: AuditEvent) -> Bool {
        switch self {
        case .all: return true
        case .runs: return e.kind == .run || e.kind == .resultOnly
        case .denied: return e.kind == .refused
        case .changes: return e.kind == .change || e.kind == .standingGrant
        }
    }
}

/// How a row is drawn: a run that worked, a run that did not, a denial by the
/// person, a block by a rule, a daemon error, or a plain record.
public enum ActivityTone: Equatable, Sendable {
    case neutral
    case succeeded
    case failed
    /// You said no.
    case denied
    /// Blocked by `.grantpin.yml` or a protection level.
    case blocked
    case error
}

extension AuditEvent {
    public var tone: ActivityTone {
        switch decision {
        case "denied_user": return .denied
        case "refused_policy", "refused_tier": return .blocked
        case "error": return .error
        default: break
        }
        switch result {
        case .finished(let code, _): return code == 0 ? .succeeded : .failed
        case .noResultRecorded: return .failed
        default: return .neutral
        }
    }

    /// The Result column: `Exit 0 · 1.2 s`, `Running…`, `No result recorded`,
    /// `…`, or the refusal's name; empty for a plain record.
    public var resultText: String {
        switch result {
        case .finished(let code, let ms):
            let d = AuditPairing.duration(milliseconds: ms)
            if let code { return "Exit \(code) · \(d)" }
            return d
        case .running: return "Running…"
        case .noResultRecorded: return "No result recorded"
        case .outsideWindow: return "…"
        case .none:
            switch decision {
            case "denied_user": return "Denied"
            case "refused_policy", "refused_tier": return "Blocked"
            case "error": return reason.isEmpty ? "Error" : reason
            default: return ""
            }
        }
    }
}

/// The detail pane of one event (docs/UI-SPEC.md 3.4). Strings are sanitised.
public struct ActivityDetail: Equatable, Sendable {
    public var title: String
    public var time: Date
    public var caller: String
    /// The full command, one monospaced string (8 KB at most), or empty.
    public var command: String
    public var cwd: String
    public var secretsRequested: String
    /// The concrete names the request expanded to, when the row carries them.
    public var secretsExpanded: String?
    public var grantID: String
    public var result: String
    public var reason: String
    public var rowIDs: [String]
}

/// The state of the Activity window (docs/UI-SPEC.md 3.4): the paired events,
/// filter and search, "Load more", Verify Log and Export CSV.
@Observable
@MainActor
public final class ActivityViewModel {
    public enum VerifyState: Equatable, Sendable {
        case idle
        case running
        case ok(entries: Int)
        case broken(firstBadID: String)
        case failed(UserMessage)
    }

    public enum ExportOutcome: Equatable, Sendable {
        /// The CSV text exactly as received, and the file name to suggest.
        case csv(String, fileName: String)
        case failed(UserMessage)
    }

    public static let pageSize = 200
    public static let maximum = 1000

    public private(set) var entries: [AuditEntry] = []
    /// The `limit` the current rows were asked for.
    public private(set) var loadedLimit = ActivityViewModel.pageSize
    public private(set) var truncated = false
    public private(set) var hasLoaded = false
    public private(set) var isLoading = false
    public var filter: ActivityFilter = .all
    public var searchText = ""
    public var selection: String?
    public var banner: UserMessage?
    public private(set) var verify: VerifyState = .idle
    public private(set) var isExporting = false
    public private(set) var connection: ConnectionState?

    @ObservationIgnored private let service: ActivityService
    @ObservationIgnored private let now: () -> Date

    public init(service: ActivityService, now: @escaping () -> Date = Date.init) {
        self.service = service
        self.now = now
    }

    // MARK: connection

    public func connectionChanged(_ state: ConnectionState?) {
        let wasEnabled = isEnabled
        connection = state
        if isEnabled, !wasEnabled { Task { await refresh() } }
    }

    public var isEnabled: Bool {
        if case .ready = connection { return true }
        return false
    }

    public var disabledReason: String? {
        switch connection {
        case .ready?: return nil
        case nil: return "Checking grantpin…"
        case .notRunning?: return "grantpin is not running. Start it from the menu bar item."
        case .locked?: return "Unlock your Mac to read the log."
        case .notInitialized?: return "There is no vault yet. Create one from the menu bar item."
        }
    }

    // MARK: rows

    /// The log was loaded to its start: fewer rows came back than were asked
    /// for, and the page was not cut to fit a protocol line.
    public var windowIsComplete: Bool { !truncated && entries.count < loadedLimit }

    /// All paired events, newest first. Paired once per load, not on every
    /// read: a render reads this several times and up to 1,000 rows are loaded.
    public private(set) var events: [AuditEvent] = []

    public var visibleEvents: [AuditEvent] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        return events.filter { e in
            guard filter.matches(e) else { return false }
            if q.isEmpty { return true }
            return e.title.localizedCaseInsensitiveContains(q) || e.command.localizedCaseInsensitiveContains(q)
                || e.caller.localizedCaseInsensitiveContains(q)
                || e.secrets.contains { $0.localizedCaseInsensitiveContains(q) }
                || e.resultText.localizedCaseInsensitiveContains(q)
        }
    }

    public var isEmpty: Bool { hasLoaded && entries.isEmpty }

    /// "Load more" can fetch older rows: the log has more and the page is not
    /// already cut to one protocol line.
    public var canLoadMore: Bool {
        hasLoaded && !truncated && entries.count >= loadedLimit && loadedLimit < Self.maximum
    }

    /// The footer under the table, or nil.
    public var footer: String? {
        guard hasLoaded else { return nil }
        if truncated {
            return "Some older entries did not fit in one page. Export CSV to read them all."
        }
        if entries.count >= loadedLimit && loadedLimit >= Self.maximum {
            return "Older entries are only in the CSV export."
        }
        return nil
    }

    public func detail(for id: String) -> ActivityDetail? {
        guard let event = events.first(where: { $0.id == id }) else { return nil }
        let rows = entries.filter { event.rowIDs.contains($0.id) }.sorted { $0.ts < $1.ts }
        guard let first = rows.first else { return nil }
        let argvText = DisplayText.sanitise(first.argv.joined(separator: " "), limit: DisplayText.detailLimit, allowNewlines: true)
        let expanded = rows.compactMap(\.expanded).first(where: { !$0.isEmpty })
        return ActivityDetail(
            title: event.title, time: event.time, caller: DisplayText.sanitise(first.caller),
            command: argvText, cwd: DisplayText.sanitise(first.cwd, limit: DisplayText.detailLimit),
            secretsRequested: DisplayText.sanitise(first.secrets.joined(separator: ", "), limit: DisplayText.detailLimit),
            secretsExpanded: expanded.map { DisplayText.sanitise($0.joined(separator: ", "), limit: DisplayText.detailLimit) },
            grantID: DisplayText.sanitise(rows.map(\.grantID).first(where: { !$0.isEmpty }) ?? ""),
            result: event.resultText, reason: event.reason, rowIDs: rows.map(\.id))
    }

    // MARK: loading

    /// Reloads as many rows as are loaded now (at least one page).
    public func refresh() async {
        await load(limit: loadedLimit)
    }

    /// Asks for 200 more rows (1,000 at most).
    public func loadMore() async {
        guard canLoadMore else { return }
        await load(limit: min(loadedLimit + Self.pageSize, Self.maximum))
    }

    private func load(limit: Int) async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let list = try await service.listAudit(limit: limit)
            entries = list.entries
            truncated = list.truncated
            loadedLimit = limit
            hasLoaded = true
            events = AuditPairing.pair(entries, windowIsComplete: windowIsComplete, now: now())
            if let id = selection, !events.contains(where: { $0.id == id }) { selection = nil }
            if banner?.refreshAdvised == true || bannerIsFromLoad { banner = nil; bannerIsFromLoad = false }
        } catch {
            if let e = error as? GrantpinError, e.isNotRunning || e.isVaultLocked || e.isVaultNotInitialized { return }
            if error is CancellationError { return }
            banner = UserMessage.from(error)
            bannerIsFromLoad = true
        }
    }

    @ObservationIgnored private var bannerIsFromLoad = false

    // MARK: verify

    public static func verifiedText(entries: Int) -> String {
        "Log verified: \(entries) \(entries == 1 ? "entry" : "entries"), chain intact."
    }
    public static let verifiedCaption =
        "This detects edits and removals in the middle of the log. It cannot detect the newest entries being deleted."
    public static func brokenText(firstBadID: String) -> String {
        "Log check failed at entry \(DisplayText.sanitise(firstBadID, limit: 40)). Entries from there on can't be trusted. "
            + "Someone may have edited the vault file. Export a copy now."
    }

    public func verifyLog() async {
        guard verify != .running else { return }
        verify = .running
        do {
            let r = try await service.verifyAudit()
            if r.ok {
                verify = .ok(entries: r.entries)
            } else {
                verify = .broken(firstBadID: r.firstBadID ?? "?")
            }
        } catch {
            verify = .failed(UserMessage.from(error))
        }
    }

    public func dismissVerify() { verify = .idle }

    // MARK: export

    public static let tooLargeText = "The log is over 1 MB and can't be exported in one piece yet. Use Load more and copy what you need."
    public static let exportPanelMessage = "Cells contain text chosen by other programs. Open this file in a text editor if you are not sure."

    /// `grantpin-audit-2026-10-25.csv`.
    public static func exportFileName(date: Date, calendar: Calendar = .current) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "grantpin-audit-%04d-%02d-%02d.csv", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    /// Asks the daemon for the CSV. The text is returned exactly as received;
    /// the view writes it to the file the person chooses.
    public func exportCSV() async -> ExportOutcome {
        isExporting = true
        defer { isExporting = false }
        do {
            let csv = try await service.exportAudit()
            return .csv(csv, fileName: Self.exportFileName(date: now()))
        } catch {
            if let e = error as? GrantpinError, e.reason == .responseTooLarge {
                return .failed(UserMessage(Self.tooLargeText))
            }
            return .failed(UserMessage.from(error))
        }
    }
}
