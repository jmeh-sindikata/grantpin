import Foundation
import Observation

/// What the Grants window and the standing-grant form need from the daemon.
/// `Client` is the real one; tests use a fake.
public protocol GrantsService: Sendable {
    func listGrants() async throws -> [GrantInfo]
    func revokeGrant(id: String) async throws
    func revokeAllGrants() async throws
    /// Creates a standing grant. The daemon shows its own dialog and Touch ID
    /// and answers when the human has; this can take minutes.
    func addStandingGrant(_ grant: StandingGrantRequest) async throws -> GrantInfo
    /// The current secrets, for the form's checklist.
    func listSecrets() async throws -> [SecretInfo]
    /// The newest audit rows, for the callers seen so far.
    func listAudit(limit: Int?) async throws -> AuditList
}

extension Client: GrantsService {}

extension ExpiryFormatter {
    /// The time left in a grants list: `in 23 min`, `in 2 h 5 min`,
    /// `in 29 d 4 h`, `in <1 min`, `expired`.
    public static func timeLeft(_ date: Date, now: Date = Date()) -> String {
        let remaining = date.timeIntervalSince(now)
        if remaining <= 0 { return "expired" }
        let days = Int(remaining / 86_400)
        let hours = Int(remaining.truncatingRemainder(dividingBy: 86_400) / 3600)
        let minutes = Int(remaining.truncatingRemainder(dividingBy: 3600) / 60)
        if days >= 1 { return hours > 0 ? "in \(days) d \(hours) h" : "in \(days) d" }
        if hours >= 1 { return minutes > 0 ? "in \(hours) h \(minutes) min" : "in \(hours) h" }
        if minutes >= 1 { return "in \(minutes) min" }
        return "in <1 min"
    }
}

/// A badge on a row of the Grants list (docs/UI-SPEC.md 3.3).
public enum GrantBadge: Equatable, Hashable, Sendable {
    /// Blue: created on purpose, long-lived.
    case standing
    /// Orange: under 10 minutes left.
    case expiringSoon
    /// Gray: crossed its end between two refreshes; gone at the next poll.
    case expired
    /// Red: failed verification.
    case tampered

    public var title: String {
        switch self {
        case .standing: return "Standing"
        case .expiringSoon: return "Expiring soon"
        case .expired: return "Expired"
        case .tampered: return "Tampered"
        }
    }
}

/// One row of the Grants list, ready to show. For a tampered grant only the
/// id is real; the other fields of the daemon's row are untrusted and are
/// never copied here.
public struct GrantRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var tampered: Bool
    public var standing: Bool
    public var badges: [GrantBadge]
    public var caller: String
    public var folder: String
    public var secrets: String
    public var command: String
    public var kind: String
    public var expiresAt: Date?
    public var timeLeft: String
    public var usesLeft: String
    /// The text of a tampered row.
    public var tamperedNote: String?

    public static let tamperedText = "Failed verification. grantpin ignores it. Remove it."
    public static let soonThreshold: TimeInterval = 10 * 60

    public init(_ g: GrantInfo, now: Date) {
        id = g.id
        tampered = g.tampered
        if g.tampered {
            standing = false
            badges = [.tampered]
            caller = ""; folder = ""; secrets = ""; command = ""; kind = ""
            expiresAt = nil; timeLeft = ""; usesLeft = ""
            tamperedNote = Self.tamperedText
            return
        }
        standing = g.standing
        var b = [GrantBadge]()
        if g.standing { b.append(.standing) }
        let remaining = g.expiresAt.timeIntervalSince(now)
        if remaining <= 0 { b.append(.expired) } else if remaining < Self.soonThreshold { b.append(.expiringSoon) }
        badges = b
        caller = DisplayText.sanitise(g.caller)
        folder = DisplayText.sanitise(g.cwdPrefix)
        secrets = DisplayText.sanitise(g.secrets.joined(separator: ", "))
        command = DisplayText.argvLine(g.cmdPrefix, limit: DisplayText.cellLimit)
        kind = g.standing ? "Standing" : "Session"
        expiresAt = g.expiresAt
        timeLeft = ExpiryFormatter.timeLeft(g.expiresAt, now: now)
        usesLeft = g.usesRemaining.map { String($0) } ?? "No limit"
        tamperedNote = nil
    }
}

extension Confirmation {
    /// `Revoke this grant?`
    public static func revoke(_ g: GrantInfo) -> Confirmation {
        if g.tampered { return removeTampered }
        let caller = DisplayText.sanitise(g.caller, limit: 64)
        let secrets = DisplayText.sanitise(g.secrets.joined(separator: ", "), limit: 120)
        let folder = DisplayText.sanitise(g.cwdPrefix, limit: 120)
        return Confirmation(
            title: "Revoke this grant?",
            message: "\(caller) will have to ask you again before it can use \(secrets) in \(folder). A command that is already running keeps running.",
            confirmLabel: "Revoke")
    }

    /// `Remove this grant?`, for a row that failed verification.
    public static let removeTampered = Confirmation(
        title: "Remove this grant?",
        message: "grantpin could not verify this grant, so it is ignored and never allows anything. Removing it clears the warning.",
        confirmLabel: "Remove")

    /// `Revoke all {n} grants?`
    public static func revokeAll(count: Int) -> Confirmation {
        Confirmation(
            title: count == 1 ? "Revoke 1 grant?" : "Revoke all \(count) grants?",
            message: "Every agent will have to ask you again, including for standing grants you created on purpose. Commands already running keep running.",
            confirmLabel: "Revoke All")
    }
}

/// The state of the Grants window (docs/UI-SPEC.md 3.3): the list, the
/// selection, revoke one and revoke all, and the standing-grant form.
@Observable
@MainActor
public final class GrantsViewModel {
    public private(set) var grants: [GrantInfo] = []
    public private(set) var hasLoaded = false
    public private(set) var isLoading = false
    public var selection: Set<String> = []
    public var banner: UserMessage?
    /// A one-line result, such as the toast after a standing grant was created.
    public var notice: String?
    public private(set) var connection: ConnectionState?
    /// A clock the rows are computed against; the window ticks it.
    public private(set) var now: Date

    @ObservationIgnored private let service: GrantsService
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private var bannerIsFromLoad = false
    @ObservationIgnored private let loads = LoadCoalescer()

    public init(service: GrantsService, now: @escaping () -> Date = Date.init) {
        self.service = service
        self.clock = now
        self.now = now()
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
        case .locked?: return "Unlock your Mac to use grants."
        case .notInitialized?: return "There is no vault yet. Create one from the menu bar item."
        }
    }

    // MARK: the list

    /// Re-computes the "time left" texts against the current time.
    public func tick() { now = clock() }

    /// Tampered rows first (they need attention), then by soonest end.
    public var rows: [GrantRow] {
        let sorted = grants.sorted { a, b in
            if a.tampered != b.tampered { return a.tampered }
            if a.tampered { return a.id < b.id }
            if a.expiresAt != b.expiresAt { return a.expiresAt < b.expiresAt }
            return a.id < b.id
        }
        return sorted.map { GrantRow($0, now: now) }
    }

    public var tamperedCount: Int { grants.filter(\.tampered).count }
    public var isEmpty: Bool { hasLoaded && grants.isEmpty }

    public func grant(id: String) -> GrantInfo? { grants.first { $0.id == id } }

    public var selectedGrants: [GrantInfo] {
        grants.filter { selection.contains($0.id) }
    }

    /// Loads the list. When a load is already in flight (the one
    /// `connectionChanged` starts), this waits for it and for one more pass,
    /// so `hasLoaded` and `grants` are current when it returns.
    public func refresh() async {
        await loads.run { await loadOnce() }
    }

    private func loadOnce() async {
        isLoading = true
        defer { isLoading = false }
        do {
            let list = try await service.listGrants()
            grants = list
            hasLoaded = true
            now = clock()
            selection = selection.intersection(Set(list.map(\.id)))
            if banner?.refreshAdvised == true || bannerIsFromLoad { banner = nil; bannerIsFromLoad = false }
        } catch {
            if let e = error as? GrantpinError, e.isNotRunning || e.isVaultLocked || e.isVaultNotInitialized { return }
            if error is CancellationError { return }
            banner = UserMessage.from(error)
            bannerIsFromLoad = true
        }
    }

    // MARK: revoke

    public func revokeConfirmation(for id: String) -> Confirmation? {
        grant(id: id).map(Confirmation.revoke)
    }

    public func revokeAllConfirmation() -> Confirmation? {
        grants.isEmpty ? nil : Confirmation.revokeAll(count: grants.count)
    }

    /// Revokes (or, for a tampered row, removes) one grant, then reloads.
    @discardableResult
    public func revoke(id: String) async -> Bool {
        do {
            try await service.revokeGrant(id: id)
            banner = nil
            await refresh()
            return true
        } catch {
            await refresh()
            banner = UserMessage.from(error)
            return false
        }
    }

    @discardableResult
    public func revokeAll() async -> Bool {
        do {
            try await service.revokeAllGrants()
            banner = nil
            selection = []
            await refresh()
            return true
        } catch {
            await refresh()
            banner = UserMessage.from(error)
            return false
        }
    }

    // MARK: the form

    public func makeStandingForm(initialFolder: String? = nil, initialTTL: StandingTTL = .days30) -> StandingGrantFormModel {
        StandingGrantFormModel(service: service, initialFolder: initialFolder, initialTTL: initialTTL, now: clock)
    }

    /// After the form created a grant: reload and say so.
    public func formDidCreate(_ message: String) async {
        notice = message
        await refresh()
    }
}
