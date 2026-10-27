import Foundation
import Observation

/// The state of the Secrets window (docs/UI-SPEC.md 3.2): the list, search,
/// sort, selection, the "last 4 characters" check, deletion and the banner.
///
/// Every mutation ends with a refresh from the daemon; nothing is edited
/// optimistically. While the daemon is down, locked or has no vault, the model
/// is `isEnabled == false` and the window disables its controls instead of
/// showing errors for each of them.
@Observable
@MainActor
public final class SecretsViewModel {
    public enum EmptyState: Equatable, Sendable {
        /// There are rows to show.
        case none
        /// The vault holds no secrets: "No secrets yet. Add one, or import a .env file."
        case noSecrets
        /// The search matches nothing.
        case noMatches
    }

    public enum MaskedState: Equatable, Sendable {
        case idle
        case loading
        case value(String)
        case failed(UserMessage)
    }

    public private(set) var secrets: [SecretInfo] = []
    public private(set) var grants: [GrantInfo] = []
    public var searchText = ""
    public var sortAscending = true
    public var selection: Set<String> = []
    public private(set) var hasLoaded = false
    public private(set) var isLoading = false
    public var banner: UserMessage?
    public private(set) var connection: ConnectionState?
    public private(set) var masked: MaskedState = .idle
    @ObservationIgnored private var maskedFor: String?
    /// The banner says the list could not be loaded; a good load clears it.
    @ObservationIgnored private var bannerIsFromLoad = false
    @ObservationIgnored private let loads = LoadCoalescer()

    @ObservationIgnored private let service: SecretsService
    @ObservationIgnored private let pasteboard: PasteboardAccess?
    @ObservationIgnored private let now: () -> Date

    public init(service: SecretsService, pasteboard: PasteboardAccess? = nil, now: @escaping () -> Date = Date.init) {
        self.service = service
        self.pasteboard = pasteboard
        self.now = now
    }

    // MARK: connection

    /// Called with the monitor's state. Reloads when the daemon becomes usable.
    public func connectionChanged(_ state: ConnectionState?) {
        let wasEnabled = isEnabled
        connection = state
        if isEnabled, !wasEnabled { Task { await refresh() } }
    }

    public var isEnabled: Bool {
        if case .ready = connection { return true }
        return false
    }

    /// Why the controls are disabled, nil when they are not.
    public var disabledReason: String? {
        switch connection {
        case .ready?: return nil
        case nil: return "Checking grantpin…"
        case .notRunning?: return "grantpin is not running. Start it from the menu bar item."
        case .locked?: return "Unlock your Mac to use secrets."
        case .notInitialized?: return "There is no vault yet. Create one from the menu bar item."
        }
    }

    public var keystoreTier: Tier {
        if case .ready(let s)? = connection { return s.keystoreTier }
        return .vaultDefault
    }

    // MARK: the list

    public var visibleSecrets: [SecretInfo] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        let filtered = q.isEmpty ? secrets : secrets.filter { s in
            s.name.localizedCaseInsensitiveContains(q) || s.tags.contains { $0.localizedCaseInsensitiveContains(q) }
        }
        return filtered.sorted {
            let order = $0.name.localizedStandardCompare($1.name)
            return sortAscending ? order == .orderedAscending : order == .orderedDescending
        }
    }

    public var emptyState: EmptyState {
        if !visibleSecrets.isEmpty { return .none }
        if secrets.isEmpty { return hasLoaded ? .noSecrets : .none }
        return .noMatches
    }

    public var selectedSecrets: [SecretInfo] {
        secrets.filter { selection.contains($0.name) }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The one selected secret, for the detail pane.
    public var detailSecret: SecretInfo? {
        let s = selectedSecrets
        return s.count == 1 ? s[0] : nil
    }

    public func secret(named name: String) -> SecretInfo? { secrets.first { $0.name == name } }

    /// Loads the list. A failure while the daemon is not usable is left to the
    /// disabled state; any other failure becomes the banner.
    /// When a load is already in flight, this waits for it and for one more
    /// pass, so `hasLoaded` and `secrets` are current when it returns.
    public func refresh() async {
        await loads.run { await loadOnce() }
    }

    private func loadOnce() async {
        isLoading = true
        defer { isLoading = false }
        do {
            let list = try await service.listSecrets()
            secrets = list
            hasLoaded = true
            let names = Set(list.map(\.name))
            selection = selection.intersection(names)
            if maskedFor.map({ !names.contains($0) }) == true { resetMasked() }
            if banner?.refreshAdvised == true || bannerIsFromLoad { banner = nil; bannerIsFromLoad = false }
        } catch {
            handleLoadFailure(error)
        }
    }

    private func handleLoadFailure(_ error: Error) {
        if let e = error as? GrantpinError, e.isNotRunning || e.isVaultLocked || e.isVaultNotInitialized { return }
        if error is CancellationError { return }
        banner = UserMessage.from(error)
        bannerIsFromLoad = true
    }

    // MARK: last 4 characters

    /// Asks the daemon for the masked value of the selected secret
    /// (`masked`: `****` plus the last four characters, or `********`).
    public func checkLastCharacters(of name: String) async {
        maskedFor = name
        masked = .loading
        do {
            let text = try await service.masked(name)
            guard maskedFor == name else { return }
            masked = .value(text)
        } catch {
            guard maskedFor == name else { return }
            masked = .failed(UserMessage.from(error))
        }
    }

    public func resetMasked() {
        maskedFor = nil
        masked = .idle
    }

    // MARK: sheets

    public func makeAddForm() -> SecretFormModel {
        SecretFormModel(service: service, existingNames: Set(secrets.map(\.name)), keystoreTier: keystoreTier,
                        pasteboard: pasteboard, now: now)
    }

    public func makeEditForm(for secret: SecretInfo) -> SecretFormModel {
        SecretFormModel(service: service, original: secret, existingNames: Set(secrets.map(\.name)),
                        keystoreTier: keystoreTier, pasteboard: pasteboard, now: now)
    }

    /// After a sheet saved: reload and select the row.
    public func formDidSave(name: String) async {
        await refresh()
        if secrets.contains(where: { $0.name == name }) { selection = [name] }
        resetMasked()
    }

    // MARK: delete

    /// The confirmation for deleting `names`, with the number of active
    /// grants that mention exactly this one secret (single delete only). The
    /// grants are loaded fresh; if that fails the sentence is simply left out.
    public func deleteConfirmation(for names: [String]) async -> Confirmation {
        var mentioning = 0
        if names.count == 1 {
            if let loaded = try? await service.listGrants() { grants = loaded }
            mentioning = grants.filter { !$0.tampered && $0.secrets.contains(names[0]) }.count
        }
        return Confirmation.delete(names: names, grantsMentioning: mentioning)
    }

    /// Deletes the names one after another. If one fails the rest are not
    /// attempted and the banner says which were deleted.
    @discardableResult
    public func delete(names: [String]) async -> Bool {
        var deleted = [String]()
        var failure: Error?
        for name in names {
            do {
                try await service.delete(name)
                deleted.append(name)
            } catch {
                failure = error
                break
            }
        }
        await refresh()
        if let failure {
            var m = UserMessage.from(failure)
            if !deleted.isEmpty {
                let list = deleted.map { DisplayText.sanitise($0) }.joined(separator: ", ")
                m.detail = "Deleted before the problem: \(list)." + (m.detail.map { " " + $0 } ?? "")
            }
            banner = m
            return false
        }
        banner = nil
        selection.subtract(deleted)
        resetMasked()
        return true
    }
}
