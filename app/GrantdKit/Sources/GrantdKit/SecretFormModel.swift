import Foundation
import Observation

/// The system clipboard, as far as the sheet needs it. Reading happens once,
/// on an explicit Paste click; clearing happens only after a successful save
/// and only if nothing else was copied meanwhile (docs/UI-SPEC.md 3.2, 4.1).
public protocol PasteboardAccess {
    var changeCount: Int { get }
    func string() -> String?
    func clearContents()
}

extension Tier {
    /// none < dialog < hardware. A tier this build does not know ranks with dialog.
    public var rank: Int {
        switch rawValue {
        case "none": return 0
        case "hardware": return 2
        default: return 1
        }
    }
}

/// How the "Protection" picker reads.
public enum TierChoice: Hashable, Sendable, CaseIterable {
    case vaultDefault, dialog, hardware

    /// The tier to send, nil for the vault default (the field is omitted; the
    /// app never sends `none`).
    public var tier: Tier? {
        switch self {
        case .vaultDefault: return nil
        case .dialog: return .dialog
        case .hardware: return .hardware
        }
    }

    public init(_ tier: Tier) {
        switch tier.rank {
        case 2: self = .hardware
        case 1: self = .dialog
        default: self = .vaultDefault
        }
    }

    public var title: String {
        switch self {
        case .vaultDefault: return "Vault default"
        case .dialog: return "Dialog"
        case .hardware: return "Hardware"
        }
    }

    public var explanation: String {
        switch self {
        case .vaultDefault:
            return "Uses the protection this vault was created with."
        case .dialog:
            return "Every use needs your approval in a dialog."
        case .hardware:
            return "Every use needs your approval in a dialog and Touch ID, with the key in the Secure Enclave."
        }
    }
}

/// The expiry picker.
public enum ExpiryKind: Hashable, Sendable, CaseIterable {
    case never, days7, days30, days90, date, custom

    public var title: String {
        switch self {
        case .never: return "Never"
        case .days7: return "In 7 days"
        case .days30: return "In 30 days"
        case .days90: return "In 90 days"
        case .date: return "Pick a date…"
        case .custom: return "Custom…"
        }
    }
}

/// What the Add, Edit and Replace sheet edits.
///
/// One model for the three jobs of the sheet (docs/UI-SPEC.md 3.2): a new
/// secret (`.add`), a metadata edit of an existing one (`.editDetails`, the
/// `update` op, never touches the value) and a new value for an existing one
/// (`.replaceValue`, `set` with `overwrite`, which replaces the metadata too,
/// so the form keeps the current metadata prefilled).
///
/// The value lives in `value` only while the sheet is open. On a successful
/// save, on `discardSensitive()` and when the mode changes it is cleared; the
/// `Data` handed to the client is overwritten with zeros by the client. A
/// Swift `String` cannot be wiped; that limit is documented in UI-SPEC 4.1.
@Observable
@MainActor
public final class SecretFormModel {
    public enum Mode: Equatable, Sendable {
        case add, editDetails, replaceValue
    }

    /// The secret being edited; nil when adding.
    public let original: SecretInfo?
    public var mode: Mode {
        didSet { if mode != oldValue { value = ""; showCharacters = false; error = nil } }
    }

    public var name: String
    public var value = ""
    public var multiline = false
    public var showCharacters = false
    public var tagsText: String
    public var url: String
    public var notes: String
    public var expiryKind: ExpiryKind
    public var expiryDate: Date
    public var expiryCustom = ""
    public var tier: TierChoice
    /// "Clear the clipboard after saving"; only offered after a Paste click.
    public var clearClipboardAfterSaving = true

    public private(set) var isSaving = false
    public private(set) var error: UserMessage?
    public private(set) var savedName: String?
    public private(set) var pastedFromClipboard = false

    @ObservationIgnored private let service: SecretsService
    @ObservationIgnored private let pasteboard: PasteboardAccess?
    @ObservationIgnored private let existingNames: Set<String>
    @ObservationIgnored private let keystoreTier: Tier
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let calendar: Calendar
    @ObservationIgnored private var pastedChangeCount = 0

    /// - Parameters:
    ///   - original: the secret to edit, nil to add one.
    ///   - existingNames: the names in the loaded list (to offer Replace).
    ///   - keystoreTier: `status.keystore_tier`; Hardware is disabled unless it is `hardware`.
    public init(service: SecretsService, original: SecretInfo? = nil, existingNames: Set<String> = [],
                keystoreTier: Tier = .hardware, pasteboard: PasteboardAccess? = nil,
                now: @escaping () -> Date = Date.init, calendar: Calendar = .current) {
        self.service = service
        self.original = original
        self.existingNames = existingNames
        self.keystoreTier = keystoreTier
        self.pasteboard = pasteboard
        self.now = now
        self.calendar = calendar
        self.mode = original == nil ? .add : .editDetails
        self.name = original?.name ?? ""
        self.tagsText = original?.tags.joined(separator: ", ") ?? ""
        self.url = original?.url ?? ""
        self.notes = original?.notes ?? ""
        if let exp = original?.expiresAt {
            self.expiryKind = .date
            self.expiryDate = exp
        } else {
            self.expiryKind = .never
            self.expiryDate = calendar.date(byAdding: .day, value: 30, to: now()) ?? now()
        }
        self.tier = original.map { TierChoice($0.minTier) } ?? .vaultDefault
    }

    // MARK: derived state

    public var isAdding: Bool { mode == .add }
    public var needsValue: Bool { mode != .editDetails }
    public var nameIsEditable: Bool { mode == .add }

    public var nameIssue: NameIssue? { isAdding ? Validators.nameIssue(name) : nil }
    /// The name problem to show inline: none while the field is still empty.
    public var nameMessage: String? {
        guard isAdding, !name.isEmpty else { return nil }
        return nameIssue?.message
    }
    /// Adding under a name that already exists turns Save into Replace.
    public var nameExists: Bool { isAdding && nameIssue == nil && existingNames.contains(name) }
    public var replacesExisting: Bool { nameExists || mode == .replaceValue }

    public var tagParse: TagParse { Validators.parseTags(tagsText) }
    public var urlMessage: String? { Validators.urlIssue(url) }
    public var urlNote: String? { Validators.urlNote(url) }
    public var notesMessage: String? { Validators.notesIssue(notes) }

    public var valueIssue: ValueIssue? { needsValue ? Validators.valueIssue(value) : nil }
    public var valueMessage: String? {
        guard needsValue, !value.isEmpty else { return nil }
        return valueIssue?.message
    }
    public var valueCounter: String? { needsValue ? Validators.valueCounter(value) : nil }
    public var valueNote: String? { needsValue ? Validators.valueSpaceNote(value) : nil }

    public var expiryChoice: ExpiryChoice {
        switch expiryKind {
        case .never: return .never
        case .days7: return .inDays(7)
        case .days30: return .inDays(30)
        case .days90: return .inDays(90)
        case .date: return .date(expiryDate)
        case .custom: return .custom(expiryCustom)
        }
    }

    /// Why the chosen expiry cannot be used, nil if it can. In Edit details and
    /// Replace value an unchanged expiry is never a problem (an already
    /// expired secret can be edited, or get a new value, without touching the
    /// date).
    public var expiryMessage: String? {
        if mode != .add, !expiryChanged { return nil }
        do { _ = try expiryChoice.resolve(now: now(), calendar: calendar) } catch let e as ExpiryError {
            if expiryKind == .custom, expiryCustom.isEmpty { return nil }
            return e.message
        } catch { return nil }
        return nil
    }

    /// Hardware is offered only when the vault's key can satisfy it, or when
    /// the secret already has it.
    public func isAllowed(_ choice: TierChoice) -> Bool {
        if choice != .hardware { return true }
        if keystoreTier == .hardware { return true }
        return original.map { $0.minTier.rank == 2 } ?? false
    }

    public var hardwareDisabledHelp: String {
        "This vault's key is not in the Secure Enclave, so a hardware-only secret could never be released."
    }

    /// The protection level may be changed in Add and Edit details; Replace keeps it.
    public var tierIsEditable: Bool { mode != .replaceValue }

    /// Edit details: the chosen level is lower than the current one. The
    /// daemon then asks the human (dialog, then Touch ID) before changing it.
    public var tierIsLowering: Bool {
        guard mode == .editDetails, let original else { return false }
        return tierToSend(forUpdate: true) != nil && tier.tier!.rank < original.minTier.rank
    }

    public var lowerTierNote: String? { tierIsLowering ? Confirmation.lowerProtectionNote : nil }

    // MARK: what Save would send

    /// Edit details: the minimal `update`, nil fields untouched.
    public struct UpdatePlan: Equatable, Sendable {
        public var tags: [String]?
        public var url: String?
        public var notes: String?
        public var expires: Date?
        public var minTier: Tier?
        public var clear: Set<ClearField> = []

        public var isEmpty: Bool {
            tags == nil && url == nil && notes == nil && expires == nil && minTier == nil && clear.isEmpty
        }
    }

    private var expiryChanged: Bool {
        guard let original else { return true }
        switch (original.expiresAt, expiryKind) {
        case (nil, .never): return false
        case (nil, _): return true
        case (.some, .never): return true
        case (.some(let old), .date):
            return calendar.startOfDay(for: old) != calendar.startOfDay(for: expiryDate)
        case (.some, _): return true
        }
    }

    private func tierToSend(forUpdate: Bool) -> Tier? {
        guard let original else { return tier.tier }
        if forUpdate {
            // Only a real change is sent: `update` with a min_tier uses the
            // long timeout and may ask the human, so never send it otherwise.
            guard let t = tier.tier, t != original.minTier else { return nil }
            return t
        }
        // Replace: keep the level the secret has now.
        return original.minTier.rank == 0 ? nil : original.minTier
    }

    public func updatePlan() throws -> UpdatePlan {
        guard let original else { return UpdatePlan() }
        var plan = UpdatePlan()
        let tags = tagParse.tags
        if Set(tags) != Set(original.tags) {
            if tags.isEmpty { plan.clear.insert(.tags) } else { plan.tags = tags }
        }
        let newURL = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if newURL != original.url {
            if newURL.isEmpty { plan.clear.insert(.url) } else { plan.url = newURL }
        }
        if notes != original.notes {
            if notes.isEmpty { plan.clear.insert(.notes) } else { plan.notes = notes }
        }
        if expiryChanged {
            if let date = try expiryChoice.resolve(now: now(), calendar: calendar) {
                plan.expires = date
            } else {
                plan.clear.insert(.expires)
            }
        }
        plan.minTier = tierToSend(forUpdate: true)
        return plan
    }

    // MARK: saving

    public var hasValidFields: Bool {
        guard tagParse.isValid, urlMessage == nil, notesMessage == nil, expiryMessage == nil, isAllowed(tier) else { return false }
        // "Custom…" with nothing typed yet is not an expiry.
        if expiryKind == .custom, expiryCustom.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    public var canSave: Bool {
        guard !isSaving, hasValidFields else { return false }
        switch mode {
        case .add: return nameIssue == nil && valueIssue == nil
        case .replaceValue: return valueIssue == nil
        case .editDetails: return ((try? updatePlan())?.isEmpty == false)
        }
    }

    public var saveTitle: String {
        switch mode {
        case .add: return nameExists ? "Replace…" : "Save"
        case .replaceValue: return "Replace…"
        case .editDetails: return "Save"
        }
    }

    /// The confirmation to show before `save()` when it overwrites a value.
    public var replaceConfirmation: Confirmation? {
        replacesExisting ? Confirmation.replace(name: original?.name ?? name) : nil
    }

    /// Sends the request. On success the value is cleared and `savedName` is
    /// set; on failure the sheet stays as it is and `error` says why.
    /// - Returns: true if the daemon accepted it.
    @discardableResult
    public func save() async -> Bool {
        guard canSave else { return false }
        isSaving = true
        error = nil
        defer { isSaving = false }
        do {
            switch mode {
            case .add, .replaceValue:
                try await saveValue()
            case .editDetails:
                try await saveDetails()
            }
        } catch {
            self.error = UserMessage.from(error)
            return false
        }
        savedName = original?.name ?? name
        clearClipboardAfterSave()
        discardSensitive()
        return true
    }

    private func saveValue() async throws {
        var data = Data(Validators.normalisedValue(value).utf8)
        defer { data.resetBytes(in: 0..<data.count) }
        // Replace value with the expiry untouched sends the stored instant as it
        // is: resolving the prefilled date would move it to the end of its day.
        let expires: Date?
        if mode == .replaceValue, !expiryChanged { expires = original?.expiresAt } else {
            expires = try expiryChoice.resolve(now: now(), calendar: calendar)
        }
        let target = original?.name ?? name
        let notesValue = notes.isEmpty ? nil : notes
        let urlValue = url.trimmingCharacters(in: .whitespacesAndNewlines)
        try await service.set(
            name: target, value: &data, tags: tagParse.tags, url: urlValue.isEmpty ? nil : urlValue,
            notes: notesValue, expires: expires, minTier: tierToSend(forUpdate: false),
            overwrite: replacesExisting)
    }

    private func saveDetails() async throws {
        let plan = try updatePlan()
        guard let original else { return }
        try await service.update(
            name: original.name, tags: plan.tags, url: plan.url, notes: plan.notes,
            expires: plan.expires, minTier: plan.minTier, clear: plan.clear)
    }

    // MARK: sensitive input

    /// Drops the typed value. Called after a save, when the sheet closes and
    /// when the mode changes.
    public func discardSensitive() {
        value = ""
        showCharacters = false
        pastedFromClipboard = false
    }

    /// Reads the clipboard once, on the Paste click.
    public func paste() {
        guard let pasteboard else { return }
        value = pasteboard.string() ?? ""
        pastedChangeCount = pasteboard.changeCount
        pastedFromClipboard = !value.isEmpty
    }

    /// After a successful save: clears the clipboard if the value came from a
    /// Paste click, the user left "Clear the clipboard after saving" on, and
    /// nothing else was copied since. Returns whether it cleared.
    @discardableResult
    private func clearClipboardAfterSave() -> Bool {
        guard pastedFromClipboard, clearClipboardAfterSaving, let pasteboard,
              pasteboard.changeCount == pastedChangeCount
        else { return false }
        pasteboard.clearContents()
        return true
    }
}
