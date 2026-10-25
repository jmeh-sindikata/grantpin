import Foundation

/// Client-side mirrors of the daemon's input rules, so the sheets can say what
/// is wrong while the user types. The daemon stays the authority: every rule
/// here is copied from internal/vault/name.go, internal/vault/secrets.go and
/// internal/broker (`maxURLBytes`, `maxNotesBytes`), and a dev-daemon test
/// checks that these functions and the daemon agree (docs/UI-SPEC.md 3.2,
/// 6(a) "Validator parity").
public enum Limits {
    /// `maxNameLen` (bytes; a valid name is ASCII, so bytes and characters agree).
    public static let nameBytes = 256
    /// `maxTagLen`.
    public static let tagBytes = 64
    /// `maxTags`.
    public static let tagCount = 32
    /// `maxValueLen`: 1 MiB.
    public static let valueBytes = 1 << 20
    /// The value counter appears above this many bytes (900 KiB).
    public static let valueWarningBytes = 900 * 1024
    /// `maxURLBytes` of the broker: the stored URL, in bytes.
    public static let urlBytes = 2 << 10
    /// `maxNotesBytes` of the broker: the stored notes, in bytes.
    public static let notesBytes = 2 << 10
}

/// Why a secret name is not acceptable. `message` is the inline text.
public enum NameIssue: Equatable, Sendable {
    case empty
    case tooLong
    case badCharacters
    case leadingOrTrailingSlash
    case doubleDot
    case emptySegment
    case dotSegment

    public var message: String {
        switch self {
        case .empty: return "Enter a name."
        case .tooLong: return "Too long (256 characters max)."
        case .badCharacters: return "Use letters, numbers, _ . - and / only."
        case .leadingOrTrailingSlash: return "Can't start or end with /."
        case .doubleDot: return "Can't contain .."
        case .emptySegment: return "Can't have an empty part between slashes."
        case .dotSegment: return "Can't have a part that is just a dot."
        }
    }
}

/// Why a tag is not acceptable.
public enum TagIssue: Equatable, Sendable {
    case empty
    case tooLong(String)
    case badCharacters(String)

    public var message: String {
        switch self {
        case .empty: return "A tag can't be empty."
        case .tooLong: return "A tag is too long (64 characters max)."
        case .badCharacters: return "Tags can use letters, numbers, _ . - and : only."
        }
    }
}

/// The tags field, parsed.
public struct TagParse: Equatable, Sendable {
    /// Distinct valid tags in the order typed. The daemon sorts them.
    public var tags: [String]
    /// The first problem found, if any.
    public var issue: TagIssue?
    /// More than `Limits.tagCount` distinct tags.
    public var tooMany: Bool

    public var message: String? {
        if tooMany { return "Too many tags (32 max)." }
        return issue?.message
    }

    public var isValid: Bool { issue == nil && !tooMany }
}

public enum Validators {
    // MARK: name

    /// `vault.ValidateName`: `^[A-Za-z0-9_/.-]+$`, at most 256 bytes, no
    /// leading or trailing `/`, no `..` anywhere, no empty segment, no `.`
    /// segment. The same order of checks as the daemon.
    public static func nameIssue(_ name: String) -> NameIssue? {
        if name.isEmpty { return .empty }
        let bytes = Array(name.utf8)
        if bytes.count > Limits.nameBytes { return .tooLong }
        for b in bytes where !isNameByte(b) { return .badCharacters }
        if name.hasPrefix("/") || name.hasSuffix("/") { return .leadingOrTrailingSlash }
        if name.contains("..") { return .doubleDot }
        for segment in name.split(separator: "/", omittingEmptySubsequences: false) {
            if segment.isEmpty { return .emptySegment }
            if segment == "." { return .dotSegment }
        }
        return nil
    }

    public static func isValidName(_ name: String) -> Bool { nameIssue(name) == nil }

    private static func isNameByte(_ c: UInt8) -> Bool {
        (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39)
            || c == 0x5F || c == 0x2F || c == 0x2E || c == 0x2D
    }

    // MARK: tags

    /// `validateTag`: 1 to 64 bytes of `[A-Za-z0-9_.:-]` (a name character
    /// except `/`, plus `:`).
    public static func tagIssue(_ tag: String) -> TagIssue? {
        let bytes = Array(tag.utf8)
        if bytes.isEmpty { return .empty }
        if bytes.count > Limits.tagBytes { return .tooLong(tag) }
        for b in bytes where !(isNameByte(b) && b != 0x2F || b == 0x3A) { return .badCharacters(tag) }
        return nil
    }

    /// Splits the tags field on commas, spaces and newlines, drops empty
    /// pieces and duplicates, and validates each tag.
    public static func parseTags(_ text: String) -> TagParse {
        let separators = CharacterSet(charactersIn: ", \n\t")
        var seen = Set<String>()
        var tags = [String]()
        var issue: TagIssue?
        for piece in text.components(separatedBy: separators) where !piece.isEmpty {
            guard seen.insert(piece).inserted else { continue }
            if issue == nil, let i = tagIssue(piece) { issue = i }
            tags.append(piece)
        }
        return TagParse(tags: tags, issue: issue, tooMany: tags.count > Limits.tagCount)
    }

    // MARK: url, notes

    /// A hard problem with the URL field, or nil. The daemon only limits the
    /// stored size (2 KiB).
    public static func urlIssue(_ url: String) -> String? {
        url.utf8.count > Limits.urlBytes ? "Too long (2 KB max)." : nil
    }

    /// A non-blocking remark: the URL is not an http(s) address.
    public static func urlNote(_ url: String) -> String? {
        let t = url.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        if let u = URL(string: t), let scheme = u.scheme?.lowercased(), scheme == "http" || scheme == "https",
           let host = u.host, !host.isEmpty {
            return nil
        }
        return "This isn't a web address."
    }

    public static func notesIssue(_ notes: String) -> String? {
        notes.utf8.count > Limits.notesBytes ? "Too long (2 KB max)." : nil
    }

    // MARK: value

    /// What the app sends for a value typed into the sheet: one trailing
    /// `\n` or `\r\n` is removed, as the CLI does (`readValue`).
    public static func normalisedValue(_ text: String) -> String {
        // "\r\n" is a single Character in Swift, so work on scalars.
        var scalars = text.unicodeScalars
        if scalars.last == "\n" {
            scalars.removeLast()
            if scalars.last == "\r" { scalars.removeLast() }
        }
        return String(scalars)
    }

    /// A problem with the value as it would be sent, or nil. An empty value is
    /// reported as `.empty` (the Save button just stays disabled).
    public static func valueIssue(_ text: String) -> ValueIssue? {
        let size = normalisedValue(text).utf8.count
        if size == 0 { return .empty }
        if size > Limits.valueBytes { return .tooLarge }
        return nil
    }

    /// Non-blocking remark about leading or trailing spaces.
    public static func valueSpaceNote(_ text: String) -> String? {
        let v = normalisedValue(text)
        let starts = v.hasPrefix(" "), ends = v.hasSuffix(" ")
        switch (starts, ends) {
        case (true, true): return "This value starts and ends with a space. That is kept."
        case (true, false): return "This value starts with a space. That is kept."
        case (false, true): return "This value ends with a space. That is kept."
        default: return nil
        }
    }

    /// Text for the size counter once the value is above 900 KiB.
    public static func valueCounter(_ text: String) -> String? {
        let size = normalisedValue(text).utf8.count
        guard size > Limits.valueWarningBytes else { return nil }
        if size > Limits.valueBytes { return "Too large: 1 MiB maximum." }
        return "\(size / 1024) KiB of 1024 KiB"
    }
}

public enum ValueIssue: Equatable, Sendable {
    case empty
    case tooLarge

    public var message: String {
        switch self {
        case .empty: return "Enter a value."
        case .tooLarge: return "Too large: 1 MiB maximum."
        }
    }
}
