import Foundation

/// Helpers for text that did not come from the user's own keystrokes in this
/// window: secret names, URLs, notes, tags, callers, paths, argv, daemon
/// messages, helper stderr (docs/UI-SPEC.md 4.4). Everything here is for
/// display only; never use the result to talk back to the daemon.
public enum DisplayText {
    /// Default budget for a table cell.
    public static let cellLimit = 200
    /// Budget for a detail pane.
    public static let detailLimit = 8192

    /// Makes `text` safe to show:
    ///
    /// 1. C0 and C1 control characters (and DEL) become `⟦U+XXXX⟧`. With
    ///    `allowNewlines` a line feed stays (the multi-line detail pane); a tab
    ///    is always shown as `→`.
    /// 2. Bidirectional and invisible formatting characters (U+061C,
    ///    U+200B to U+200F, U+2028/2029, U+202A to U+202E, U+2060 to U+2064,
    ///    U+2066 to U+2069, U+FEFF) become the same visible escape.
    /// 3. A result longer than `limit` characters is cut in the middle with
    ///    `…`, keeping both ends.
    ///
    /// Render the result with `Text(verbatim:)` (never `Text("\(x)")`, which
    /// parses Markdown and creates links).
    public static func sanitise(_ text: String, limit: Int = cellLimit, allowNewlines: Bool = false) -> String {
        var out = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if scalar == "\n", allowNewlines {
                out.append(scalar)
            } else if scalar == "\t" {
                out.append("\u{2192}")  // →
            } else if needsEscape(scalar) {
                out.append(contentsOf: escape(scalar).unicodeScalars)
            } else {
                out.append(scalar)
            }
        }
        return truncateMiddle(String(out), limit: limit)
    }

    /// `text` cut to `limit` characters by replacing the middle with `…`.
    public static func truncateMiddle(_ text: String, limit: Int) -> String {
        guard text.count > limit else { return text }
        guard limit > 1 else { return "…" }
        let keep = limit - 1
        let head = (keep + 1) / 2
        let tail = keep - head
        return String(text.prefix(head)) + "…" + String(text.suffix(tail))
    }

    /// A command line for display: each argument sanitised, joined by spaces.
    public static func argvLine(_ argv: [String], limit: Int = detailLimit) -> String {
        sanitise(argv.joined(separator: " "), limit: limit)
    }

    static func escape(_ scalar: Unicode.Scalar) -> String {
        let hex = String(scalar.value, radix: 16, uppercase: true)
        return "\u{27E6}U+" + String(repeating: "0", count: max(0, 4 - hex.count)) + hex + "\u{27E7}"
    }

    static func needsEscape(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x061C, 0x200B...0x200F, 0x2028, 0x2029, 0x202A...0x202E, 0x2060...0x2064, 0x2066...0x2069, 0xFEFF:
            return true
        default:
            return scalar.properties.generalCategory == .control
        }
    }
}
