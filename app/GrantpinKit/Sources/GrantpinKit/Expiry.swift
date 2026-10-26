import Foundation

/// Why an expiry text or date is not acceptable.
public enum ExpiryError: Error, Equatable, Sendable {
    case empty
    /// The text is not a duration the CLI accepts.
    case invalid
    /// A duration of zero or less.
    case notPositive
    /// Not at least a minute away.
    case notInFuture

    public var message: String {
        switch self {
        case .empty: return "Enter a time such as 30d, 12h or 90m."
        case .invalid: return "Use a number and a unit: 30d, 2w, 12h, 90m."
        case .notPositive: return "Must be longer than zero."
        case .notInFuture: return "Choose a date in the future."
        }
    }
}

/// Parses the expiry texts the CLI accepts (`--expires 30d`), the same way
/// (cmd/grantpin/clihelp.go `parseDuration`): `Nd` days and `Nw` weeks with N at
/// most 36500, otherwise a Go `time.ParseDuration` string (`12h`, `90m`,
/// `1h30m`, `1.5h`, `2s`, `100ms`). Surrounding whitespace is ignored. Like
/// the CLI, a duration of zero or less is rejected as "must be positive".
public enum ExpiryParser {
    /// The largest N of `Nd` / `Nw`.
    public static let maxCount = 36500
    /// The daemon rejects an expiry that is not in the future; the app asks
    /// for at least this much so a slow request cannot miss.
    public static let minimumLead: TimeInterval = 60

    /// The duration in seconds, always positive.
    public static func parseDuration(_ text: String) throws -> TimeInterval {
        let s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { throw ExpiryError.empty }
        let seconds: Double
        if let dw = parseDaysOrWeeks(s) {
            guard let v = dw else { throw ExpiryError.invalid }
            seconds = v
        } else {
            seconds = try goDuration(s)
        }
        guard seconds > 0 else { throw ExpiryError.notPositive }
        return seconds
    }

    /// `now` plus the duration: what `grantpin set --expires` sends.
    public static func date(from text: String, now: Date = Date()) throws -> Date {
        now.addingTimeInterval(try parseDuration(text))
    }

    /// nil: not of the form `Nd`/`Nw` at all. .some(nil): of that form but N is
    /// too large. .some(value): seconds.
    private static func parseDaysOrWeeks(_ s: String) -> Double?? {
        guard let unit = s.last, unit == "d" || unit == "w" else { return nil }
        let digits = s.dropLast()
        guard !digits.isEmpty, digits.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
        guard let n = Int(digits), n <= maxCount else { return .some(nil) }
        return .some(Double(n) * (unit == "w" ? 7 : 1) * 86_400)
    }

    /// Go's `time.ParseDuration`, in seconds. Mirrors its grammar: an optional
    /// sign, then one or more `<number><unit>`, where the number may have a
    /// fraction, the unit is `ns us µs μs ms s m h`, and a bare `0` is allowed.
    static func goDuration(_ s: String) throws -> Double {
        var rest = Substring(s)
        var negative = false
        if let first = rest.first, first == "-" || first == "+" {
            negative = first == "-"
            rest = rest.dropFirst()
        }
        if rest == "0" { return 0 }
        if rest.isEmpty { throw ExpiryError.invalid }
        var total = 0.0
        while !rest.isEmpty {
            // number
            var digits = ""
            var fraction = ""
            var sawDot = false
            while let c = rest.first, c.isASCII, c.isNumber || c == "." {
                if c == "." {
                    if sawDot { throw ExpiryError.invalid }
                    sawDot = true
                } else if sawDot {
                    fraction.append(c)
                } else {
                    digits.append(c)
                }
                rest = rest.dropFirst()
            }
            if digits.isEmpty && fraction.isEmpty { throw ExpiryError.invalid }
            // unit: everything up to the next digit or dot
            var unit = ""
            while let c = rest.first, !(c.isASCII && (c.isNumber || c == ".")) {
                unit.append(c)
                rest = rest.dropFirst()
            }
            guard let scale = unitSeconds[unit] else { throw ExpiryError.invalid }
            guard let whole = Double(digits.isEmpty ? "0" : digits),
                  let frac = Double("0." + (fraction.isEmpty ? "0" : fraction))
            else { throw ExpiryError.invalid }
            total += (whole + frac) * scale
            if total > 9.2e9 { throw ExpiryError.invalid }  // Go: overflow of int64 nanoseconds
        }
        return negative ? -total : total
    }

    private static let unitSeconds: [String: Double] = [
        "ns": 1e-9, "us": 1e-6, "\u{00B5}s": 1e-6, "\u{03BC}s": 1e-6,
        "ms": 1e-3, "s": 1, "m": 60, "h": 3600,
    ]
}

/// How the expiry picker's choice becomes a date.
public enum ExpiryChoice: Equatable, Sendable {
    case never
    /// `now` plus this many days ("In 7 days", "In 30 days", "In 90 days").
    case inDays(Int)
    /// The end (23:59:59) of this day, local time ("Pick a date…").
    case date(Date)
    /// A duration text the CLI would accept, such as `12h`.
    case custom(String)

    public static let shortcuts: [Int] = [7, 30, 90]

    /// The absolute expiry to send, nil for "never". Throws if a date or
    /// duration is not at least a minute away.
    public func resolve(now: Date = Date(), calendar: Calendar = .current) throws -> Date? {
        let result: Date
        switch self {
        case .never:
            return nil
        case .inDays(let n):
            result = now.addingTimeInterval(Double(n) * 86_400)
        case .date(let d):
            result = Self.endOfDay(d, calendar: calendar)
        case .custom(let text):
            result = try ExpiryParser.date(from: text, now: now)
        }
        guard result.timeIntervalSince(now) >= ExpiryParser.minimumLead else { throw ExpiryError.notInFuture }
        return result
    }

    /// 23:59:59 local time on the day of `date`.
    public static func endOfDay(_ date: Date, calendar: Calendar = .current) -> Date {
        let start = calendar.startOfDay(for: date)
        let next = calendar.date(byAdding: .day, value: 1, to: start) ?? start.addingTimeInterval(86_400)
        return next.addingTimeInterval(-1)
    }
}

/// How an expiry looks in the list and the detail pane.
public enum ExpiryState: Equatable, Sendable {
    case none
    case later
    /// Under seven days away.
    case soon
    case expired
}

public enum ExpiryFormatter {
    public static let soonThreshold: TimeInterval = 7 * 86_400

    public static func state(_ date: Date?, now: Date = Date()) -> ExpiryState {
        guard let date else { return .none }
        let remaining = date.timeIntervalSince(now)
        if remaining <= 0 { return .expired }
        return remaining < soonThreshold ? .soon : .later
    }

    /// The short list form: `in 12 d`, `in 5 h`, `in 20 min`, `in <1 min`,
    /// `expired`; nil for no expiry.
    public static func relative(_ date: Date?, now: Date = Date()) -> String? {
        guard let date else { return nil }
        let remaining = date.timeIntervalSince(now)
        if remaining <= 0 { return "expired" }
        let days = Int(remaining / 86_400)
        if days >= 1 { return "in \(days) d" }
        let hours = Int(remaining / 3600)
        if hours >= 1 { return "in \(hours) h" }
        let minutes = Int(remaining / 60)
        if minutes >= 1 { return "in \(minutes) min" }
        return "in <1 min"
    }

    /// The detail-pane sentence: `Never expires`, `Expires in 3 days`,
    /// `Expires in 5 hours`, `Expired`.
    public static func sentence(_ date: Date?, now: Date = Date()) -> String {
        guard let date else { return "Never expires" }
        let remaining = date.timeIntervalSince(now)
        if remaining <= 0 { return "Expired" }
        func plural(_ n: Int, _ unit: String) -> String { "\(n) \(unit)\(n == 1 ? "" : "s")" }
        let days = Int(remaining / 86_400)
        if days >= 1 { return "Expires in \(plural(days, "day"))" }
        let hours = Int(remaining / 3600)
        if hours >= 1 { return "Expires in \(plural(hours, "hour"))" }
        let minutes = Int(remaining / 60)
        if minutes >= 1 { return "Expires in \(plural(minutes, "minute"))" }
        return "Expires in less than a minute"
    }
}
