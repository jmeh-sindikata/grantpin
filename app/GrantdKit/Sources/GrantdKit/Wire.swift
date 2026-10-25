import Foundation

/// A request line, without any secret value (docs/PROTOCOL.md "Request").
/// Only fields the app sends are modelled. A value for `set` is never part of
/// a `Request`: it travels as bytes into `RequestLine`, so there is nothing
/// here that could print, log or encode it.
public struct Request: Encodable, Sendable, Equatable {
    public var v: Int = 1
    public var op: String
    public var caller: String = "grantd-app"

    public var name: String?
    public var tags: [String]?
    public var url: String?
    public var notes: String?
    public var expires: Date?
    public var minTier: Tier?
    public var overwrite: Bool?
    public var clear: [String]?
    public var tag: String?
    public var expiringWithinS: Int?
    public var action: String?
    public var grantID: String?
    public var grantCaller: String?
    public var ttlS: Int?
    public var uses: Int?
    public var limit: Int?
    public var cwd: String?
    public var argv: [String]?
    public var secrets: [String]?

    public init(op: String, caller: String = "grantd-app") {
        self.op = op
        self.caller = caller
    }

    public static let status = Request(op: "status")

    enum CodingKeys: String, CodingKey {
        case v, op, caller, name, tags, url, notes, expires
        case minTier = "min_tier", overwrite, clear, tag
        case expiringWithinS = "expiring_within_s", action
        case grantID = "grant_id", grantCaller = "grant_caller"
        case ttlS = "ttl_s", uses, limit, cwd, argv, secrets
    }

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .custom { date, encoder in
            // RFC 3339 UTC, whole seconds: "2026-11-24T22:59:59Z".
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime]
            var c = encoder.singleValueContainer()
            try c.encode(f.string(from: date))
        }
        return e
    }()
}

/// The final response of an exchange. The op-specific `result` stays raw JSON
/// until `decodeResult` is called.
private struct ResultEnvelope<R: Decodable>: Decodable { var result: R? }

public struct Response: Sendable {
    public var ok: Bool
    /// The failure category (`error` on the wire), "" on success.
    public var category: String
    public var reason: String
    public var message: String
    public var auditID: String
    public var grantID: String
    let line: Data

    /// Decodes `result` as `T`, with the protocol's snake_case keys and RFC 3339
    /// times. Unknown fields are ignored.
    public func decodeResult<T: Decodable>(_ type: T.Type) throws -> T {
        do {
            guard let r = try Wire.decoder.decode(ResultEnvelope<T>.self, from: line).result else {
                throw GrantdError.malformedResponse("response has no result")
            }
            return r
        } catch let e as GrantdError {
            throw e
        } catch {
            throw GrantdError.malformedResponse("result does not decode as \(T.self)")
        }
    }

    /// The error this response stands for, or nil when `ok`.
    var error: GrantdError? {
        ok ? nil : .daemon(category: ErrorCategory(wire: category), reason: ErrorReason(wire: reason), message: message)
    }

    /// Parses one line. Returns nil for a stream frame (`{"stream":...}`), the
    /// response for a `{"ok":...}` line, and throws for anything else.
    static func parse(line: Data) throws -> Response? {
        struct Head: Decodable {
            var isStream = false
            var ok: Bool?
            var error: String?
            var reason: String?
            var message: String?
            var auditID: String?
            var grantID: String?
            enum K: String, CodingKey { case stream, ok, error, reason, message, auditID = "audit_id", grantID = "grant_id" }
            init(from decoder: Decoder) throws {
                let c = try decoder.container(keyedBy: K.self)
                isStream = c.contains(.stream)
                guard !isStream else { return }
                ok = try c.decodeIfPresent(Bool.self, forKey: .ok)
                error = try c.decodeIfPresent(String.self, forKey: .error)
                reason = try c.decodeIfPresent(String.self, forKey: .reason)
                message = try c.decodeIfPresent(String.self, forKey: .message)
                auditID = try c.decodeIfPresent(String.self, forKey: .auditID)
                grantID = try c.decodeIfPresent(String.self, forKey: .grantID)
            }
        }
        let head: Head
        do {
            head = try JSONDecoder().decode(Head.self, from: line)
        } catch {
            throw GrantdError.malformedResponse("not a protocol message")
        }
        if head.isStream { return nil }
        guard let ok = head.ok else { throw GrantdError.malformedResponse("neither a stream frame nor a response") }
        return Response(ok: ok, category: head.error ?? "", reason: head.reason ?? "", message: head.message ?? "",
                        auditID: head.auditID ?? "", grantID: head.grantID ?? "", line: line)
    }
}

enum Wire {
    /// The protocol's line limit, newline included (`proto.MaxLineBytes`).
    static let maxLineBytes = 4 << 20

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = fractional.date(from: s) ?? plain.date(from: s) { return d }
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "bad time \(s)"))
        }
        return d
    }()
}

/// One request line, newline included, in a buffer this type owns so it can
/// be overwritten with zeros once the request has been written (docs/UI-SPEC.md
/// 4.1). For `set` the value is escaped straight from the caller's bytes into
/// the buffer: no `String` and no second buffer of the value is created here.
///
/// It prints as `[REDACTED]` however it is formatted.
final class RequestLine: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let lock = NSLock()
    private var storage: UnsafeMutableBufferPointer<UInt8>
    private var wiped = false

    var description: String { "RequestLine([REDACTED], \(storage.count) bytes)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: ["bytes": "[REDACTED]"]) }

    /// Builds the line for `request`. `value`, if given, becomes the `"value"`
    /// member of the JSON object. Throws `requestTooLarge` before allocating
    /// when the line would exceed the protocol limit, and `invalidRequest` for
    /// a value that is not UTF-8.
    init(request: Request, value: Data? = nil) throws {
        let header: Data
        do {
            header = try Request.encoder.encode(request)
        } catch {
            throw GrantdError.invalidRequest("cannot encode request")
        }
        guard header.last == UInt8(ascii: "}") else { throw GrantdError.invalidRequest("cannot encode request") }

        var escaped = 0
        if let value {
            guard let n = value.withUnsafeBytes({ Self.escapedLength(of: $0) }) else {
                throw GrantdError.invalidRequest("the value is not valid UTF-8")
            }
            escaped = n
        }
        let valueMember = value == nil ? 0 : (header.count > 2 ? 1 : 0) + 9 + escaped + 1  // [,]"value":" ... "
        let total = (header.count - 1) + valueMember + 1 + 1                              // ... } \n
        guard total <= Wire.maxLineBytes else { throw GrantdError.requestTooLarge }

        let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: total)
        var i = 0
        func put(_ b: UInt8) { buf[i] = b; i += 1 }
        for b in header.dropLast() { put(b) }
        if let value {
            if header.count > 2 { put(UInt8(ascii: ",")) }
            for b in "\"value\":\"".utf8 { put(b) }
            value.withUnsafeBytes { raw in
                for b in raw { Self.emit(b, put) }
            }
            put(UInt8(ascii: "\""))
        }
        put(UInt8(ascii: "}"))
        put(0x0A)
        precondition(i == total, "request line length miscalculated")
        storage = buf
    }

    deinit { wipe() }

    /// The bytes, for the duration of `body`. Empty once wiped.
    func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        lock.lock(); defer { lock.unlock() }
        return try body(UnsafeRawBufferPointer(storage))
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return storage.count }

    /// Overwrites the buffer with zeros (`memset_s`, which the optimiser may
    /// not remove) and frees it. Idempotent.
    func wipe() {
        lock.lock(); defer { lock.unlock() }
        guard !wiped else { return }
        wiped = true
        if let base = storage.baseAddress {
            _ = memset_s(base, storage.count, 0, storage.count)
            base.deallocate()
        }
        storage = UnsafeMutableBufferPointer(start: nil, count: 0)
    }

    var isWiped: Bool { lock.lock(); defer { lock.unlock() }; return wiped }

    // MARK: JSON string escaping

    /// Length of the JSON-escaped form of valid UTF-8 `bytes`, nil if they are
    /// not valid UTF-8. `"` and `\` get a backslash, bytes below 0x20 become
    /// `\u00XX` (six bytes), everything else is copied.
    static func escapedLength(of bytes: UnsafeRawBufferPointer) -> Int? {
        guard isValidUTF8(bytes) else { return nil }
        var n = 0
        for b in bytes {
            switch b {
            case 0x22, 0x5C: n += 2
            case 0..<0x20: n += 6
            default: n += 1
            }
        }
        return n
    }

    private static func emit(_ b: UInt8, _ put: (UInt8) -> Void) {
        switch b {
        case 0x22, 0x5C:
            put(0x5C); put(b)
        case 0..<0x20:
            let hex = Array("0123456789abcdef".utf8)
            put(0x5C); put(UInt8(ascii: "u")); put(UInt8(ascii: "0")); put(UInt8(ascii: "0"))
            put(hex[Int(b >> 4)]); put(hex[Int(b & 0xF)])
        default:
            put(b)
        }
    }

    /// Strict UTF-8 validation (no overlong forms, no surrogates, nothing above
    /// U+10FFFF), without creating a `String`.
    static func isValidUTF8(_ bytes: UnsafeRawBufferPointer) -> Bool {
        var i = 0
        let n = bytes.count
        while i < n {
            let b0 = bytes[i]
            if b0 < 0x80 { i += 1; continue }
            func cont(_ k: Int, _ lo: UInt8 = 0x80, _ hi: UInt8 = 0xBF) -> Bool {
                i + k < n && bytes[i + k] >= lo && bytes[i + k] <= hi
            }
            switch b0 {
            case 0xC2...0xDF:
                guard cont(1) else { return false }
                i += 2
            case 0xE0:
                guard cont(1, 0xA0, 0xBF), cont(2) else { return false }
                i += 3
            case 0xE1...0xEC, 0xEE...0xEF:
                guard cont(1), cont(2) else { return false }
                i += 3
            case 0xED:
                guard cont(1, 0x80, 0x9F), cont(2) else { return false }
                i += 3
            case 0xF0:
                guard cont(1, 0x90, 0xBF), cont(2), cont(3) else { return false }
                i += 4
            case 0xF1...0xF3:
                guard cont(1), cont(2), cont(3) else { return false }
                i += 4
            case 0xF4:
                guard cont(1, 0x80, 0x8F), cont(2), cont(3) else { return false }
                i += 4
            default:
                return false
            }
        }
        return true
    }
}
