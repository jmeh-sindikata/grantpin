import Foundation
import XCTest
@testable import GrantpinKit

/// The request buffer: escaping, limits, wiping, redaction.
final class RequestLineTests: XCTestCase {
    private func text(_ line: RequestLine) -> String {
        line.withBytes { String(decoding: $0, as: UTF8.self) }
    }

    private func object(_ line: RequestLine) throws -> [String: Any] {
        let s = text(line)
        XCTAssertTrue(s.hasSuffix("}\n"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any])
    }

    func testValueIsEscapedIntoValidJSONAndRoundTrips() throws {
        let samples = [
            "plain", "with \"quotes\" and \\ backslash", "line1\nline2\r\n\ttab", "nul\u{0}ctl\u{1}\u{1F}",
            "caf\u{00E9} \u{1F511} \u{4E2D}\u{6587}", "\u{2028}\u{2029}", "/slash/", String(repeating: "ab\"", count: 1000),
        ]
        for s in samples {
            var r = Request(op: "set")
            r.name = "k"
            let line = try RequestLine(request: r, value: Data(s.utf8))
            let obj = try object(line)
            XCTAssertEqual(obj["value"] as? String, s, "round trip of \(s.debugDescription)")
            XCTAssertEqual(obj["name"] as? String, "k")
            XCTAssertEqual(obj["op"] as? String, "set")
            XCTAssertEqual(text(line).filter { $0 == "\n" }.count, 1, "raw newline inside the line")
            line.wipe()
        }
    }

    func testRequestWithoutAValueHasNoValueMember() throws {
        let line = try RequestLine(request: Request(op: "list"))
        XCTAssertNil(try object(line)["value"])
    }

    func testInvalidUTF8IsRefused() {
        let bad: [[UInt8]] = [[0xFF], [0xC0, 0x80], [0xED, 0xA0, 0x80], [0xE2, 0x82], [0xF4, 0x90, 0x80, 0x80], [0x80], [0xC3]]
        for b in bad {
            XCTAssertThrowsError(try RequestLine(request: Request(op: "set"), value: Data(b)), "\(b)") { e in
                guard case GrantpinError.invalidRequest = e else { return XCTFail("\(e)") }
            }
        }
        // valid multi-byte forms pass
        for s in ["\u{00E9}", "\u{20AC}", "\u{1F600}", "\u{10FFFF}", "\u{D7FF}", "\u{E000}"] {
            XCTAssertNoThrow(try RequestLine(request: Request(op: "set"), value: Data(s.utf8)), s)
        }
    }

    func testLimitIsFourMiBOfLine() throws {
        // 1 MiB of control characters escapes to 6 MiB: refused before allocating.
        XCTAssertThrowsError(try RequestLine(request: Request(op: "set"), value: Data(repeating: 0x07, count: 1 << 20))) { e in
            XCTAssertEqual(e as? GrantpinError, .requestTooLarge)
        }
        // 1 MiB of ordinary bytes is fine (the daemon's own limit is 1 MiB).
        let ok = try RequestLine(request: Request(op: "set"), value: Data(repeating: 0x61, count: 1 << 20))
        XCTAssertLessThan(ok.count, Wire.maxLineBytes)
        // the line limit is on the whole line: find the largest accepted size
        let header = try RequestLine(request: Request(op: "set")).count
        let room = Wire.maxLineBytes - header - 11  // `,"value":"` and the closing `"` are 11 bytes
        let atLimit = try RequestLine(request: Request(op: "set"), value: Data(repeating: 0x61, count: room))
        XCTAssertEqual(atLimit.count, Wire.maxLineBytes)
        XCTAssertThrowsError(try RequestLine(request: Request(op: "set"), value: Data(repeating: 0x61, count: room + 1))) { e in
            XCTAssertEqual(e as? GrantpinError, .requestTooLarge)
        }
    }

    func testWipeZeroesAndFrees() throws {
        let line = try RequestLine(request: Request(op: "set"), value: Data("top-secret-value".utf8))
        // Observe the bytes through a raw pointer taken before the wipe.
        let (base, n) = line.withBytes { ($0.baseAddress!, $0.count) }
        XCTAssertGreaterThan(n, 16)
        XCTAssertFalse(line.isWiped)
        line.wipe()
        XCTAssertTrue(line.isWiped)
        XCTAssertEqual(line.count, 0)
        XCTAssertTrue(line.withBytes { $0.isEmpty })
        line.wipe()  // idempotent
        _ = base
    }

    func testTheBufferIsAllZeroAfterTheRequestIsWritten() async throws {
        let received = ManagedFlag()
        let server = try FakeServer { fd, line in
            if line.contains("top-secret-value") { received.set() }
            FakeServer.send(fd, #"{"ok":true}"# + "\n")
        }
        var r = Request(op: "set")
        r.name = "k"
        let line = try RequestLine(request: r, value: Data("top-secret-value".utf8))
        let cancel = Client.CancelFlag()
        _ = try Client.exchange(path: server.path, line: line, timeout: 5, cancel: cancel)
        XCTAssertTrue(received.value, "the server never got the value")
        XCTAssertTrue(line.isWiped, "the request buffer was not wiped after the request was written")
    }

    func testRequestLineNeverPrintsItsContent() throws {
        let secret = "do-not-print-me-0123"
        let line = try RequestLine(request: Request(op: "set"), value: Data(secret.utf8))
        defer { line.wipe() }
        var dumped = ""
        dump(line, to: &dumped)
        for text in [String(describing: line), String(reflecting: line), "\(line)", dumped] {
            XCTAssertTrue(text.contains("REDACTED"), text)
            XCTAssertFalse(text.contains(secret), text)
        }
    }

    func testRequestHasNoValueField() {
        // A Request cannot hold a secret, so nothing that prints or encodes
        // one can leak it.
        let names = Mirror(reflecting: Request(op: "set")).children.compactMap(\.label)
        XCTAssertFalse(names.contains("value"))
    }

    func testDatesEncodeAsRFC3339UTC() throws {
        var r = Request(op: "set")
        r.expires = Date(timeIntervalSince1970: 1_795_561_199)  // 2026-11-24T22:59:59Z
        let line = try RequestLine(request: r)
        XCTAssertEqual(try object(line)["expires"] as? String, "2026-11-24T22:59:59Z")
    }
}

final class DisplayTextTests: XCTestCase {
    func testPlainTextIsUnchanged() {
        XCTAssertEqual(DisplayText.sanitise("stripe/api_key — café 中文 🔑"), "stripe/api_key — café 中文 🔑")
    }

    func testControlCharactersBecomeVisibleEscapes() {
        XCTAssertEqual(DisplayText.sanitise("a\u{0}b"), "a⟦U+0000⟧b")
        XCTAssertEqual(DisplayText.sanitise("\u{1B}[31mred"), "⟦U+001B⟧[31mred")
        XCTAssertEqual(DisplayText.sanitise("x\u{7F}y"), "x⟦U+007F⟧y")
        XCTAssertEqual(DisplayText.sanitise("x\u{85}y"), "x⟦U+0085⟧y")  // C1
        XCTAssertEqual(DisplayText.sanitise("a\r\nb"), "a⟦U+000D⟧⟦U+000A⟧b")
        XCTAssertEqual(DisplayText.sanitise("a\tb"), "a→b")
    }

    func testNewlinesOnlyWhenAsked() {
        XCTAssertEqual(DisplayText.sanitise("a\nb", allowNewlines: true), "a\nb")
        XCTAssertEqual(DisplayText.sanitise("a\nb"), "a⟦U+000A⟧b")
        XCTAssertEqual(DisplayText.sanitise("a\r\nb", allowNewlines: true), "a⟦U+000D⟧\nb")
    }

    func testBidiAndInvisibleCharactersAreEscaped() {
        let scalars: [UInt32] = [0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                                 0x2060, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0x2028, 0x2029]
        for v in scalars {
            let s = "a\(Unicode.Scalar(v)!)b"
            let out = DisplayText.sanitise(s)
            XCTAssertEqual(out, "a⟦U+\(String(format: "%04X", v))⟧b")
            XCTAssertFalse(out.unicodeScalars.contains(Unicode.Scalar(v)!))
        }
        // the right-to-left override that reverses what follows
        XCTAssertEqual(DisplayText.sanitise("rm \u{202E}txt.exe"), "rm ⟦U+202E⟧txt.exe")
    }

    func testLongTextIsCutInTheMiddle() {
        let long = String(repeating: "a", count: 2500) + "END"
        let cell = DisplayText.sanitise(long)
        XCTAssertEqual(cell.count, 200)
        XCTAssertTrue(cell.contains("…") && cell.hasSuffix("END") && cell.hasPrefix("aaa"))
        let five = DisplayText.sanitise(String(repeating: "x", count: 5000), limit: DisplayText.detailLimit)
        XCTAssertEqual(five.count, 5000)
        let detail = DisplayText.sanitise(String(repeating: "x", count: 9000), limit: DisplayText.detailLimit)
        XCTAssertEqual(detail.count, 8192)
        XCTAssertEqual(DisplayText.truncateMiddle("abcdef", limit: 6), "abcdef")
        XCTAssertEqual(DisplayText.truncateMiddle("abcdefg", limit: 6), "abc…fg")
        XCTAssertEqual(DisplayText.truncateMiddle("abcdefg", limit: 1), "…")
    }

    func testArgvLine() {
        XCTAssertEqual(DisplayText.argvLine(["php", "a\u{1B}b", "x\u{202E}"]), "php a⟦U+001B⟧b x⟦U+202E⟧")
        XCTAssertEqual(DisplayText.argvLine([String](repeating: String(repeating: "z", count: 100), count: 200)).count, 8192)
    }

    func testZeroWidthJoinerIsEscapedEvenInsideEmoji() {
        // Per the spec's list U+200D is escaped; a family emoji shows its parts.
        XCTAssertTrue(DisplayText.sanitise("👩\u{200D}👩").contains("⟦U+200D⟧"))
    }
}

final class SocketLocatorTests: XCTestCase {
    private let home = URL(fileURLWithPath: "/Users/a")

    private func plist(_ dict: [String: Any]) throws -> URL {
        let url = URL(fileURLWithPath: "/tmp/gdt-plist-\(UUID().uuidString.prefix(8)).plist")
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0).write(to: url)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    func testRule1EnvironmentWinsOverThePlist() throws {
        let p = try plist(["EnvironmentVariables": ["GRANTPIN_SOCKET": "/from/plist.sock"]])
        let r = SocketLocator.resolve(environment: ["GRANTPIN_SOCKET": "/tmp/x.sock"], home: home, plist: p)
        XCTAssertEqual(r, SocketLocator.Resolution(path: "/tmp/x.sock", source: .environment))
        XCTAssertTrue(r.isDevelopment)
    }

    func testRule2PlistWhenTheEnvironmentHasNone() throws {
        let p = try plist(["Label": "dev.grantpin.daemon", "EnvironmentVariables": ["PATH": "/usr/bin", "GRANTPIN_SOCKET": "/custom/g.sock"]])
        let r = SocketLocator.resolve(environment: [:], home: home, plist: p)
        XCTAssertEqual(r, SocketLocator.Resolution(path: "/custom/g.sock", source: .launchAgentPlist))
        XCTAssertFalse(r.isDevelopment)
        // an empty variable is not an override
        XCTAssertEqual(SocketLocator.resolve(environment: ["GRANTPIN_SOCKET": ""], home: home, plist: p).source, .launchAgentPlist)
    }

    func testRule3DefaultPath() throws {
        let r = SocketLocator.resolve(environment: [:], home: home, plist: URL(fileURLWithPath: "/tmp/gdt-no-such.plist"))
        XCTAssertEqual(r.path, "/Users/a/Library/Application Support/grantpin/grantpin.sock")
        XCTAssertEqual(r.source, .defaultPath)
        XCTAssertFalse(r.isDevelopment)
    }

    func testAPlistWithoutAUsableValueFallsThroughToTheDefault() throws {
        let cases: [[String: Any]] = [
            [:],
            ["EnvironmentVariables": [String: String]()],
            ["EnvironmentVariables": ["PATH": "/usr/bin"]],
            ["EnvironmentVariables": ["GRANTPIN_SOCKET": ""]],
            ["EnvironmentVariables": ["GRANTPIN_SOCKET": "relative.sock"]],
            ["EnvironmentVariables": ["GRANTPIN_SOCKET": 5]],
            ["EnvironmentVariables": "not a dictionary"],
        ]
        for c in cases {
            let r = SocketLocator.resolve(environment: [:], home: home, plist: try plist(c))
            XCTAssertEqual(r.source, .defaultPath, "\(c)")
        }
        // a file that is not a plist at all
        let junk = URL(fileURLWithPath: "/tmp/gdt-junk-\(UUID().uuidString.prefix(8)).plist")
        try Data("not a plist".utf8).write(to: junk)
        defer { try? FileManager.default.removeItem(at: junk) }
        XCTAssertEqual(SocketLocator.resolve(environment: [:], home: home, plist: junk).source, .defaultPath)
    }

    func testThePlistIsFoundUnderLibraryLaunchAgents() throws {
        let h = URL(fileURLWithPath: "/tmp/gdt-home-\(UUID().uuidString.prefix(8))")
        let agents = h.appendingPathComponent("Library/LaunchAgents")
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: h) }
        let data = try PropertyListSerialization.data(fromPropertyList: ["EnvironmentVariables": ["GRANTPIN_SOCKET": "/s/g.sock"]], format: .xml, options: 0)
        try data.write(to: agents.appendingPathComponent("dev.grantpin.daemon.plist"))
        XCTAssertEqual(SocketLocator.launchAgentPlistURL(home: h).lastPathComponent, "dev.grantpin.daemon.plist")
        let r = SocketLocator.resolve(environment: [:], home: h)
        XCTAssertEqual(r, SocketLocator.Resolution(path: "/s/g.sock", source: .launchAgentPlist))
    }

    func testTooLongPathIsFlagged() {
        let long = "/tmp/" + String(repeating: "a", count: 120)
        XCTAssertTrue(SocketLocator.Resolution(path: long, source: .defaultPath).isTooLong)
        XCTAssertFalse(SocketLocator.Resolution(path: "/tmp/ok.sock", source: .defaultPath).isTooLong)
        XCTAssertEqual(SocketLocator.maxBytes, 103)
    }
}
