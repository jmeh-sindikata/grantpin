import Foundation
import XCTest
@testable import GrantdKit

final class ValidatorTests: XCTestCase {
    // The same table the Go tests use, plus the shapes the spec names.
    static let validNames = [
        "a", "A", "0", "_", "-", ".a", "a.", "a-b", "a_b", "a.b", "API_KEY", "aws/prod/key", "a/b", "a/.b", "a/b.c/d-e_f",
        String(repeating: "a", count: 256), "x.y.z", "...a".replacingOccurrences(of: "...", with: "-"),
    ]
    static let invalidNames: [(String, NameIssue)] = [
        ("", .empty),
        (String(repeating: "a", count: 257), .tooLong),
        ("a b", .badCharacters), ("a\n", .badCharacters), ("a\tb", .badCharacters), ("a*", .badCharacters),
        ("a?", .badCharacters), ("a[b]", .badCharacters), ("a{b}", .badCharacters), ("a\\b", .badCharacters),
        ("a:b", .badCharacters), ("a@b", .badCharacters), ("ä", .badCharacters), ("日本", .badCharacters),
        ("a\u{0}b", .badCharacters), ("$HOME", .badCharacters), ("a=b", .badCharacters), ("a,b", .badCharacters),
        ("/a", .leadingOrTrailingSlash), ("a/", .leadingOrTrailingSlash), ("/", .leadingOrTrailingSlash),
        ("a..b", .doubleDot), ("..", .doubleDot), ("../a", .doubleDot), ("a/..", .doubleDot), ("a/../b", .doubleDot),
        ("a//b", .emptySegment), ("a///b", .emptySegment),
        (".", .dotSegment), ("./a", .dotSegment), ("a/.", .dotSegment), ("a/./b", .dotSegment),
    ]

    func testValidNames() {
        for n in Self.validNames { XCTAssertNil(Validators.nameIssue(n), "\(n.prefix(20))") }
    }

    func testInvalidNamesAndTheirReasons() {
        for (n, issue) in Self.invalidNames {
            XCTAssertEqual(Validators.nameIssue(n), issue, "\(n.prefix(20).debugDescription)")
            XCTAssertFalse(Validators.isValidName(n))
        }
    }

    func testNameLimitIsBytesNotCharacters() {
        XCTAssertNil(Validators.nameIssue(String(repeating: "a", count: 256)))
        // a multi-byte character fails on characters first, as the daemon does
        XCTAssertEqual(Validators.nameIssue(String(repeating: "é", count: 129)), .tooLong)
    }

    func testNameMessages() {
        XCTAssertEqual(NameIssue.badCharacters.message, "Use letters, numbers, _ . - and / only.")
        XCTAssertEqual(NameIssue.leadingOrTrailingSlash.message, "Can't start or end with /.")
        XCTAssertEqual(NameIssue.doubleDot.message, "Can't contain ..")
        XCTAssertEqual(NameIssue.tooLong.message, "Too long (256 characters max).")
    }

    // MARK: tags

    func testTagRules() {
        for t in ["a", "A1", "prod", "team:billing", "v1.2", "a_b", "a-b", ":", String(repeating: "x", count: 64)] {
            XCTAssertNil(Validators.tagIssue(t), t)
        }
        XCTAssertEqual(Validators.tagIssue(""), .empty)
        XCTAssertEqual(Validators.tagIssue(String(repeating: "x", count: 65)), .tooLong(String(repeating: "x", count: 65)))
        for t in ["a/b", "a b", "a*", "é", "a,b", "a\n", "#tag", "a;b"] {
            XCTAssertEqual(Validators.tagIssue(t), .badCharacters(t), t)
        }
    }

    func testParseTagsSplitsOnCommaSpaceAndNewline() {
        let p = Validators.parseTags("prod, billing  ops\nteam:x,,")
        XCTAssertEqual(p.tags, ["prod", "billing", "ops", "team:x"])
        XCTAssertTrue(p.isValid)
        XCTAssertNil(p.message)
    }

    func testParseTagsCollapsesDuplicatesKeepingOrder() {
        XCTAssertEqual(Validators.parseTags("b, a, b, a").tags, ["b", "a"])
    }

    func testParseTagsReportsTheFirstBadTag() {
        let p = Validators.parseTags("ok, bad/tag, also bad")
        XCTAssertEqual(p.issue, .badCharacters("bad/tag"))
        XCTAssertFalse(p.isValid)
        XCTAssertEqual(p.message, "Tags can use letters, numbers, _ . - and : only.")
    }

    func testTagCountLimit() {
        let ok = (0..<32).map { "t\($0)" }.joined(separator: ",")
        XCTAssertTrue(Validators.parseTags(ok).isValid)
        let many = (0..<33).map { "t\($0)" }.joined(separator: ",")
        let p = Validators.parseTags(many)
        XCTAssertTrue(p.tooMany)
        XCTAssertEqual(p.message, "Too many tags (32 max).")
        // duplicates do not count twice
        XCTAssertTrue(Validators.parseTags(many + ",t1,t2").tooMany)
        XCTAssertFalse(Validators.parseTags(ok + ",t1,t2").tooMany)
    }

    func testEmptyTagFieldIsValidAndEmpty() {
        let p = Validators.parseTags("  , ,")
        XCTAssertEqual(p.tags, [])
        XCTAssertTrue(p.isValid)
    }

    // MARK: url, notes

    func testURLAndNotesLimitsAreTwoKiBInBytes() {
        XCTAssertNil(Validators.urlIssue(String(repeating: "a", count: 2048)))
        XCTAssertNotNil(Validators.urlIssue(String(repeating: "a", count: 2049)))
        XCTAssertNil(Validators.notesIssue(String(repeating: "a", count: 2048)))
        XCTAssertNotNil(Validators.notesIssue(String(repeating: "a", count: 2049)))
        // multi-byte characters count by bytes, like the daemon's len()
        XCTAssertNotNil(Validators.notesIssue(String(repeating: "é", count: 1025)))
        XCTAssertNil(Validators.notesIssue(String(repeating: "é", count: 1024)))
    }

    func testURLNoteIsNonBlockingAndOnlyForNonWebAddresses() {
        XCTAssertNil(Validators.urlNote(""))
        XCTAssertNil(Validators.urlNote("https://console.aws.amazon.com/x"))
        XCTAssertNil(Validators.urlNote("http://localhost:8080"))
        XCTAssertEqual(Validators.urlNote("ftp://example.com"), "This isn't a web address.")
        XCTAssertEqual(Validators.urlNote("example.com"), "This isn't a web address.")
        XCTAssertEqual(Validators.urlNote("javascript:alert(1)"), "This isn't a web address.")
        XCTAssertEqual(Validators.urlNote("https://"), "This isn't a web address.")
    }

    // MARK: value

    func testNormalisedValueStripsOneTrailingNewline() {
        XCTAssertEqual(Validators.normalisedValue("abc\n"), "abc")
        XCTAssertEqual(Validators.normalisedValue("abc\r\n"), "abc")
        XCTAssertEqual(Validators.normalisedValue("abc\n\n"), "abc\n")
        XCTAssertEqual(Validators.normalisedValue("abc\r"), "abc\r")
        XCTAssertEqual(Validators.normalisedValue("  abc  "), "  abc  ")
    }

    func testValueIssues() {
        XCTAssertEqual(Validators.valueIssue(""), .empty)
        XCTAssertEqual(Validators.valueIssue("\n"), .empty)
        XCTAssertNil(Validators.valueIssue("x"))
        XCTAssertNil(Validators.valueIssue(String(repeating: "x", count: 1 << 20)))
        XCTAssertNil(Validators.valueIssue(String(repeating: "x", count: 1 << 20) + "\n"))
        XCTAssertEqual(Validators.valueIssue(String(repeating: "x", count: (1 << 20) + 1)), .tooLarge)
    }

    func testValueCounterAppearsAbove900KiB() {
        XCTAssertNil(Validators.valueCounter(String(repeating: "x", count: 900 * 1024)))
        XCTAssertEqual(Validators.valueCounter(String(repeating: "x", count: 900 * 1024 + 1)), "900 KiB of 1024 KiB")
        XCTAssertEqual(Validators.valueCounter(String(repeating: "x", count: (1 << 20) + 1)), "Too large: 1 MiB maximum.")
    }

    func testSpaceNote() {
        XCTAssertNil(Validators.valueSpaceNote("abc"))
        XCTAssertEqual(Validators.valueSpaceNote(" abc"), "This value starts with a space. That is kept.")
        XCTAssertEqual(Validators.valueSpaceNote("abc "), "This value ends with a space. That is kept.")
        XCTAssertEqual(Validators.valueSpaceNote(" abc "), "This value starts and ends with a space. That is kept.")
        XCTAssertNil(Validators.valueSpaceNote("abc\n"))
    }
}
