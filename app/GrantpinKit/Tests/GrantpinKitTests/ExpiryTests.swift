import Foundation
import XCTest
@testable import GrantpinKit

final class ExpiryParserTests: XCTestCase {
    func testDaysAndWeeks() throws {
        XCTAssertEqual(try ExpiryParser.parseDuration("30d"), 30 * 86_400)
        XCTAssertEqual(try ExpiryParser.parseDuration("1d"), 86_400)
        XCTAssertEqual(try ExpiryParser.parseDuration("2w"), 14 * 86_400)
        XCTAssertEqual(try ExpiryParser.parseDuration("  7d  "), 7 * 86_400)
        XCTAssertEqual(try ExpiryParser.parseDuration("36500d"), 36500 * 86_400)
    }

    func testGoDurations() throws {
        XCTAssertEqual(try ExpiryParser.parseDuration("12h"), 12 * 3600)
        XCTAssertEqual(try ExpiryParser.parseDuration("90m"), 5400)
        XCTAssertEqual(try ExpiryParser.parseDuration("1h30m"), 5400)
        XCTAssertEqual(try ExpiryParser.parseDuration("1.5h"), 5400)
        XCTAssertEqual(try ExpiryParser.parseDuration("2s"), 2)
        XCTAssertEqual(try ExpiryParser.parseDuration("1500ms"), 1.5, accuracy: 1e-9)
        XCTAssertEqual(try ExpiryParser.parseDuration("+5m"), 300)
        XCTAssertEqual(try ExpiryParser.parseDuration(".5h"), 1800)
        XCTAssertEqual(try ExpiryParser.parseDuration("100h"), 360_000)
        XCTAssertEqual(try ExpiryParser.parseDuration("10us"), 1e-5, accuracy: 1e-12)
        XCTAssertEqual(try ExpiryParser.parseDuration("1\u{00B5}s"), 1e-6, accuracy: 1e-12)
    }

    func testRejectedTextsMatchTheCLI() {
        let cases: [(String, ExpiryError)] = [
            ("", .empty), ("   ", .empty),
            ("abc", .invalid), ("30", .invalid), ("d", .invalid), ("-d", .invalid), ("1.5d", .invalid), ("3 d", .invalid),
            ("1h30", .invalid), ("h", .invalid), ("1x", .invalid), ("1.2.3h", .invalid), ("--5h", .invalid), ("5H", .invalid),
            ("36501d", .invalid), ("999999999999999999999d", .invalid), ("5000w2", .invalid), ("1 h", .invalid), ("٣d", .invalid),
            ("0d", .notPositive), ("0w", .notPositive), ("0", .notPositive), ("0s", .notPositive), ("-5h", .notPositive), ("-0", .notPositive),
        ]
        for (text, expected) in cases {
            XCTAssertThrowsError(try ExpiryParser.parseDuration(text), text) { e in
                XCTAssertEqual(e as? ExpiryError, expected, text)
            }
        }
    }

    func testDateIsNowPlusDuration() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertEqual(try ExpiryParser.date(from: "30d", now: now), now.addingTimeInterval(30 * 86_400))
    }

    func testMessages() {
        XCTAssertEqual(ExpiryError.invalid.message, "Use a number and a unit: 30d, 2w, 12h, 90m.")
        XCTAssertEqual(ExpiryError.notInFuture.message, "Choose a date in the future.")
    }
}

final class ExpiryChoiceTests: XCTestCase {
    var cal: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "Europe/Berlin")!
        return c
    }
    let now = Date(timeIntervalSince1970: 1_800_000_000)  // 2027-01-15 08:00:00 UTC

    func testNeverIsNil() throws {
        XCTAssertNil(try ExpiryChoice.never.resolve(now: now, calendar: cal))
    }

    func testShortcutsAreNowPlusDays() throws {
        for n in ExpiryChoice.shortcuts {
            XCTAssertEqual(try ExpiryChoice.inDays(n).resolve(now: now, calendar: cal), now.addingTimeInterval(Double(n) * 86_400))
        }
        XCTAssertEqual(ExpiryChoice.shortcuts, [7, 30, 90])
    }

    func testPickedDateMeansEndOfThatDayLocalTime() throws {
        let picked = now.addingTimeInterval(3 * 86_400)
        let d = try XCTUnwrap(try ExpiryChoice.date(picked).resolve(now: now, calendar: cal))
        let parts = cal.dateComponents([.hour, .minute, .second], from: d)
        XCTAssertEqual(parts.hour, 23)
        XCTAssertEqual(parts.minute, 59)
        XCTAssertEqual(parts.second, 59)
        XCTAssertTrue(cal.isDate(d, inSameDayAs: picked))
    }

    func testTodayIsStillAllowedWhenEndOfDayIsAMinuteAway() throws {
        // 23:58:30 local: the end of today is 90 s away, so it is valid.
        let late = try XCTUnwrap(cal.date(from: DateComponents(year: 2027, month: 1, day: 15, hour: 23, minute: 58, second: 30)))
        XCTAssertNoThrow(try ExpiryChoice.date(late).resolve(now: late, calendar: cal))
        // 23:59:30: less than a minute left.
        let later = late.addingTimeInterval(60)
        XCTAssertThrowsError(try ExpiryChoice.date(later).resolve(now: later, calendar: cal)) {
            XCTAssertEqual($0 as? ExpiryError, .notInFuture)
        }
    }

    func testPastDateFails() {
        XCTAssertThrowsError(try ExpiryChoice.date(now.addingTimeInterval(-2 * 86_400)).resolve(now: now, calendar: cal)) {
            XCTAssertEqual($0 as? ExpiryError, .notInFuture)
        }
    }

    func testCustomUsesTheCLIParserAndTheMinimumLead() throws {
        XCTAssertEqual(try ExpiryChoice.custom("12h").resolve(now: now, calendar: cal), now.addingTimeInterval(43_200))
        XCTAssertThrowsError(try ExpiryChoice.custom("30s").resolve(now: now, calendar: cal)) {
            XCTAssertEqual($0 as? ExpiryError, .notInFuture)
        }
        XCTAssertThrowsError(try ExpiryChoice.custom("zzz").resolve(now: now, calendar: cal)) {
            XCTAssertEqual($0 as? ExpiryError, .invalid)
        }
        XCTAssertNoThrow(try ExpiryChoice.custom("60s").resolve(now: now, calendar: cal))
    }
}

final class ExpiryFormatterTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func testRelativeForms() {
        XCTAssertNil(ExpiryFormatter.relative(nil, now: now))
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(12.5 * 86_400), now: now), "in 12 d")
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(86_400), now: now), "in 1 d")
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(23 * 3600 + 59 * 60), now: now), "in 23 h")
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(20 * 60 + 5), now: now), "in 20 min")
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(30), now: now), "in <1 min")
        XCTAssertEqual(ExpiryFormatter.relative(now, now: now), "expired")
        XCTAssertEqual(ExpiryFormatter.relative(now.addingTimeInterval(-5), now: now), "expired")
    }

    func testStates() {
        XCTAssertEqual(ExpiryFormatter.state(nil, now: now), .none)
        XCTAssertEqual(ExpiryFormatter.state(now.addingTimeInterval(8 * 86_400), now: now), .later)
        XCTAssertEqual(ExpiryFormatter.state(now.addingTimeInterval(6.9 * 86_400), now: now), .soon)
        XCTAssertEqual(ExpiryFormatter.state(now.addingTimeInterval(7 * 86_400), now: now), .later)
        XCTAssertEqual(ExpiryFormatter.state(now.addingTimeInterval(1), now: now), .soon)
        XCTAssertEqual(ExpiryFormatter.state(now, now: now), .expired)
    }

    func testSentences() {
        XCTAssertEqual(ExpiryFormatter.sentence(nil, now: now), "Never expires")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(3.2 * 86_400), now: now), "Expires in 3 days")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(1.5 * 86_400), now: now), "Expires in 1 day")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(5 * 3600 + 5), now: now), "Expires in 5 hours")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(61), now: now), "Expires in 1 minute")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(10), now: now), "Expires in less than a minute")
        XCTAssertEqual(ExpiryFormatter.sentence(now.addingTimeInterval(-1), now: now), "Expired")
    }
}
