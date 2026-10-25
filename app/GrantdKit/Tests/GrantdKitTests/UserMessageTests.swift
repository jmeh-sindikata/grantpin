import Foundation
import XCTest
@testable import GrantdKit

final class UserMessageTests: XCTestCase {
    func d(_ c: ErrorCategory, _ r: ErrorReason, _ m: String = "") -> UserMessage {
        UserMessage.from(GrantdError.daemon(category: c, reason: r, message: m))
    }

    func testSpecTable() {
        XCTAssertEqual(d(.failed, .vaultNotInitialized).headline, "Create your vault first.")
        XCTAssertEqual(d(.failed, .vaultNotInitialized).action, .setUp)
        XCTAssertEqual(d(.badRequest, .secretExists).headline, "A secret with this name already exists.")
        XCTAssertEqual(d(.notFound, .secretNotFound).headline, "That secret no longer exists.")
        XCTAssertTrue(d(.notFound, .secretNotFound).refreshAdvised)
        XCTAssertEqual(d(.notFound, .grantNotFound).headline, "That grant is already gone.")
        XCTAssertEqual(d(.denied, .userDenied).headline, "You cancelled the confirmation.")
        XCTAssertEqual(d(.denied, .approverUnavailable).headline,
                       "grantd could not show the confirmation dialog. Make sure you are logged in at this Mac and have a device password, then try again.")
        XCTAssertEqual(d(.refused, .policyRefused, "no").headline, "A .grantd.yml file in that folder does not allow this.")
        XCTAssertEqual(d(.refused, .policyRefused, "no").detail, "no")
        XCTAssertEqual(d(.refused, .tierUnmet).headline, "This secret needs a stronger protection level than this vault provides.")
        XCTAssertEqual(d(.refused, .secretExpired).headline, "That secret has expired.")
        XCTAssertEqual(d(.badRequest, .badRequest, "value too large").headline, "grantd rejected the request:")
        XCTAssertEqual(d(.badRequest, .badRequest, "value too large").detail, "value too large")
        XCTAssertEqual(d(.badRequest, .unsupportedVersion).headline, "This app and the background service are out of step. Use Repair in Settings.")
        XCTAssertEqual(d(.failed, .canceled).headline, "The request was cancelled.")
        XCTAssertEqual(d(.failed, .timeout).headline, "grantd took too long to answer.")
        XCTAssertEqual(d(.failed, .internalError).headline, "grantd had an internal error. Details are in the log.")
        XCTAssertEqual(d(.failed, .internalError).action, .openLogs)
    }

    func testUnknownReasonFallsBackToTheCategory() {
        XCTAssertEqual(d(.denied, .unknown("zzz")).headline, "grantd said no.")
        XCTAssertEqual(d(.refused, .unknown("zzz")).headline, "grantd refused this.")
        XCTAssertEqual(d(.badRequest, .unknown("zzz")).headline, "grantd rejected this request.")
        XCTAssertEqual(d(.notFound, .unknown("zzz")).headline, "Not found.")
        XCTAssertEqual(d(.failed, .unknown("zzz")).headline, "grantd could not finish this.")
        XCTAssertEqual(d(.unknown("new"), .absent).headline, "grantd could not finish this.")
    }

    func testLockedVault() {
        XCTAssertEqual(d(.failed, .vaultLocked).headline, "Unlock your Mac to use secrets.")
    }

    func testLocalErrors() {
        XCTAssertEqual(UserMessage.from(GrantdError.timeout).headline, "grantd took too long to answer.")
        XCTAssertEqual(UserMessage.from(GrantdError.notRunning).headline, "grantd is not running.")
        XCTAssertEqual(UserMessage.from(GrantdError.requestTooLarge).headline, "That is too large to send.")
        XCTAssertEqual(UserMessage.from(CancellationError()).headline, "The request was cancelled.")
        XCTAssertEqual(UserMessage.from(NSError(domain: "x", code: 1)).headline, "grantd could not finish this.")
    }

    func testDaemonTextIsSanitised() {
        let m = d(.badRequest, .badRequest, "bad \u{1B}[31m name \u{202E}")
        XCTAssertFalse(m.detail?.unicodeScalars.contains("\u{1B}") ?? true)
        XCTAssertFalse(m.detail?.unicodeScalars.contains("\u{202E}") ?? true)
    }
}

final class ConfirmationTests: XCTestCase {
    func testDeleteOne() {
        let c = Confirmation.delete(names: ["aws/key"])
        XCTAssertEqual(c.title, "Delete \"aws/key\"?")
        XCTAssertEqual(c.message, "This permanently deletes the secret and its value from this Mac. Programs and agents that ask for it will get \"secret not found\". This can't be undone.")
        XCTAssertEqual(c.confirmLabel, "Delete")
    }

    func testDeleteOneWithGrants() {
        XCTAssertTrue(Confirmation.delete(names: ["a"], grantsMentioning: 2).message.hasSuffix(
            "\n\n2 active grants mention this secret. They stay in place but won't work until you add it again."))
        XCTAssertTrue(Confirmation.delete(names: ["a"], grantsMentioning: 1).message.hasSuffix(
            "\n\n1 active grant mentions this secret. It stays in place but won't work until you add it again."))
        XCTAssertFalse(Confirmation.delete(names: ["a"], grantsMentioning: 0).message.contains("active grant"))
    }

    func testDeleteMany() {
        let c = Confirmation.delete(names: ["a", "b", "c"])
        XCTAssertEqual(c.title, "Delete 3 secrets?")
        XCTAssertEqual(c.message, "This permanently deletes 3 secrets and their values from this Mac. This can't be undone.")
    }

    func testReplace() {
        let c = Confirmation.replace(name: "aws/key")
        XCTAssertEqual(c.title, "Replace \"aws/key\"?")
        XCTAssertEqual(c.message, "The current value will be overwritten. It can't be recovered.")
        XCTAssertEqual(c.confirmLabel, "Replace")
    }

    func testImportOverwriteListsTenNamesThenMore() {
        let names = (1...12).map { "N\($0)" }
        let c = Confirmation.importOverwrite(names: names)
        XCTAssertEqual(c.title, "Overwrite 12 existing secrets?")
        XCTAssertEqual(c.message, "These secrets will get the values from the file: N1, N2, N3, N4, N5, N6, N7, N8, N9, N10 and 2 more. The old values can't be recovered.")
        XCTAssertEqual(c.confirmLabel, "Overwrite")
        let three = Confirmation.importOverwrite(names: ["A", "B", "C"])
        XCTAssertEqual(three.message, "These secrets will get the values from the file: A, B, C. The old values can't be recovered.")
        XCTAssertEqual(Confirmation.importOverwrite(names: ["A"]).title, "Overwrite 1 existing secret?")
    }

    func testNamesInTitlesAreSanitised() {
        XCTAssertFalse(Confirmation.delete(names: ["a\u{202E}b"]).title.unicodeScalars.contains("\u{202E}"))
    }
}
