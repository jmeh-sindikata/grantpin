import Foundation
import XCTest
@testable import GrantdKit

final class ConnectSnippetTests: XCTestCase {
    let plain = "/Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd"

    func testTheExactCommands() {
        XCTAssertEqual(ConnectSnippets.command(scope: .allProjects, helper: plain),
                       "claude mcp add --scope user grantd -- /Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd mcp")
        XCTAssertEqual(ConnectSnippets.command(scope: .oneProject, helper: plain),
                       "claude mcp add grantd -- /Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd mcp")
        XCTAssertEqual(ConnectSnippets.removeCommand, "claude mcp remove grantd")
    }

    func testTheExactJSONForTheDefaultPath() {
        XCTAssertEqual(ConnectSnippets.mcpJSON(helper: plain), """
        {
          "mcpServers": {
            "grantd": {
              "command": "/Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd",
              "args": ["mcp"]
            }
          }
        }
        """)
    }

    func testQuotingRules() {
        XCTAssertEqual(ConnectSnippets.shellQuote("/a/b_c-d.e/f"), "/a/b_c-d.e/f")
        XCTAssertEqual(ConnectSnippets.shellQuote("/My Apps/grantd"), "'/My Apps/grantd'")
        XCTAssertEqual(ConnectSnippets.shellQuote("/it's/grantd"), "'/it'\\''s/grantd'")
        XCTAssertEqual(ConnectSnippets.shellQuote(""), "''")
        XCTAssertEqual(ConnectSnippets.shellQuote("/a\"b"), "'/a\"b'")
    }

    static let awkward = [
        "/Applications/grantd.app/x", "/Users/me/My Apps/grantd.app/x", "/Users/o'brien/Apps/grantd.app/x",
        "/tmp/a\"b/x", "/tmp/a\\b/x", "/tmp/$HOME/`x`/$(y)/x", "/tmp/a b'c\"d\\e/x", "/tmp/;rm -rf/x", "/tmp/ünï/日本/x",
        "/tmp/-leading", "/tmp/a*b?c[d]/x", "/tmp/new\nline/x",
    ]

    /// The quoted path, run through a real shell, comes back as the same path.
    func testShellQuotingRoundTripsThroughSh() throws {
        for path in Self.awkward {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", "printf %s \(ConnectSnippets.shellQuote(path))"]
            let out = Pipe()
            p.standardOutput = out
            try p.run()
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            XCTAssertEqual(String(decoding: data, as: UTF8.self), path, path.debugDescription)
        }
    }

    /// The whole command, split by a real shell, has the helper as one argument.
    func testTheCommandIsOneArgumentPerPart() throws {
        for path in Self.awkward {
            let cmd = ConnectSnippets.command(scope: .allProjects, helper: path)
            let script = "set -- \(cmd.replacingOccurrences(of: "claude mcp add ", with: "")); for a; do printf '%s\\0' \"$a\"; done"
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", script]
            let out = Pipe()
            p.standardOutput = out
            try p.run()
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let parts = String(decoding: data, as: UTF8.self).split(separator: "\0", omittingEmptySubsequences: false).dropLast().map(String.init)
            XCTAssertEqual(parts, ["--scope", "user", "grantd", "--", path, "mcp"], path.debugDescription)
        }
    }

    func testJSONRoundTrips() throws {
        for path in Self.awkward {
            let text = ConnectSnippets.mcpJSON(helper: path)
            let obj = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
            let server = ((obj?["mcpServers"] as? [String: Any])?["grantd"]) as? [String: Any]
            XCTAssertEqual(server?["command"] as? String, path, path.debugDescription)
            XCTAssertEqual(server?["args"] as? [String], ["mcp"])
            XCTAssertEqual((obj?["mcpServers"] as? [String: Any])?.count, 1)
        }
        XCTAssertFalse(ConnectSnippets.mcpJSON(helper: plain).contains("\\/"), "slashes are not escaped")
        XCTAssertFalse(ConnectSnippets.mcpJSON(helper: plain).contains("env"), "no environment variable or password")
    }

    func testTextsAreTheSpecs() {
        XCTAssertEqual(ConnectSnippets.testPrompt, "Use grantd's secret_list tool and tell me the names of my secrets.")
        XCTAssertEqual(ConnectSnippets.testPromptCaption, "Claude will see names only, never values. To see an approval, ask it to run a command with a secret.")
        XCTAssertEqual(ConnectSnippets.restartNote, "Claude Code must be restarted, or run /mcp, to pick up the new server.")
        XCTAssertEqual(ConnectSnippets.jsonCaption, "Put this in a file named .mcp.json in your project's folder. It contains a path on your Mac, so don't commit it to a shared repository.")
        XCTAssertEqual(ConnectSnippets.oldPathCallout, "Already connected with an older path? Run claude mcp remove grantd first, then the command above.")
        XCTAssertEqual(ConnectSnippets.toolNames, ["secret_list", "secret_exists", "secret_masked", "secret_run"])
    }

    func testDefaultHelperPath() {
        XCTAssertEqual(ConnectSnippets.defaultHelperPath(bundleURL: URL(fileURLWithPath: "/Applications/grantd.app")), plain)
    }
}

final class ConnectionTestTests: XCTestCase {
    struct Fake: ExistsService {
        var answer: Result<Bool, Error>
        func exists(_ name: String) async throws -> Bool { try answer.get() }
    }

    func testAnswered() async {
        for exists in [true, false] {
            let r = await ConnectionTest.run(Fake(answer: .success(exists)))
            XCTAssertEqual(r, .answered)
            XCTAssertEqual(r.text, "grantd answered. Claude Code asks it the same way.")
        }
    }

    func testFailuresAreMapped() async {
        let down = await ConnectionTest.run(Fake(answer: .failure(GrantdError.notRunning)))
        XCTAssertEqual(down.text, "grantd is not running. Start it from the menu bar item.")
        let novault = await ConnectionTest.run(Fake(answer: .failure(daemonError(.failed, .vaultNotInitialized))))
        XCTAssertEqual(novault.text, "Create your vault first.")
    }

    func testTheProbeNameIsValid() {
        XCTAssertNil(Validators.nameIssue(ConnectionTest.probeName))
    }
}

final class AppLocationTests: XCTestCase {
    let home = URL(fileURLWithPath: "/Users/me")

    func testLocations() {
        func loc(_ p: String) -> AppLocation { AppLocation.check(bundleURL: URL(fileURLWithPath: p), home: home) }
        XCTAssertEqual(loc("/Applications/grantd.app"), .ok)
        XCTAssertEqual(loc("/Users/me/Applications/grantd.app"), .ok)
        XCTAssertEqual(loc("/Applications/Utilities/grantd.app"), .ok)
        XCTAssertEqual(loc("/Users/me/Downloads/grantd.app"), .elsewhere)
        XCTAssertEqual(loc("/Volumes/grantd/grantd.app"), .elsewhere)
        XCTAssertEqual(loc("/Users/me/Desktop/projects/Secrets/dist/grantd.app"), .elsewhere)
        XCTAssertEqual(loc("/private/var/folders/xx/AppTranslocation/ABC/d/grantd.app"), .translocated)
        XCTAssertEqual(loc("/Applications"), .elsewhere, "the folder itself is not an app in it")
        XCTAssertEqual(loc("/ApplicationsEvil/grantd.app"), .elsewhere)
        XCTAssertEqual(loc("/Users/other/Applications/grantd.app"), .elsewhere)
        XCTAssertEqual(AppLocation.blockedMessage, "Move grantd to your Applications folder first")
        XCTAssertEqual(AppLocation.moveButton, "Move to Applications and Relaunch")
    }

    func testCopyUsesTheFirstDestinationThatWorksAndNeverReplaces() throws {
        let t = try TempDir()
        let src = try t.file("Downloads/grantd.app/Contents/Info.plist").deletingLastPathComponent().deletingLastPathComponent()
        let dest1 = t.url.appendingPathComponent("A/grantd.app")
        let dest2 = t.url.appendingPathComponent("B/grantd.app")
        let moved = try AppLocation.copyToApplications(bundleURL: src, destinations: [dest1, dest2])
        XCTAssertEqual(moved, dest1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest1.appendingPathComponent("Contents/Info.plist").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: src.path), "the original stays")
        // an existing app is never replaced; the next destination is used
        let again = try AppLocation.copyToApplications(bundleURL: src, destinations: [dest1, dest2])
        XCTAssertEqual(again, dest2)
        XCTAssertThrowsError(try AppLocation.copyToApplications(bundleURL: src, destinations: [dest1, dest2])) {
            guard case AppLocation.MoveError.alreadyThere = $0 else { return XCTFail("\($0)") }
        }
    }

    func testCopyFailureIsReported() throws {
        let t = try TempDir()
        XCTAssertThrowsError(try AppLocation.copyToApplications(bundleURL: t.url.appendingPathComponent("missing.app"),
                                                                 destinations: [t.url.appendingPathComponent("X/missing.app")])) {
            XCTAssertEqual($0 as? AppLocation.MoveError, .failed)
        }
    }

    /// Copies part of the bundle and then fails, like a full disk.
    private final class HalfCopyingFileManager: FileManager {
        override func copyItem(at srcURL: URL, to dstURL: URL) throws {
            try createDirectory(at: dstURL.appendingPathComponent("Contents"), withIntermediateDirectories: true)
            try "partial".write(to: dstURL.appendingPathComponent("Contents/Info.plist"), atomically: true, encoding: .utf8)
            throw CocoaError(.fileWriteOutOfSpace)
        }
    }

    func testAFailedCopyLeavesNoHalfCopiedBundleAndNoTemporaryFolder() throws {
        let t = try TempDir()
        let src = try t.file("Downloads/grantd.app/Contents/Info.plist").deletingLastPathComponent().deletingLastPathComponent()
        let dest = t.url.appendingPathComponent("Apps/grantd.app")
        XCTAssertThrowsError(try AppLocation.copyToApplications(bundleURL: src, destinations: [dest], fileManager: HalfCopyingFileManager())) {
            XCTAssertEqual($0 as? AppLocation.MoveError, .failed)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
        let left = (try? FileManager.default.contentsOfDirectory(atPath: dest.deletingLastPathComponent().path)) ?? []
        XCTAssertEqual(left, [], "the temporary copy is removed")
    }

    func testTheBundleAppearsOnlyWhole() throws {
        let t = try TempDir()
        let src = try t.file("Downloads/grantd.app/Contents/Info.plist").deletingLastPathComponent().deletingLastPathComponent()
        let dest = t.url.appendingPathComponent("Apps/grantd.app")
        _ = try AppLocation.copyToApplications(bundleURL: src, destinations: [dest])
        let names = try FileManager.default.contentsOfDirectory(atPath: dest.deletingLastPathComponent().path)
        XCTAssertEqual(names, ["grantd.app"], "no temporary name remains after the rename")
    }

    func testARaceWithAnAppOfTheSameNameIsNotReplaced() throws {
        // The destination appears between the check and the rename.
        final class RacingFileManager: FileManager {
            override func copyItem(at srcURL: URL, to dstURL: URL) throws {
                try super.copyItem(at: srcURL, to: dstURL)
                let target = dstURL.deletingLastPathComponent().appendingPathComponent("grantd.app")
                try createDirectory(at: target, withIntermediateDirectories: true)
                try "theirs".write(to: target.appendingPathComponent("marker"), atomically: true, encoding: .utf8)
            }
        }
        let t = try TempDir()
        let src = try t.file("Downloads/grantd.app/Contents/Info.plist").deletingLastPathComponent().deletingLastPathComponent()
        let dest = t.url.appendingPathComponent("Apps/grantd.app")
        XCTAssertThrowsError(try AppLocation.copyToApplications(bundleURL: src, destinations: [dest], fileManager: RacingFileManager())) {
            guard case AppLocation.MoveError.alreadyThere = $0 else { return XCTFail("\($0)") }
        }
        XCTAssertEqual(try String(contentsOf: dest.appendingPathComponent("marker"), encoding: .utf8), "theirs")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dest.deletingLastPathComponent().path), ["grantd.app"])
    }

    func testDestinationsPreferTheSystemFolder() {
        let d = AppLocation.destinations(bundleName: "grantd.app", home: home)
        XCTAssertEqual(d.map(\.path), ["/Applications/grantd.app", "/Users/me/Applications/grantd.app"])
    }
}
