import Foundation
import XCTest
@testable import GrantpinKit

/// Everything runs in a temporary folder: a fake home and a fake app bundle.
/// The real home folder and the real `~/.local/bin` are never touched.
final class CommandLineToolTests: XCTestCase {
    var temp: TempDir!
    var home: URL { temp.url.appendingPathComponent("home", isDirectory: true) }
    var bundle: URL { temp.url.appendingPathComponent("Applications/grantpin.app", isDirectory: true) }
    var helper: URL!
    var link: URL { home.appendingPathComponent(".local/bin/grantpin") }
    let fm = FileManager.default

    override func setUpWithError() throws {
        temp = try TempDir()
        try fm.createDirectory(at: home, withIntermediateDirectories: true)
        helper = try temp.file("Applications/grantpin.app/" + HelperLocator.relativePath, "#!/bin/sh\n")
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    }

    func tool(path: String? = nil, helper: URL?? = nil) -> CommandLineTool {
        CommandLineTool(home: home, bundleURL: bundle, helper: helper ?? self.helper, searchPath: path)
    }

    func destination(_ url: URL) -> String? { try? fm.destinationOfSymbolicLink(atPath: url.path) }
    func mode(_ url: URL) -> Int? { (try? fm.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int }

    func plantLink(to target: String) throws {
        try fm.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: target)
    }

    // MARK: install

    func testFreshInstallCreatesTheFoldersAndTheLink() {
        let t = tool()
        XCTAssertEqual(t.linkState(), .absent)
        XCTAssertEqual(t.install(), .installed(link.path))
        XCTAssertEqual(destination(link), helper.path)
        XCTAssertEqual(mode(home.appendingPathComponent(".local")), 0o755)
        XCTAssertEqual(mode(home.appendingPathComponent(".local/bin")), 0o755)
        XCTAssertEqual(t.linkState(), .ours)
        XCTAssertEqual(t.status(), .installed(link.path))
        XCTAssertTrue(fm.isExecutableFile(atPath: link.path), "the link reaches the helper")
    }

    func testInstallKeepsAnExistingFolderAsItIs() throws {
        let bin = home.appendingPathComponent(".local/bin")
        try fm.createDirectory(at: bin, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        XCTAssertEqual(tool().install(), .installed(link.path))
        XCTAssertEqual(mode(bin), 0o700, "a folder that was already there keeps its mode")
    }

    func testInstallIsIdempotent() {
        let t = tool()
        _ = t.install()
        let again = t.install()
        XCTAssertEqual(again, .alreadyInstalled(link.path))
        XCTAssertTrue(again.isSuccess)
        XCTAssertEqual(destination(link), helper.path)
    }

    func testARelativeLinkToTheHelperCountsAsOurs() throws {
        let relative = "../../../Applications/grantpin.app/" + HelperLocator.relativePath
        try plantLink(to: relative)
        XCTAssertEqual(tool().linkState(), .ours)
        XCTAssertEqual(tool().install(), .alreadyInstalled(link.path))
    }

    func testInstallRefusesToReplaceARegularFile() throws {
        _ = try temp.file("home/.local/bin/grantpin", "mine")
        let r = tool().install()
        guard case .refused(let text) = r else { return XCTFail("\(r)") }
        XCTAssertFalse(r.isSuccess)
        XCTAssertTrue(text.contains(link.path), "the message names the path")
        XCTAssertEqual(try String(contentsOf: link, encoding: .utf8), "mine")
        XCTAssertEqual(tool().linkState(), .notALink)
    }

    func testInstallRefusesToReplaceAFolder() throws {
        try fm.createDirectory(at: link, withIntermediateDirectories: true)
        guard case .refused = tool().install() else { return XCTFail() }
        var isDir: ObjCBool = false
        XCTAssertTrue(fm.fileExists(atPath: link.path, isDirectory: &isDir) && isDir.boolValue)
    }

    func testInstallRefusesToReplaceALinkToElsewhere() throws {
        try plantLink(to: "/opt/homebrew/bin/grantpin")
        let r = tool().install()
        guard case .refused(let text) = r else { return XCTFail("\(r)") }
        XCTAssertTrue(text.contains(link.path))
        XCTAssertTrue(text.contains("/opt/homebrew/bin/grantpin"), "the message names where it points")
        XCTAssertEqual(destination(link), "/opt/homebrew/bin/grantpin")
        XCTAssertEqual(tool().linkState(), .elsewhere("/opt/homebrew/bin/grantpin"))
    }

    func testInstallRefusesToReplaceADanglingLink() throws {
        try plantLink(to: temp.url.appendingPathComponent("gone").path)
        guard case .refused = tool().install() else { return XCTFail() }
        XCTAssertNotNil(destination(link))
    }

    func testALinkWithDotDotOutOfTheBundleIsNotInsideIt() throws {
        try plantLink(to: bundle.path + "/Contents/../../elsewhere")
        guard case .elsewhere = tool().linkState() else { return XCTFail("\(tool().linkState())") }
    }

    func testALinkToAnotherFileInTheBundleIsNotTheHelperButIsTheApps() throws {
        let other = bundle.path + "/Contents/MacOS/old"
        try plantLink(to: other)
        XCTAssertEqual(tool().linkState(), .otherInBundle(other))
        guard case .refused = tool().install() else { return XCTFail() }
        XCTAssertEqual(destination(link), other)
    }

    func testInstallFailsWhenAFileIsInTheWayOfTheFolder() throws {
        _ = try temp.file("home/.local", "a file")
        guard case .failed = tool().install() else { return XCTFail() }
        XCTAssertEqual(try String(contentsOf: home.appendingPathComponent(".local"), encoding: .utf8), "a file")
    }

    func testInstallWithoutAHelperChangesNothing() {
        let t = CommandLineTool(home: home, bundleURL: bundle, helper: nil)
        guard case .refused = t.install() else { return XCTFail() }
        XCTAssertFalse(fm.fileExists(atPath: home.appendingPathComponent(".local").path))
    }

    // MARK: remove

    func testRemoveDeletesOurLinkAndNotTheHelper() {
        let t = tool()
        _ = t.install()
        XCTAssertEqual(t.remove(), .removed(link.path))
        XCTAssertEqual(t.linkState(), .absent)
        XCTAssertTrue(fm.fileExists(atPath: helper.path), "the program in the app stays")
    }

    func testRemoveWithNothingThereSaysSo() {
        let r = tool().remove()
        XCTAssertEqual(r, .nothingToRemove)
        XCTAssertTrue(r.isSuccess)
    }

    func testRemoveLeavesAFileAlone() throws {
        _ = try temp.file("home/.local/bin/grantpin", "mine")
        guard case .refused = tool().remove() else { return XCTFail() }
        XCTAssertEqual(try String(contentsOf: link, encoding: .utf8), "mine")
    }

    func testRemoveLeavesALinkToElsewhereAlone() throws {
        try plantLink(to: "/opt/homebrew/bin/grantpin")
        guard case .refused = tool().remove() else { return XCTFail() }
        XCTAssertEqual(destination(link), "/opt/homebrew/bin/grantpin")
    }

    func testRemoveTakesALinkToAnotherFileInTheBundle() throws {
        try plantLink(to: bundle.path + "/Contents/MacOS/old")
        XCTAssertEqual(tool().remove(), .removed(link.path))
        XCTAssertEqual(tool().linkState(), .absent)
    }

    // MARK: the PATH

    func testFolderOnPathDetection() throws {
        let bin = home.appendingPathComponent(".local/bin").path
        try fm.createDirectory(atPath: bin, withIntermediateDirectories: true)
        XCTAssertEqual(tool(path: "/usr/bin:\(bin):/bin").folderIsOnPath, true)
        XCTAssertEqual(tool(path: "/usr/bin:\(bin)/:/bin").folderIsOnPath, true, "a trailing slash is the same folder")
        XCTAssertEqual(tool(path: "/usr/bin:/bin:/opt/homebrew/bin").folderIsOnPath, false)
        XCTAssertEqual(tool(path: "").folderIsOnPath, false)
        XCTAssertEqual(tool(path: "/usr/bin::\(bin)").folderIsOnPath, true, "empty elements are ignored")
        XCTAssertNil(tool(path: nil).folderIsOnPath, "an unknown PATH is not 'missing'")
    }

    func testFolderOnPathThroughASymlinkedFolder() throws {
        try fm.createDirectory(at: home.appendingPathComponent(".local/bin"), withIntermediateDirectories: true)
        let alias = temp.url.appendingPathComponent("alias")
        try fm.createSymbolicLink(atPath: alias.path, withDestinationPath: home.appendingPathComponent(".local/bin").path)
        XCTAssertEqual(tool(path: "/usr/bin:\(alias.path)").folderIsOnPath, true)
    }

    func testAShellPathLineForEachShell() {
        XCTAssertEqual(CommandLineTool.pathLine(forShell: "/bin/zsh"), "export PATH=\"$HOME/.local/bin:$PATH\"")
        XCTAssertEqual(CommandLineTool.pathLine(forShell: "/bin/bash"), "export PATH=\"$HOME/.local/bin:$PATH\"")
        XCTAssertEqual(CommandLineTool.pathLine(forShell: "/opt/homebrew/bin/fish"), "fish_add_path ~/.local/bin")
        XCTAssertEqual(CommandLineTool.pathLine(forShell: "/usr/local/bin/fish"), "fish_add_path ~/.local/bin")
    }

    // MARK: another grantpin on the PATH

    func makeBin(_ name: String) throws -> URL {
        let dir = temp.url.appendingPathComponent(name, isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testAHomebrewLinkToThisAppIsRecognised() throws {
        let brew = try makeBin("brew")
        try fm.createSymbolicLink(atPath: brew.appendingPathComponent("grantpin").path, withDestinationPath: helper.path)
        let t = tool(path: "/usr/bin:\(brew.path)")
        XCTAssertEqual(t.firstOnPath(), .thisApp(brew.appendingPathComponent("grantpin").path))
        XCTAssertEqual(t.status(), .onPath(.thisApp(brew.appendingPathComponent("grantpin").path)))
    }

    func testADifferentGrantpinOnThePathIsReported() throws {
        let other = try makeBin("other")
        let exe = other.appendingPathComponent("grantpin")
        try "#!/bin/sh\n".write(to: exe, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        XCTAssertEqual(tool(path: other.path).firstOnPath(), .another(exe.path))
        XCTAssertEqual(tool(path: other.path).status(), .onPath(.another(exe.path)))
    }

    func testTheFirstGrantpinOnThePathWins() throws {
        let a = try makeBin("a"), b = try makeBin("b")
        for dir in [a, b] {
            let exe = dir.appendingPathComponent("grantpin")
            try "#!/bin/sh\n".write(to: exe, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        }
        XCTAssertEqual(tool(path: "\(a.path):\(b.path)").firstOnPath(), .another(a.appendingPathComponent("grantpin").path))
    }

    func testNothingOnThePathMeansNotInstalled() throws {
        let empty = try makeBin("empty")
        XCTAssertNil(tool(path: empty.path).firstOnPath())
        XCTAssertEqual(tool(path: empty.path).status(), .notInstalled)
        XCTAssertNil(tool(path: nil).firstOnPath())
    }

    func testAFileThatIsNotExecutableOrIsAFolderIsNotACommand() throws {
        let plain = try makeBin("plain")
        _ = try temp.file("plain/grantpin", "text")
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: plain.appendingPathComponent("grantpin").path)
        let folder = try makeBin("folder")
        try fm.createDirectory(at: folder.appendingPathComponent("grantpin"), withIntermediateDirectories: true)
        XCTAssertNil(tool(path: "\(plain.path):\(folder.path)").firstOnPath())
    }

    func testOurLinkTakesPrecedenceOverTheRestOfThePath() throws {
        let brew = try makeBin("brew")
        try fm.createSymbolicLink(atPath: brew.appendingPathComponent("grantpin").path, withDestinationPath: helper.path)
        let t = tool(path: brew.path)
        _ = t.install()
        XCTAssertEqual(t.status(), .installed(link.path))
    }

    func testABlockerIsReportedAsBlockedEvenWithAGrantpinOnThePath() throws {
        _ = try temp.file("home/.local/bin/grantpin", "mine")
        let brew = try makeBin("brew")
        try fm.createSymbolicLink(atPath: brew.appendingPathComponent("grantpin").path, withDestinationPath: helper.path)
        XCTAssertEqual(tool(path: brew.path).status(), .blocked(path: link.path, state: .notALink))
    }
}

@MainActor
final class CommandLineToolModelTests: XCTestCase {
    var temp: TempDir!
    var home: URL { temp.url.appendingPathComponent("home", isDirectory: true) }
    var bundle: URL { temp.url.appendingPathComponent("Applications/grantpin.app", isDirectory: true) }
    var helper: URL!
    var link: URL { home.appendingPathComponent(".local/bin/grantpin") }

    override func setUpWithError() throws {
        temp = try TempDir()
        helper = try temp.file("Applications/grantpin.app/" + HelperLocator.relativePath, "#!/bin/sh\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    func model(location: AppLocation = .ok, dev: Bool = false, hasHelper: Bool = true, shell: String = "/bin/zsh",
               path: String = "/usr/bin:/bin") -> CommandLineToolModel {
        CommandLineToolModel(
            tool: CommandLineTool(home: home, bundleURL: bundle, helper: hasHelper ? helper : nil),
            location: location, isDevelopment: dev, shell: shell, detectPath: { path })
    }

    func testTheStatusTexts() async throws {
        let m = model()
        XCTAssertEqual(m.statusText, "Not installed")
        XCTAssertTrue(m.canInstall)
        XCTAssertFalse(m.canRemove)
        m.install()
        XCTAssertEqual(m.statusText, "Installed at \(link.path)")
        XCTAssertFalse(m.canInstall, "installed: the button shows as done")
        XCTAssertTrue(m.canRemove)
        XCTAssertEqual(m.result, .installed(link.path))
        XCTAssertTrue(m.statusIsOK)
        m.remove()
        XCTAssertEqual(m.statusText, "Not installed")
        XCTAssertEqual(m.result, .removed(link.path))
    }

    func testAnotherGrantpinOnThePath() async throws {
        let brew = temp.url.appendingPathComponent("brew")
        try FileManager.default.createDirectory(at: brew, withIntermediateDirectories: true)
        let exe = brew.appendingPathComponent("grantpin")
        try FileManager.default.createSymbolicLink(atPath: exe.path, withDestinationPath: helper.path)
        let m = model(path: "/usr/bin:\(brew.path)")
        await m.refresh()
        XCTAssertEqual(m.statusText, "Another grantpin is already on your PATH at \(exe.path)")
        XCTAssertEqual(m.statusNote, CommandLineToolModel.onPathThisAppNote)
        XCTAssertFalse(m.canInstall, "it resolves to this app: no install button needed")
        XCTAssertTrue(m.statusIsOK)
    }

    func testAForeignGrantpinOnThePathStillAllowsInstall() async throws {
        let other = temp.url.appendingPathComponent("other")
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        let exe = other.appendingPathComponent("grantpin")
        try "#!/bin/sh\n".write(to: exe, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        let m = model(path: other.path)
        await m.refresh()
        XCTAssertEqual(m.statusNote, CommandLineToolModel.onPathAnotherNote)
        XCTAssertTrue(m.canInstall)
    }

    func testABlockerDisablesInstallAndNamesThePath() throws {
        _ = try temp.file("home/.local/bin/grantpin", "mine")
        let m = model()
        XCTAssertFalse(m.canInstall)
        XCTAssertTrue(m.statusIsProblem)
        XCTAssertTrue(m.statusText.contains(link.path))
        m.install()
        XCTAssertNil(m.result, "the button does nothing when it is off")
        XCTAssertEqual(try String(contentsOf: link, encoding: .utf8), "mine")
        XCTAssertFalse(m.canRemove, "not ours: no Remove button")
    }

    func testOutsideApplicationsInstallIsOffAndNothingIsWritten() {
        for location in [AppLocation.translocated, .elsewhere] {
            let m = model(location: location)
            XCTAssertFalse(m.canInstall)
            XCTAssertEqual(m.disabledReason, CommandLineToolModel.temporaryLocationWarning)
            m.install()
            XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".local").path))
        }
    }

    func testDevelopmentModeAndNoHelperDisable() {
        XCTAssertEqual(model(dev: true).disabledReason, CommandLineToolModel.developmentNote)
        XCTAssertFalse(model(dev: true).canInstall)
        XCTAssertEqual(model(hasHelper: false).disabledReason, CommandLineToolModel.noHelperNote)
        XCTAssertFalse(model(hasHelper: false).canInstall)
    }

    func testDevelopmentModeDoesNotStartALoginShell() async {
        var asked = false
        let m = CommandLineToolModel(
            tool: CommandLineTool(home: home, bundleURL: bundle, helper: helper),
            location: .ok, isDevelopment: true, detectPath: { asked = true; return "/usr/bin" })
        await m.refresh()
        XCTAssertFalse(asked)
        XCTAssertFalse(m.pathKnown)
    }

    func testThePathHintAppearsOnlyForAnInstalledLinkWhenTheFolderIsMissing() async {
        let missing = model()
        await missing.refresh()
        XCTAssertFalse(missing.pathMissing, "not installed: nothing to hint")
        missing.install()
        XCTAssertTrue(missing.pathMissing)
        XCTAssertEqual(missing.pathLine, "export PATH=\"$HOME/.local/bin:$PATH\"")

        let fish = model(shell: "/opt/homebrew/bin/fish")
        await fish.refresh()
        fish.install()
        XCTAssertTrue(fish.pathMissing)
        XCTAssertEqual(fish.pathLine, "fish_add_path ~/.local/bin")
        XCTAssertEqual(fish.pathSteps, CommandLineToolModel.pathStepsFish)
    }

    func testNoPathHintWhenTheFolderIsOnThePath() async throws {
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".local/bin"), withIntermediateDirectories: true)
        let m = model(path: "/usr/bin:\(home.path)/.local/bin")
        await m.refresh()
        m.install()
        XCTAssertFalse(m.pathMissing)
    }

    func testNoPathHintBeforeThePathIsKnown() {
        let m = model()
        m.install()
        XCTAssertFalse(m.pathMissing, "an unread PATH is not reported as missing")
    }
}

@MainActor
final class UninstallCommandLineTests: XCTestCase {
    var temp: TempDir!
    var home: URL { temp.url.appendingPathComponent("home", isDirectory: true) }
    var bundle: URL { temp.url.appendingPathComponent("Applications/grantpin.app", isDirectory: true) }
    var helper: URL!
    var link: URL { home.appendingPathComponent(".local/bin/grantpin") }
    var vault: URL { temp.url.appendingPathComponent("Application Support/grantpin") }
    var logs: URL { temp.url.appendingPathComponent("Logs/grantpin") }
    let fm = FileManager.default

    override func setUpWithError() throws {
        temp = try TempDir()
        helper = try temp.file("Applications/grantpin.app/" + HelperLocator.relativePath, "#!/bin/sh\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        _ = try temp.file("Application Support/grantpin/vault.db")
    }

    var tool: CommandLineTool { CommandLineTool(home: home, bundleURL: bundle, helper: helper) }

    func model(stop: Bool = true, tool: CommandLineTool? = nil) -> UninstallModel {
        let m = UninstallModel(
            control: FakeServiceControl(), secrets: 1, grants: 0, keystoreTier: .hardware, isDevelopment: false,
            vaultFolder: vault, logsFolder: logs, daemonState: { .stopped }, sleep: { _ in },
            commandLine: tool ?? self.tool)
        m.stopService = stop
        return m
    }

    func plant(_ target: String) throws {
        try fm.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: target)
    }

    func testNotOfferedWhenThereIsNoLink() {
        let m = model()
        XCTAssertFalse(m.offersCommandLine)
        XCTAssertFalse(m.willRemoveCommandLine)
    }

    func testOfferedAndTickedByDefaultForOurLink() {
        XCTAssertEqual(tool.install(), .installed(link.path))
        let m = model()
        XCTAssertTrue(m.offersCommandLine)
        XCTAssertTrue(m.removeCommandLine, "default on")
        XCTAssertTrue(m.willRemoveCommandLine)
        XCTAssertEqual(UninstallModel.commandLineLabel, "Remove the grantpin command from ~/.local/bin")
    }

    func testRemovingTheLinkOnItsOwn() async {
        _ = tool.install()
        let m = model(stop: false)
        XCTAssertTrue(m.canRemove, "the link alone is enough to enable Remove")
        await m.remove()
        guard case .finished(let r) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(r.succeeded, r.problem ?? "")
        XCTAssertEqual(r.done, ["The grantpin command was removed from \(link.path)."])
        XCTAssertEqual(tool.linkState(), .absent)
        XCTAssertTrue(fm.fileExists(atPath: helper.path))
    }

    func testUntickedLinkStays() async {
        _ = tool.install()
        let m = model()
        m.removeCommandLine = false
        await m.remove()
        XCTAssertEqual(tool.linkState(), .ours)
        guard case .finished(let r) = m.phase else { return XCTFail() }
        XCTAssertEqual(r.done, ["The background service was stopped and removed."])
    }

    func testALinkToElsewhereIsNeverOfferedNorTouched() async throws {
        try plant("/opt/homebrew/bin/grantpin")
        let m = model()
        XCTAssertFalse(m.offersCommandLine)
        m.removeCommandLine = true
        XCTAssertFalse(m.willRemoveCommandLine)
        await m.remove()
        XCTAssertEqual(try fm.destinationOfSymbolicLink(atPath: link.path), "/opt/homebrew/bin/grantpin")
    }

    func testARegularFileIsNeverOfferedNorTouched() async throws {
        _ = try temp.file("home/.local/bin/grantpin", "mine")
        let m = model(stop: false)
        XCTAssertFalse(m.offersCommandLine)
        XCTAssertFalse(m.canRemove, "nothing is chosen that can be done")
        XCTAssertEqual(try String(contentsOf: link, encoding: .utf8), "mine")
    }

    func testALinkToAnotherFileInTheBundleIsRemoved() async throws {
        try plant(bundle.path + "/Contents/MacOS/old")
        let m = model()
        XCTAssertTrue(m.offersCommandLine)
        await m.remove()
        XCTAssertEqual(tool.linkState(), .absent)
    }

    func testAFailedStopLeavesTheLinkInPlace() async {
        _ = tool.install()
        let c = FakeServiceControl()
        c.uninstallResult = ActionResult(outcome: .failed, summary: "No.")
        let m = UninstallModel(control: c, secrets: 1, grants: 0, keystoreTier: .hardware, isDevelopment: false,
                               vaultFolder: vault, logsFolder: logs, daemonState: { .stopped }, sleep: { _ in }, commandLine: tool)
        await m.remove()
        XCTAssertEqual(tool.linkState(), .ours)
    }

    func testWithoutACommandLineToolNothingChanges() {
        let m = UninstallModel(control: FakeServiceControl(), secrets: 1, grants: 0, keystoreTier: .hardware, isDevelopment: false,
                               vaultFolder: vault, logsFolder: logs, daemonState: { .stopped }, sleep: { _ in })
        XCTAssertFalse(m.offersCommandLine)
        XCTAssertTrue(m.canRemove)
    }
}
