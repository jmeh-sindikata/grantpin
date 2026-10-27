import AppKit
import SwiftUI
import GrantpinKit

/// The Settings window (docs/UI-SPEC.md 3.5): General, Connect, Security &
/// data and Uninstall. Everything that changes the system asks first.
struct SettingsView: View {
    let app: AppModel
    @Bindable private var navigation: AppModel

    init(app: AppModel) {
        self.app = app
        self.navigation = app
    }

    var body: some View {
        TabView(selection: $navigation.settingsTab) {
            GeneralSettings(app: app)
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            ConnectPanel(app: app)
                .tabItem { Label("Connect", systemImage: "link") }
                .tag(SettingsTab.connect)
            SecuritySettings(app: app)
                .tabItem { Label("Security & Data", systemImage: "lock.shield") }
                .tag(SettingsTab.security)
            UninstallSettings(app: app)
                .tabItem { Label("Uninstall", systemImage: "trash") }
                .tag(SettingsTab.uninstall)
        }
        .frame(width: 600, height: 560)
        .background(WindowKeyObserver { key in
            if key { app.surfaceAppeared("settings") } else { app.surfaceDisappeared("settings") }
        })
        .background(WindowSetup())
        .onChange(of: app.monitor.state, initial: true) { _, new in app.settings.connectionChanged(new) }
        .task {
            await app.settings.refresh()
            await app.settings.loadPathIfNeeded()
            await app.commandLine.refresh()
        }
    }
}

// MARK: - General

private struct GeneralSettings: View {
    let app: AppModel
    @State private var confirmingStop = false
    @AppStorage(AppModel.showActivityKey) private var showActivity = true

    private var model: SettingsModel { app.settings }

    var body: some View {
        Form {
            if let banner = model.developmentBanner {
                Section {
                    Label { Text(verbatim: banner) } icon: { Image(systemName: "hammer.fill").foregroundStyle(.orange) }
                    if let reason = model.controlsDisabledReason {
                        Hint(reason, tint: .secondary)
                    }
                }
            } else if let reason = model.controlsDisabledReason {
                Section {
                    Label { Text(verbatim: reason) } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                    if !model.location.isOK {
                        Button(AppLocation.moveButton) { move() }
                        if let p = model.problem { Hint(p, tint: .red) }
                    }
                }
            }

            loginSection
            serviceSection
            pathSection
            CommandLineSection(model: app.commandLine)

            Section("Menu") {
                Toggle("Show recent activity in the menu", isOn: $showActivity)
            }

            aboutSection
        }
        .formStyle(.grouped)
        .alert(
            Text(verbatim: SettingsModel.stopConfirmation.title),
            isPresented: $confirmingStop
        ) {
            Button(SettingsModel.stopConfirmation.confirmLabel, role: .destructive) { Task { await model.stopService() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: SettingsModel.stopConfirmation.message)
        }
    }

    // MARK: sections

    private var loginSection: some View {
        Section("Startup") {
            Toggle("Start grantpin when I log in", isOn: Binding(
                get: { model.startAtLogin },
                set: { model.setStartAtLogin($0) }))
                .disabled(!model.loginItemAvailable)
            if model.loginNeedsApproval {
                Hint(SettingsModel.approvalNeeded, tint: .orange)
                Button("Open Login Items Settings…") { model.openLoginItemsSettings() }
            }
            if let e = model.loginError { Hint(e, tint: .red) }
            Hint("Without this, the menu bar icon is gone after a restart. Agents keep working: the background service starts on its own.", tint: .secondary)
        }
    }

    private var serviceSection: some View {
        Section("Background service") {
            Toggle("Keep grantpin running in the background", isOn: Binding(
                get: { model.backgroundServiceOn },
                set: { on in
                    if on { Task { await model.install() } } else { confirmingStop = true }
                }))
                .disabled(model.controlsDisabledReason != nil || model.isBusy)
            if model.isBusy { ProgressView().controlSize(.small) }
            if let s = model.service {
                LabeledContent("Status") {
                    Text(verbatim: s.running ? "Running" + (s.pid.map { " (pid \($0))" } ?? "") : (s.installed ? "Stopped" : "Not installed"))
                }
                if let p = s.plistPath { pathRow("Service file", p) }
                if let e = s.exePath { pathRow("Program", e) }
                if s.exeMissing {
                    Label {
                        Text("The program the service points to no longer exists. Repair points it at this app.")
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                    Button("Repair") { Task { await model.install() } }
                        .disabled(model.controlsDisabledReason != nil || model.isBusy)
                }
            } else if model.serviceUnreadable {
                Hint("The service status could not be read.", tint: .secondary)
            }
            if let r = model.lastResult { ResultLine(result: r) }
        }
    }

    private var pathSection: some View {
        Section {
            TextField(SettingsModel.pathLabel, text: Bindable(model).pathText, axis: .vertical)
                .labelsHidden()
                .font(.callout.monospaced())
                .lineLimit(1...4)
                .autocorrectionDisabled()
            HStack {
                Button("Re-detect") { Task { await model.redetectPath() } }
                    .help("Ask your login shell for its PATH")
                Button("Apply") { Task { await model.applyPath() } }
                    .disabled(model.controlsDisabledReason != nil || model.isBusy)
                    .help("Saves this list and restarts the background service")
            }
            if let m = model.pathMessage { Hint(m, tint: .red) }
        } header: {
            Text(SettingsModel.pathLabel)
        } footer: {
            Text(verbatim: SettingsModel.pathHelp)
        }
    }

    private var aboutSection: some View {
        Section("About") {
            if let s = model.status {
                LabeledContent("Version") {
                    Text(verbatim: DisplayText.sanitise(s.version, limit: 80) + " · protocol " + String(s.protoV))
                        .textSelection(.enabled)
                }
            } else {
                LabeledContent("Version") { Text("Not running").foregroundStyle(.secondary) }
            }
            if let note = model.versionNote {
                Label {
                    Text(verbatim: note).fixedSize(horizontal: false, vertical: true)
                } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                if let action = model.versionAction {
                    Button(action) { Task { await model.install() } }
                        .disabled(model.controlsDisabledReason != nil || model.isBusy)
                }
            }
            pathRow("Socket", model.status.map { $0.socket.isEmpty ? model.resolvedSocket : $0.socket } ?? model.resolvedSocket)
            Button("Open Logs Folder") { app.openLogsFolder() }
        }
    }

    private func pathRow(_ title: String, _ path: String) -> some View {
        LabeledContent(title) {
            Text(verbatim: DisplayText.sanitise(path, limit: DisplayText.detailLimit))
                .font(.caption.monospaced())
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }

    private func move() {
        if let problem = app.moveToApplicationsAndRelaunch() { model.noteProblem(problem) }
    }
}

/// A one-line result of a helper action, with its details in a disclosure.
struct ResultLine: View {
    let result: ActionResult
    @State private var showDetail = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label {
                Text(verbatim: result.summary).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: result.isSuccess ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(result.isSuccess ? Color.green : Color.red)
            }
            if let detail = result.detail {
                DisclosureGroup("Details", isExpanded: $showDetail) {
                    Text(verbatim: detail)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.caption)
            }
        }
    }
}

// MARK: - Command line tool

/// "Command line tool" in General: a link `~/.local/bin/grantpin` to the helper
/// in this app. The logic is `CommandLineToolModel`; this only draws it.
private struct CommandLineSection: View {
    let model: CommandLineToolModel

    var body: some View {
        Section {
            LabeledContent("Status") {
                HStack(spacing: 6) {
                    if model.statusIsOK { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green).accessibilityHidden(true) }
                    if model.statusIsProblem { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).accessibilityHidden(true) }
                    Text(verbatim: model.statusText)
                        .font(model.statusIsProblem ? .callout : .caption.monospaced())
                        .multilineTextAlignment(.trailing)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
            }
            if let note = model.statusNote { Hint(note, tint: .secondary) }
            if let reason = model.disabledReason {
                Label {
                    Text(verbatim: reason).fixedSize(horizontal: false, vertical: true)
                } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
            }
            HStack {
                Button("Install") { model.install() }
                    .disabled(!model.canInstall)
                    .help("Adds a link to grantpin in ~/.local/bin")
                    .accessibilityLabel(Text("Install the grantpin command"))
                if model.canRemove {
                    Button("Remove") { model.remove() }
                        .help("Removes the link from ~/.local/bin. The app is not changed.")
                        .accessibilityLabel(Text("Remove the grantpin command"))
                }
            }
            if let r = model.result {
                Label {
                    Text(verbatim: r.message).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: r.isSuccess ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(r.isSuccess ? Color.green : Color.red)
                }
            }
            if model.pathMissing {
                Hint(CommandLineToolModel.pathMissingText, tint: .orange)
                Text(verbatim: model.pathSteps).font(.callout).fixedSize(horizontal: false, vertical: true)
                CopyBox(text: model.pathLine, label: "Copy")
                Hint(CommandLineToolModel.pathNever, tint: .secondary)
            }
        } header: {
            Text("Command line tool")
        } footer: {
            Text(verbatim: CommandLineToolModel.help)
        }
    }
}

// MARK: - Security & data

private struct SecuritySettings: View {
    let app: AppModel

    var body: some View {
        let facts = SecurityFacts(status: app.settings.status, resolvedSocket: app.socket.path)
        Form {
            Section("This Mac") {
                LabeledContent("Version") { Text(verbatim: facts.version) }
                LabeledContent("Protocol") { Text(verbatim: facts.protocolVersion) }
                LabeledContent("Vault protection") { Text(verbatim: facts.vaultProtection) }
                LabeledContent("Approval") { Text(verbatim: facts.approval) }
            }
            Section("Where things are") {
                row("Socket", facts.socket)
                row("Vault folder", AppPaths.vaultFolder().path)
                row("Logs folder", AppPaths.logsFolder().path)
                HStack {
                    Button("Open Logs Folder") { app.openLogsFolder() }
                    Button("Open Vault Folder in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([AppPaths.vaultFolder()])
                    }
                }
            }
            Section {
                Text(verbatim: SecurityFacts.managingParagraph)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }

    private func row(_ title: String, _ value: String) -> some View {
        LabeledContent(title) {
            Text(verbatim: DisplayText.sanitise(value, limit: DisplayText.detailLimit))
                .font(.caption.monospaced())
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

// MARK: - Uninstall

private struct UninstallSettings: View {
    let app: AppModel
    @State private var sheet: UninstallModel?

    var body: some View {
        Form {
            Section {
                Text("Removes the background service, and optionally your vault, the logs and the key that protects the vault. Nothing is removed until you choose it on the next screen.")
                    .fixedSize(horizontal: false, vertical: true)
                Button("Uninstall grantpin…") { sheet = makeModel() }
            }
            if let reason = app.settings.controlsDisabledReason {
                Section { Hint(reason, tint: .secondary) }
            }
        }
        .formStyle(.grouped)
        .sheet(item: $sheet) { model in
            UninstallSheet(model: model, app: app) { sheet = nil }
        }
    }

    private func makeModel() -> UninstallModel {
        let status = app.settings.status
        var locked = false
        if case .locked? = app.settings.connection { locked = true }
        let client = app.client
        let login = app.loginItem
        return UninstallModel(
            control: app.serviceControl, secrets: status?.secrets, grants: status.map { $0.activeGrants + $0.tamperedGrants },
            keystoreTier: status?.keystoreTier, isDevelopment: app.socket.isDevelopment, vaultLocked: locked,
            keychain: app.serviceControl.map { HelperKeystore(helper: $0.helper) },
            daemonState: { await DaemonState.probe(client) },
            unregisterLoginItem: { try? login.unregister() },
            commandLine: app.commandLine.tool)
    }
}
