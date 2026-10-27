import SwiftUI
import GrantpinKit

/// The menu-bar popover (docs/UI-SPEC.md 3.1): the status line, the counts,
/// the last three events and the way into the windows.
///
/// Text that came from the daemon is shown with `Text(verbatim:)` after the
/// sanitiser (4.4), never as a Markdown-parsed `Text("\(x)")`.
struct PopoverView: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var isOpen = false
    @AppStorage(AppModel.showActivityKey) private var showActivity = true

    private var popover: PopoverModel { app.popover }

    var body: some View {
        let state = app.monitor.state
        let line = StatusLine.from(state, lastError: app.monitor.lastError,
                                   service: app.serviceWatcher.diagnosis, helperVersion: app.helperVersion)
        let status: StatusResult? = { if case .ready(let s)? = state { return s } else { return nil } }()
        VStack(alignment: .leading, spacing: 0) {
            StatusHeader(app: app, line: line, openWindow: open)
            if !popover.location.isOK && !popover.isDevelopment {
                LocationNotice(app: app)
            }
            if case .ready? = state {
                if !popover.quickSecrets.isEmpty {
                    Divider().padding(.vertical, 6)
                    QuickSecrets(app: app, open: open)
                }
                if showActivity {
                    Divider().padding(.vertical, 6)
                    RecentActivity(popover: popover)
                }
            }
            Divider().padding(.vertical, 6)
            if case .ready? = state {
                MenuRow(title: "Add Secret…") { app.secretsIntent = .add; open(WindowID.secrets) }
            }
            MenuRow(title: "All Secrets…") { open(WindowID.secrets) }
            MenuRow(title: grantsRowTitle(activeGrants: status?.activeGrants)) { open(WindowID.grants) }
            MenuRow(title: "Activity…") { open(WindowID.activity) }
            MenuRow(title: "Settings…", shortcut: "⌘,") { app.showSettings(.general) }
                .keyboardShortcut(",")
            Divider().padding(.vertical, 6)
            MenuRow(title: "Quit grantpin", shortcut: "⌘Q") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
                .help("Quits this app. The background service keeps running.")
        }
        .padding(.vertical, 8)
        .frame(width: 320, alignment: .leading)
        .background(WindowKeyObserver { key in
            isOpen = key
            if key { app.surfaceAppeared("popover") } else { app.surfaceDisappeared("popover") }
        })
        .task(id: "\(isOpen)-\(isReady(state))") {
            // The newest events and secrets, every 5 seconds while the popover is open (2.4).
            guard isOpen, isReady(state) else { return }
            while !Task.isCancelled {
                await popover.refreshActivity()
                await popover.refreshSecrets()
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    private func isReady(_ state: ConnectionState?) -> Bool {
        if case .ready? = state { return true }
        return false
    }

    private func open(_ id: String) {
        app.prepareToShowWindow()
        openWindow(id: id)
    }
}

/// The coloured dot, the headline and what the person can do about it.
struct StatusHeader: View {
    let app: AppModel
    let line: StatusLine
    let openWindow: (String) -> Void

    private var popover: PopoverModel { app.popover }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "circle.fill")
                    .font(.system(size: 8))
                    .foregroundStyle(color)
                    .accessibilityHidden(true)
                Text(verbatim: line.headline)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(Text(verbatim: "Status: " + line.headline))

            if let detail = line.detail {
                Text(verbatim: detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let restored = app.serviceRecovery.noticeText {
                Label {
                    Text(verbatim: restored).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
                .font(.callout)
            }
            if let note = line.note {
                Text(verbatim: note)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let counts = line.countsText {
                Text(verbatim: counts)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if let warning = line.tamperedWarning {
                Label {
                    Text(verbatim: warning).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.callout)
            }
            if line.button != nil || line.secondButton != nil {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        if let b = line.button { ActionButton(app: app, button: b, prominent: true, openWindow: openWindow) }
                        if let b = line.secondButton { ActionButton(app: app, button: b, prominent: false, openWindow: openWindow) }
                        if let running = popover.running, line.button == running || line.secondButton == running {
                            ProgressView().controlSize(.small)
                        }
                    }
                    if let reason = popover.buttonsDisabledReason, line.button.map(runsHelper) == true {
                        Text(verbatim: reason).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let result = popover.lastResult {
                        ResultLine(result: result).font(.callout)
                    }
                }
            }
            if let dev = popover.developmentSocket {
                Text(verbatim: "Development socket: " + DisplayText.sanitise(dev))
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, 4)
    }

    private func runsHelper(_ b: StatusLine.Button) -> Bool {
        switch b {
        case .startService, .repair, .restart, .createVault: return true
        case .setUp, .review, .openLogs: return false
        }
    }

    private var color: Color {
        switch line.level {
        case .neutral: return .secondary
        case .ok: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
}

/// The status line's buttons. Start, Repair and Restart all run `grantpin
/// service install --exe <this app> --path <PATH>`, the one way the app
/// starts the daemon (docs/UI-SPEC.md 2.2). Set Up opens the Welcome window at
/// the vault step, Review opens Grants, Open Logs Folder opens the folder.
struct ActionButton: View {
    let app: AppModel
    let button: StatusLine.Button
    let prominent: Bool
    let openWindow: (String) -> Void

    private var popover: PopoverModel { app.popover }

    var body: some View {
        if prominent {
            Button(button.title) { Task { await run() } }
                .controlSize(.small)
                .buttonStyle(.borderedProminent)
                .disabled(isDisabled)
                .help(popover.buttonsDisabledReason.flatMap { runsHelper ? $0 : nil } ?? helpText)
        } else {
            Button(button.title) { Task { await run() } }
                .controlSize(.small)
                .disabled(isDisabled)
                .help(helpText)
        }
    }

    private var runsHelper: Bool {
        switch button {
        case .startService, .repair, .restart, .createVault: return true
        case .setUp, .review, .openLogs: return false
        }
    }

    private var isDisabled: Bool {
        runsHelper && (popover.running != nil || popover.buttonsDisabledReason != nil)
    }

    private var helpText: String {
        switch button {
        case .startService: return "Installs and starts grantpin's background service."
        case .repair: return "Points the background service at this app again."
        case .restart: return "Restarts grantpin's background service."
        case .createVault: return "Creates your vault and its key on this Mac."
        case .setUp: return "Opens the setup window."
        case .review: return "Opens the list of grants."
        case .openLogs: return "Opens the folder with grantpin's log files."
        }
    }

    private func run() async {
        switch button {
        case .startService, .repair, .restart, .createVault:
            await popover.perform(button)
        case .setUp:
            app.onboarding.go(to: .vault)
            app.requestWindow(WindowID.onboarding)
        case .review:
            openWindow(WindowID.grants)
        case .openLogs:
            app.openLogsFolder()
        }
    }
}

/// "Move grantpin to your Applications folder first" with its button.
private struct LocationNotice: View {
    let app: AppModel
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider().padding(.vertical, 6)
            Label {
                Text(verbatim: AppLocation.blockedMessage).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "folder.badge.questionmark").foregroundStyle(.orange)
            }
            .font(.callout)
            Button(AppLocation.moveButton) { problem = app.moveToApplicationsAndRelaunch() }
                .controlSize(.small)
            if let problem { Text(verbatim: problem).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
        }
        .padding(.horizontal, 14)
    }
}

/// The six most recently updated secrets (docs/UI-SPEC.md 3.1); a click opens
/// the Secrets window with that row selected.
private struct QuickSecrets: View {
    let app: AppModel
    let open: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Secrets")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
            ForEach(app.popover.quickSecrets) { secret in
                MenuRow(title: DisplayText.sanitise(secret.name, limit: 60), verbatimTitle: true, trailing: tier(secret.minTier)) {
                    app.secretsIntent = .select(secret.name)
                    open(WindowID.secrets)
                }
            }
        }
    }

    private func tier(_ t: Tier) -> String {
        switch t.rank {
        case 2: return "Hardware"
        case 1: return "Dialog"
        default: return ""
        }
    }
}

/// The last three events, newest first.
private struct RecentActivity: View {
    let popover: PopoverModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Recent activity")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
            if popover.recent.isEmpty {
                Text(popover.activityLoaded
                     ? "Nothing yet. When an agent asks to use a secret, it shows up here."
                     : "Activity is not available right now.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 14)
            } else {
                ForEach(popover.recent) { event in
                    EventRow(event: event)
                }
            }
        }
    }
}

private struct EventRow: View {
    let event: AuditEvent

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(alignment: .firstTextBaseline) {
                Text(verbatim: event.title)
                    .font(.callout)
                    .lineLimit(1)
                Spacer(minLength: 8)
                Text(event.time, style: .relative)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            if !event.command.isEmpty {
                Text(verbatim: event.command)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.horizontal, 14)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: event.summary))
    }
}

/// One row of the popover's menu part: full width, highlighted on hover like
/// a menu item. `verbatimTitle` is for text that came from the daemon.
struct MenuRow: View {
    let title: String
    var verbatimTitle = false
    var shortcut: String?
    var trailing: String?
    let action: () -> Void
    @State private var hovering = false

    init(title: String, verbatimTitle: Bool = false, shortcut: String? = nil, trailing: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.verbatimTitle = verbatimTitle
        self.shortcut = shortcut
        self.trailing = trailing
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack {
                Group {
                    if verbatimTitle { Text(verbatim: title) } else { Text(LocalizedStringKey(title)) }
                }
                .lineLimit(1).truncationMode(.middle)
                Spacer()
                if let text = shortcut ?? trailing, !text.isEmpty {
                    Text(verbatim: text)
                        .font(trailing != nil ? .caption : .body)
                        .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.secondary))
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .contentShape(Rectangle())
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .background(
                RoundedRectangle(cornerRadius: 5)
                    .fill(hovering ? Color.accentColor : Color.clear)
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
        .onHover { hovering = $0 }
    }
}
