import SwiftUI
import GrantdKit

/// The menu-bar popover (docs/UI-SPEC.md 3.1): the status line, the counts,
/// the last three events and the way into the windows.
///
/// Text that came from the daemon is shown with `Text(verbatim:)` after the
/// sanitiser (4.4), never as a Markdown-parsed `Text("\(x)")`.
struct PopoverView: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @State private var isOpen = false

    private var popover: PopoverModel { app.popover }

    var body: some View {
        let state = app.monitor.state
        let line = StatusLine.from(state, lastError: app.monitor.lastError)
        VStack(alignment: .leading, spacing: 0) {
            StatusHeader(line: line, popover: popover)
            if case .ready? = state {
                Divider().padding(.vertical, 6)
                RecentActivity(popover: popover)
            }
            Divider().padding(.vertical, 6)
            MenuRow(title: "Open Secrets…") { open(WindowID.secrets) }
            MenuRow(title: "Open Activity…") { open(WindowID.activity) }
            MenuRow(title: "Settings…", shortcut: "⌘,") {
                app.prepareToShowWindow()
                Task {
                    // Give the activation policy a moment to take effect.
                    try? await Task.sleep(nanoseconds: 100_000_000)
                    openSettings()
                }
            }
            .keyboardShortcut(",")
            Divider().padding(.vertical, 6)
            MenuRow(title: "Quit grantd", shortcut: "⌘Q") { NSApplication.shared.terminate(nil) }
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
            // The newest events, every 5 seconds while the popover is open (2.4).
            guard isOpen, isReady(state) else { return }
            while !Task.isCancelled {
                await popover.refreshActivity()
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
private struct StatusHeader: View {
    let line: StatusLine
    let popover: PopoverModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "circle.fill")
                    .font(.system(size: 8))
                    .foregroundStyle(color)
                    .accessibilityHidden(true)
                Text(verbatim: line.headline)
                    .font(.headline)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(Text(verbatim: "Status: " + line.headline))

            if let detail = line.detail {
                Text(verbatim: detail)
                    .font(.callout)
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
            if let button = line.button {
                ActionButton(button: button, popover: popover)
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

    private var color: Color {
        switch line.level {
        case .neutral: return .secondary
        case .ok: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
}

/// "Start" and "Create vault…": the only two things the popover makes the
/// helper do. Start runs `grantd service install --exe <this app> --path
/// <PATH>`, the one way the app starts the daemon (docs/UI-SPEC.md 2.2).
/// Create vault runs `grantd init`.
private struct ActionButton: View {
    let button: StatusLine.Button
    let popover: PopoverModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Button(title) { Task { await run() } }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .disabled(popover.running != nil || popover.buttonsDisabledReason != nil)
                    .help(popover.buttonsDisabledReason ?? helpText)
                if popover.running == button {
                    ProgressView().controlSize(.small)
                }
            }
            if let reason = popover.buttonsDisabledReason {
                Text(verbatim: reason).font(.caption).foregroundStyle(.secondary)
            }
            if let result = popover.lastResult {
                ResultView(result: result)
            }
        }
    }

    private var title: String { button == .startService ? "Start" : "Create vault…" }
    private var helpText: String {
        button == .startService
            ? "Installs and starts grantd's background service."
            : "Creates your vault and its key on this Mac."
    }

    private func run() async {
        switch button {
        case .startService: await popover.start()
        case .createVault: await popover.createVault()
        }
    }
}

private struct ResultView: View {
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
            .font(.callout)
            if let detail = result.detail {
                DisclosureGroup("Details", isExpanded: $showDetail) {
                    Text(verbatim: detail)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.caption)
            }
            if result.secureEnclaveUnavailable {
                Text("This Mac's Secure Enclave could not be used. Choosing weaker Keychain protection comes with the setup screens in the next update.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
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
/// a menu item.
struct MenuRow: View {
    let title: String
    var shortcut: String?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                if let shortcut {
                    Text(shortcut).foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.secondary))
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
