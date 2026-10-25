import SwiftUI
import GrantdKit

/// Stub of the menu-bar app: a menu bar icon, a title, one status line from
/// `DaemonMonitor` (not running, locked, no vault, ready) and Quit. The real
/// screens come with the later steps of docs/UI-SPEC.md section 7.
@main
struct GrantdApp: App {
    @State private var monitor: DaemonMonitor
    private let socket = SocketLocator.resolve()

    init() {
        let m = DaemonMonitor(transport: Client(socketPath: SocketLocator.resolve().path))
        m.start()
        _monitor = State(initialValue: m)
    }

    var body: some Scene {
        MenuBarExtra {
            PopoverView(monitor: monitor, developmentSocket: socket.isDevelopment ? socket.path : nil)
        } label: {
            Image(systemName: "lock.shield")
                .accessibilityLabel("grantd")
        }
        .menuBarExtraStyle(.window)
    }
}

struct PopoverView: View {
    let monitor: DaemonMonitor
    let developmentSocket: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: "grantd")
                .font(.headline)
            Text(verbatim: StatusText.headline(monitor.state))
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityLabel(Text(verbatim: "Status: " + StatusText.headline(monitor.state)))
            if let detail = StatusText.detail(monitor.state) {
                Text(verbatim: detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let dev = developmentSocket {
                Text(verbatim: "Development socket: " + dev)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Divider()
            Button("Quit grantd") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
                .help("Quits this app. The background service keeps running.")
        }
        .padding(12)
        .frame(width: 320, alignment: .leading)
        .onAppear {
            monitor.isVisible = true
            Task { await monitor.refreshNow() }
        }
        .onDisappear { monitor.isVisible = false }
    }
}
