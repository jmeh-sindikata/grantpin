import AppKit
import SwiftUI
import GrantpinKit

/// The visible ask (see `ServiceAskGate`): a small window that opens on its
/// own when the background service is missing or has stopped, so a menu-bar
/// icon that is still there is not mistaken for a service that is running.
///
/// It shows the same status line as the popover, with the same Start, Repair
/// or Restart button, and nothing is installed until the person presses it.
/// A MenuBarExtra popover cannot be opened from code with the SwiftUI API, so
/// this is an ordinary window opened like the others (`requestWindow`).
struct ServiceAskWindow: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        let line = StatusLine.from(app.monitor.state, lastError: app.monitor.lastError,
                                   service: app.serviceWatcher.diagnosis, helperVersion: app.helperVersion)
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: line.level == .ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(line.level == .ok ? Color.green : Color.orange)
                    .accessibilityHidden(true)
                StatusHeader(app: app, line: line, openWindow: { id in
                    app.prepareToShowWindow()
                    openWindow(id: id)
                })
                .padding(.horizontal, -14)
                .padding(.top, -4)
            }
            HStack {
                Spacer()
                Button(line.dismissTitle) { dismissWindow(id: WindowID.serviceAsk) }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 420)
        .background(WindowKeyObserver { key in
            if key { app.surfaceAppeared("service-ask") } else { app.surfaceDisappeared("service-ask") }
        })
        .background(WindowSetup())
    }
}
