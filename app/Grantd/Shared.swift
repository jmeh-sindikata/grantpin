import SwiftUI
import GrantdKit

enum WindowID {
    static let secrets = "secrets"
    static let activity = "activity"
    static let grants = "grants"
    static let onboarding = "onboarding"
}

/// The menu bar icon (docs/UI-SPEC.md 3.1): a template SF Symbol that follows
/// the daemon's state. It is also the one view that always exists, so it
/// opens the windows other parts of the app ask for (`WindowRequest`) and
/// the Welcome window on first launch.
struct MenuBarLabel: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let icon = MenuBarIcon.from(app.monitor.state)
        Image(systemName: icon.symbol)
            .symbolRenderingMode(.monochrome)
            .opacity(icon.subdued ? 0.6 : 1)
            .accessibilityLabel(Text(verbatim: icon.label))
            .help(Text(verbatim: icon.label))
            .onChange(of: app.windowRequest) { _, request in
                if let request { openWindow(id: request.id) }
            }
            .task { await app.openOnboardingIfNeeded() }
    }
}

/// Marks the hosting window non-restorable (docs/UI-SPEC.md 2.7: nothing the
/// person typed is ever restored from disk).
struct WindowSetup: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async { v.window?.isRestorable = false }
        return v
    }
    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { nsView.window?.isRestorable = false }
    }
}
