import SwiftUI
import GrantpinKit

enum WindowID {
    static let secrets = "secrets"
    static let activity = "activity"
    static let grants = "grants"
    static let onboarding = "onboarding"
    static let settings = "settings"
    static let serviceAsk = "service-ask"
}

/// The menu bar icon (docs/UI-SPEC.md 3.1): the grantpin glyph, with a badge
/// when something needs attention (see `MenuBarIconImage`). It is also the one
/// view that always exists, so it opens the windows other parts of the app ask
/// for (`WindowRequest`) and the Welcome window on first launch.
///
/// The label must read nothing but `app.menuBarIcon` (and the window
/// requests it exists to serve). Not the monitor's state: a status answer
/// that differs only in its counts or its runs in flight is a new state, and
/// re-evaluating the label for it, often while the popover is open, is what a
/// `.window`-style `MenuBarExtra` does not tolerate (it can leave the popover
/// standing when a row hands over to a new window). `AppModel` derives the
/// icon from the state and the helper's version and writes it only when it
/// differs; the recovery decision's triggers live there too
/// (`watchRecoveryTriggers`), not here.
struct MenuBarLabel: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let icon = app.menuBarIcon
        MenuBarIconView(icon: icon)
            .equatable()
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
