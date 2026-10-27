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
/// The label depends on nothing but what the icon shows and the window
/// requests. The recovery decision's triggers live in `AppModel`
/// (`watchRecoveryTriggers`), not here: a `.window`-style `MenuBarExtra` whose
/// label re-evaluates for unrelated state can leave the popover standing when
/// a row hands over to a new window.
struct MenuBarLabel: View {
    let app: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let icon = MenuBarIcon.from(app.monitor.state, helperVersion: app.helperVersion)
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
