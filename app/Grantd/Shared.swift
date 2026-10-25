import SwiftUI
import GrantdKit

enum WindowID {
    static let secrets = "secrets"
    static let activity = "activity"
}

/// The menu bar icon (docs/UI-SPEC.md 3.1): a template SF Symbol that follows
/// the daemon's state.
struct MenuBarLabel: View {
    let state: ConnectionState?

    var body: some View {
        let icon = MenuBarIcon.from(state)
        Image(systemName: icon.symbol)
            .symbolRenderingMode(.monochrome)
            .opacity(icon.subdued ? 0.6 : 1)
            .accessibilityLabel(Text(verbatim: icon.label))
            .help(Text(verbatim: icon.label))
    }
}

/// A window whose content is still to come.
struct PlaceholderWindow: View {
    let app: AppModel
    let id: String
    let title: String
    let symbol: String
    let text: String

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: symbol)
        } description: {
            Text(verbatim: text)
        }
        .padding()
        .frame(minWidth: 320, minHeight: 200)
        .background(WindowKeyObserver { key in
            if key { app.surfaceAppeared(id) } else { app.surfaceDisappeared(id) }
        })
        .background(WindowSetup())
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
