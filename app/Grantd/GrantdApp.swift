import SwiftUI
import GrantdKit

/// Step 1 stub of the menu-bar app (docs/UI-SPEC.md section 7, step 2): a menu
/// bar icon, a title, one status line fed by the daemon's `status` op, and
/// Quit. It proves the bundle layout; the real screens come later.
@main
struct GrantdApp: App {
    @State private var model = StatusModel()

    var body: some Scene {
        MenuBarExtra {
            PopoverView(model: model)
        } label: {
            Image(systemName: "lock.shield")
                .accessibilityLabel("grantd")
        }
        .menuBarExtraStyle(.window)
    }
}

struct PopoverView: View {
    let model: StatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: "grantd")
                .font(.headline)
            Text(verbatim: model.line)
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityLabel(Text(verbatim: "Status: " + model.line))
            if let dev = model.developmentSocket {
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
    }
}
