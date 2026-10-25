import SwiftUI
import GrantdKit

/// The menu-bar app: a status item with a popover, a Secrets window, and
/// placeholders for the Activity window and Settings that the next step fills
/// (docs/UI-SPEC.md sections 3.1 to 3.5).
@main
struct GrantdApp: App {
    @State private var app = AppModel()

    var body: some Scene {
        MenuBarExtra {
            PopoverView(app: app)
        } label: {
            MenuBarLabel(state: app.monitor.state)
        }
        .menuBarExtraStyle(.window)

        Window("Secrets", id: WindowID.secrets) {
            SecretsWindow(app: app)
        }
        .defaultSize(width: 880, height: 540)

        Window("Activity", id: WindowID.activity) {
            PlaceholderWindow(
                app: app, id: WindowID.activity, title: "Activity", symbol: "list.bullet.rectangle",
                text: "The activity log and the grants list arrive in the next update. The newest events are in the menu bar item.")
        }
        .defaultSize(width: 520, height: 360)

        Settings {
            PlaceholderWindow(
                app: app, id: "settings", title: "Settings", symbol: "gearshape",
                text: "Settings arrive in the next update.")
                .frame(width: 440, height: 260)
        }
    }
}
