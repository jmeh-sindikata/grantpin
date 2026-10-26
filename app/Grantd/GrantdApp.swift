import AppKit
import SwiftUI
import GrantdKit

/// The menu-bar app: a status item with a popover, and the Secrets, Grants,
/// Activity and Welcome windows plus Settings (docs/UI-SPEC.md section 3).
@main
struct GrantdApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var app = AppModel()

    var body: some Scene {
        MenuBarExtra {
            PopoverView(app: app)
        } label: {
            MenuBarLabel(app: app)
        }
        .menuBarExtraStyle(.window)

        Window("Secrets", id: WindowID.secrets) {
            SecretsWindow(app: app)
        }
        .defaultSize(width: 880, height: 540)

        Window("Grants", id: WindowID.grants) {
            GrantsWindow(app: app)
        }
        .defaultSize(width: 920, height: 460)

        Window("Activity", id: WindowID.activity) {
            ActivityWindow(app: app)
        }
        .defaultSize(width: 1040, height: 560)

        Window("Welcome to grantd", id: WindowID.onboarding) {
            OnboardingWindow(app: app)
        }
        .windowResizability(.contentSize)

        Settings {
            SettingsView(app: app)
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Uninstall grantd…") { app.showSettings(.uninstall) }
            }
        }
    }
}

/// Tells the running instance about a second launch: with
/// `LSMultipleInstancesProhibited` the system activates the first instance and
/// sends it a reopen event instead of starting another.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Task { @MainActor in AppModel.current?.handleReopen() }
        return true
    }
}
