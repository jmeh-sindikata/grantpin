import AppKit
import SwiftUI
import GrantdKit
import Observation

/// Everything the windows share: the socket client, the monitor that polls
/// `status`, the popover's and the Secrets window's models, and the helper
/// that starts the daemon and creates the vault.
///
/// The app is a client of the socket and of the signed helper inside its own
/// bundle, nothing else (docs/UI-SPEC.md 2.2). In development mode, when
/// `GRANTD_SOCKET` is set, it never touches the real launchd job or vault.
@MainActor
@Observable
final class AppModel {
    let socket = SocketLocator.resolve()
    let client: Client
    let monitor: DaemonMonitor
    let popover: PopoverModel
    let secrets: SecretsViewModel

    /// The helper (`grantd` in `grantd-daemon.app`), if it can be found.
    let helper: URL?
    /// Runs `.env` imports through the helper; nil without a helper.
    let importRunner: ImportRunner?

    @ObservationIgnored private var visibleSurfaces = Set<String>()
    @ObservationIgnored private var observers = [NSObjectProtocol]()

    init() {
        let socket = self.socket
        let client = Client(socketPath: socket.path)
        self.client = client
        let monitor = DaemonMonitor(transport: client)
        self.monitor = monitor

        let environment = ProcessInfo.processInfo.environment
        let override = socket.isDevelopment ? environment["GRANTD_HELPER"] : nil
        let helper = try? HelperLocator.resolve(bundleURL: Bundle.main.bundleURL, developmentOverride: override)
        self.helper = helper
        self.importRunner = helper.map { ImportRunner(executable: $0, socketPath: socket.path) }
        let actions = helper.map { HelperActions(helper: $0, appBundle: Bundle.main.bundleURL) }

        self.popover = PopoverModel(
            audit: client, actions: actions, developmentSocket: socket.isDevelopment ? socket.path : nil,
            onActionFinished: { await monitor.refreshNow() })
        self.secrets = SecretsViewModel(service: client, pasteboard: SystemPasteboard())

        monitor.start()
        // A Mac that has just woken up may have lost the daemon or the key: look at once.
        let wake = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { _ in Task { @MainActor in await monitor.refreshNow() } }
        observers.append(wake)
        // The last window closed: go back to being a menu bar item only.
        let closed = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard let window = note.object as? NSWindow, window.styleMask.contains(.titled) else { return }
            Task { @MainActor in self?.windowDidClose(closing: window) }
        }
        observers.append(closed)
    }

    // MARK: visibility (picks the polling interval)

    func surfaceAppeared(_ id: String) {
        visibleSurfaces.insert(id)
        monitor.isVisible = true
        Task { await monitor.refreshNow() }
    }

    func surfaceDisappeared(_ id: String) {
        visibleSurfaces.remove(id)
        monitor.isVisible = !visibleSurfaces.isEmpty
    }

    // MARK: windows

    /// The app lives in the menu bar (`LSUIElement`). A window needs it to
    /// become a regular app for as long as the window is open, so that it can
    /// come to the front and take the keyboard.
    func prepareToShowWindow() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func windowDidClose(closing: NSWindow) {
        // The closing window still reports isVisible while the notification runs.
        let open = NSApp.windows.contains { $0 !== closing && $0.isVisible && $0.styleMask.contains(.titled) && !($0 is NSPanel) }
        if !open { NSApp.setActivationPolicy(.accessory) }
    }
}

/// The system clipboard behind `PasteboardAccess`: read on a Paste click,
/// cleared only after a save and only if nothing else was copied.
struct SystemPasteboard: PasteboardAccess {
    var changeCount: Int { NSPasteboard.general.changeCount }
    func string() -> String? { NSPasteboard.general.string(forType: .string) }
    func clearContents() { NSPasteboard.general.clearContents() }
}

/// Tells the app when the window that hosts a view becomes or stops being the
/// key window. `onAppear` is not reliable for the menu bar popover (its content
/// is built once, not on every opening), and the polling interval and the
/// activity refresh depend on whether the person is looking (docs/UI-SPEC.md 2.4).
struct WindowKeyObserver: NSViewRepresentable {
    let onChange: (Bool) -> Void

    func makeNSView(context: Context) -> NSView { Tracker(onChange: onChange) }
    func updateNSView(_ nsView: NSView, context: Context) { (nsView as? Tracker)?.onChange = onChange }

    final class Tracker: NSView {
        var onChange: (Bool) -> Void
        private var observers = [NSObjectProtocol]()

        init(onChange: @escaping (Bool) -> Void) {
            self.onChange = onChange
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }

        deinit { observers.forEach(NotificationCenter.default.removeObserver) }

        override func viewDidMoveToWindow() {
            observers.forEach(NotificationCenter.default.removeObserver)
            observers = []
            guard let window else { onChange(false); return }
            let center = NotificationCenter.default
            observers.append(center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { [weak self] _ in
                self?.onChange(true)
            })
            observers.append(center.addObserver(forName: NSWindow.didResignKeyNotification, object: window, queue: .main) { [weak self] _ in
                self?.onChange(false)
            })
            observers.append(center.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
                self?.onChange(false)
            })
            onChange(window.isKeyWindow)
        }
    }
}
