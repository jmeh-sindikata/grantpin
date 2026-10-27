import AppKit
import ServiceManagement
import SwiftUI
import GrantpinKit
import Observation

/// Something another part of the app asks the Secrets window to do once it is
/// open (the popover's quick list, onboarding).
enum SecretsIntent: Equatable {
    case add
    case importFile
    case select(String)
}

/// A window to open from somewhere that has no `openWindow` of its own (the
/// second-launch handler, onboarding). The menu bar label opens it.
struct WindowRequest: Equatable {
    let id: String
    let serial: Int
}

/// The Settings tabs.
enum SettingsTab: Hashable {
    case general, connect, security, uninstall
}

/// The app's own login item, `SMAppService.mainApp` (docs/UI-SPEC.md 3.5).
@MainActor
final class SystemLoginItem: LoginItemControl {
    private var service: SMAppService { SMAppService.mainApp }

    var status: LoginItemStatus {
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered: return .notRegistered
        case .notFound: return .notFound
        @unknown default: return .notRegistered
        }
    }
    func register() throws { try service.register() }
    func unregister() throws { try service.unregister() }
    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// Everything the windows share: the socket client, the monitor that polls
/// `status`, the popover's and the Secrets window's models, and the helper
/// that starts the daemon and creates the vault.
///
/// The app is a client of the socket and of the signed helper inside its own
/// bundle, nothing else (docs/UI-SPEC.md 2.2). In development mode, when
/// `GRANTPIN_SOCKET` is set, it never touches the real launchd job or vault.
@MainActor
@Observable
final class AppModel {
    let socket = SocketLocator.resolve()
    let client: Client
    let monitor: DaemonMonitor
    let popover: PopoverModel
    let secrets: SecretsViewModel
    let grants: GrantsViewModel
    let activity: ActivityViewModel
    let settings: SettingsModel
    /// The `grantpin` command in `~/.local/bin` (Settings > General).
    let commandLine: CommandLineToolModel
    let onboarding: OnboardingModel
    let serviceWatcher: ServiceWatcher
    let loginItem = SystemLoginItem()
    /// Where the app runs from; outside an Applications folder the service and
    /// vault actions are off (docs/UI-SPEC.md 2.5).
    let location: AppLocation
    /// The helper's `--version`, checked once per launch.
    private(set) var helperVersion: String?
    /// The helper as a service controller; nil without a helper.
    let serviceControl: HelperActions?

    var secretsIntent: SecretsIntent?
    private(set) var windowRequest: WindowRequest?
    var settingsTab: SettingsTab = .general
    @ObservationIgnored private var windowSerial = 0

    static let onboardingDoneKey = "onboardingDone"
    static let showActivityKey = "showActivityInMenu"

    /// The running instance, for the application delegate.
    nonisolated(unsafe) static weak var current: AppModel?

    /// The helper (`grantpin` in `grantpin-daemon.app`), if it can be found.
    let helper: URL?
    /// Runs `.env` imports through the helper; nil without a helper.
    let importRunner: ImportRunner?

    @ObservationIgnored private var visibleSurfaces = Set<String>()
    @ObservationIgnored private var serviceAsk = ServiceAskGate()
    @ObservationIgnored private var serviceAskTask: Task<Void, Never>?
    @ObservationIgnored private var observers = [NSObjectProtocol]()

    init() {
        let socket = self.socket
        let client = Client(socketPath: socket.path, peerCheck: socket.isDevelopment ? .off : .automatic)
        self.client = client
        let monitor = DaemonMonitor(transport: client)
        self.monitor = monitor

        let environment = ProcessInfo.processInfo.environment
        let override = socket.isDevelopment ? environment["GRANTPIN_HELPER"] : nil
        let helper = try? HelperLocator.resolve(bundleURL: Bundle.main.bundleURL, developmentOverride: override)
        self.helper = helper
        self.importRunner = helper.map { ImportRunner(executable: $0, socketPath: socket.path, peerCheck: socket.isDevelopment ? .off : .automatic) }
        let actions = helper.map { HelperActions(helper: $0, appBundle: Bundle.main.bundleURL) }
        self.serviceControl = actions
        // Only a real install is checked: a development build lives in a build folder.
        let location = socket.isDevelopment ? AppLocation.ok : AppLocation.check(bundleURL: Bundle.main.bundleURL)
        self.location = location
        let devSocket = socket.isDevelopment ? socket.path : nil
        let refresh: @MainActor () async -> Void = { await monitor.refreshNow() }

        self.popover = PopoverModel(
            audit: client, actions: actions, developmentSocket: devSocket, secrets: client, location: location,
            onActionFinished: refresh)
        self.secrets = SecretsViewModel(service: client, pasteboard: SystemPasteboard())
        self.grants = GrantsViewModel(service: client)
        self.activity = ActivityViewModel(service: client)
        let login = loginItem
        self.settings = SettingsModel(
            control: actions, loginItem: login, developmentSocket: devSocket, resolvedSocket: socket.path,
            location: location, onChanged: refresh)
        // The link points at the helper of THIS bundle, never at the development override.
        let bundledHelper = try? HelperLocator.resolve(bundleURL: Bundle.main.bundleURL)
        self.commandLine = CommandLineToolModel(
            tool: CommandLineTool(bundleURL: Bundle.main.bundleURL, helper: bundledHelper),
            location: location, isDevelopment: socket.isDevelopment, shell: CommandLineToolModel.loginShell())
        self.onboarding = OnboardingModel(
            control: actions, loginItem: login, isDevelopment: socket.isDevelopment, location: location,
            onFinished: { UserDefaults.standard.set(true, forKey: AppModel.onboardingDoneKey) },
            onActionFinished: refresh)
        // The service status is only looked at while the daemon is down, and never in development mode.
        self.serviceWatcher = ServiceWatcher(control: socket.isDevelopment ? nil : actions)

        AppModel.current = self
        monitor.start()
        startServiceWatching()
        if let actions, !socket.isDevelopment {
            Task { [weak self] in self?.helperVersion = await actions.helperVersion() }
        }
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

    /// While the daemon does not answer, asks the helper what the service is
    /// doing (docs/UI-SPEC.md 2.5), at the monitor's cadence.
    private func startServiceWatching() {
        Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if case .notRunning? = self.monitor.state {
                    await self.serviceWatcher.poll()
                } else {
                    self.serviceWatcher.reset()
                }
                let seconds: UInt64 = self.monitor.isVisible ? 3 : 15
                try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            }
        }
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

    /// Opens a window from anywhere (see `WindowRequest`).
    func requestWindow(_ id: String) {
        prepareToShowWindow()
        windowSerial += 1
        windowRequest = WindowRequest(id: id, serial: windowSerial)
    }

    /// Opens Settings on a tab.
    func showSettings(_ tab: SettingsTab = .general) {
        settingsTab = tab
        requestWindow(WindowID.settings)
    }

    /// A second launch of the app (`LSMultipleInstancesProhibited`) activates
    /// this instance and opens the Secrets window (docs/UI-SPEC.md 2.7).
    func handleReopen() {
        requestWindow(WindowID.secrets)
    }

    /// First launch: the Welcome window opens by itself once the first status
    /// has arrived, unless onboarding was finished before or this is a
    /// development build.
    func openOnboardingIfNeeded() async {
        guard !socket.isDevelopment, !UserDefaults.standard.bool(forKey: Self.onboardingDoneKey) else { return }
        for _ in 0..<40 where monitor.state == nil { try? await Task.sleep(nanoseconds: 100_000_000) }
        guard monitor.state != nil else { return }
        onboarding.connectionChanged(monitor.state)
        requestWindow(WindowID.onboarding)
    }

    /// Whether the menu bar popover is the key window right now.
    var isPopoverOpen: Bool { visibleSurfaces.contains("popover") }

    /// The visible ask: when the background service is missing or has stopped,
    /// opens the "background service" window once (see `ServiceAskGate` for
    /// when). Called on every connection change and again once the grace
    /// period of a fresh outage has passed. The service is never installed
    /// from here; the window only offers the Start button.
    func serviceAskCheck() {
        serviceAskTask?.cancel()
        serviceAskTask = nil
        let onboardingPending = !UserDefaults.standard.bool(forKey: Self.onboardingDoneKey)
        let now = Date()
        if serviceAsk.evaluate(monitor.state, now: now, onboardingPending: onboardingPending,
                               isDevelopment: socket.isDevelopment, popoverOpen: isPopoverOpen) {
            Task { await presentServiceAsk() }
        } else if let wait = serviceAsk.waitTime(now: now) {
            serviceAskTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64((wait + 0.5) * 1_000_000_000))
                guard !Task.isCancelled else { return }
                self?.serviceAskCheck()
            }
        }
    }

    private func presentServiceAsk() async {
        // Know which of "not set up" and "stopped" is true before the window shows.
        await serviceWatcher.poll()
        guard case .notRunning? = monitor.state, !isPopoverOpen else { return }
        requestWindow(WindowID.serviceAsk)
    }

    func openLogsFolder() {
        let logs = AppPaths.logsFolder()
        if FileManager.default.fileExists(atPath: logs.path) {
            NSWorkspace.shared.open(logs)
        } else {
            NSWorkspace.shared.open(logs.deletingLastPathComponent())
        }
    }

    /// "Move to Applications and Relaunch": copies the app next to the others,
    /// then quits this one and lets a detached helper open the copy. The
    /// original is left alone.
    ///
    /// The copy is not started from here: with `LSMultipleInstancesProhibited`
    /// the system cannot start a second instance while this one is running.
    /// The helper waits for this process to exit and then opens the copy by its
    /// exact path (see `RelaunchCommand`). If the helper cannot be started this
    /// app keeps running, so the person is never left with nothing open.
    func moveToApplicationsAndRelaunch() -> String? {
        do {
            let target = try AppLocation.copyToApplications(bundleURL: Bundle.main.bundleURL)
            do {
                try RelaunchCommand(pid: ProcessInfo.processInfo.processIdentifier, target: target).start()
            } catch {
                return "grantpin was copied to \(DisplayText.sanitise(target.path, limit: 120)), but could not be opened. Open it from there."
            }
            NSApp.terminate(nil)
            return nil
        } catch AppLocation.MoveError.alreadyThere(let path) {
            return "grantpin is already in \(DisplayText.sanitise(path, limit: 120)). Open that one instead."
        } catch {
            return "grantpin could not be copied to your Applications folder."
        }
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
