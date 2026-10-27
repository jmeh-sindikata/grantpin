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

/// Who may be changing the background service right now, so that only one
/// thing does at a time (docs/UI-SPEC.md 3.1): the popover's Start, a
/// Settings action, onboarding's Install, the open Uninstall sheet or the
/// automatic restore or restart (both `ServiceRecovery`, the `.restore` part).
/// Each model asks whether anyone else is and refuses its own action meanwhile
/// (`ServiceBusy`); the automatic restore and restart do not start while
/// anyone is. The models are created one after another and each one's
/// closure has to see the others, so this exists first and they are attached
/// once they all exist.
@MainActor
@Observable
final class ServiceActivity {
    enum Part: CaseIterable {
        case popover, settings, onboarding, uninstall, restore
    }

    @ObservationIgnored weak var popover: PopoverModel?
    @ObservationIgnored weak var settings: SettingsModel?
    @ObservationIgnored weak var onboarding: OnboardingModel?
    @ObservationIgnored weak var recovery: ServiceRecovery?
    /// The Uninstall sheet is open: `service uninstall` may run any moment.
    var uninstallOpen = false

    /// Whether `part` is changing the service now.
    func isBusy(_ part: Part) -> Bool {
        switch part {
        case .popover: return popover?.running != nil
        case .settings: return settings?.isBusy == true
        case .onboarding: return onboarding?.running != nil
        case .uninstall: return uninstallOpen
        case .restore: return recovery?.isRestoring == true
        }
    }

    /// Something other than `own` is changing the service.
    func busy(besides own: Set<Part>) -> Bool {
        Part.allCases.contains { !own.contains($0) && isBusy($0) }
    }

    /// Anything is.
    var anyBusy: Bool { busy(besides: []) }
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
    /// Restores a service the person had installed, or asks about it.
    let serviceRecovery: ServiceRecovery
    /// Who is changing the service right now (one action at a time).
    let serviceActivity: ServiceActivity
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
    @ObservationIgnored private var recoveryTimer: Task<Void, Never>?
    @ObservationIgnored private var observers = [NSObjectProtocol]()
    /// The facts the recovery decision was last told about (`watchRecoveryTriggers`).
    @ObservationIgnored private var lastRecoveryTriggers: RecoveryTriggers?

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
        // One service action at a time: each model is told when another one,
        // or the automatic restore, is changing the service (ServiceActivity).
        let serviceActivity = ServiceActivity()
        self.serviceActivity = serviceActivity

        self.popover = PopoverModel(
            audit: client, actions: actions, developmentSocket: devSocket, secrets: client, location: location,
            onActionFinished: refresh,
            // The automatic restore runs through this model's Start, so it is not someone else here.
            externallyBusy: { serviceActivity.busy(besides: [.popover, .restore]) })
        self.secrets = SecretsViewModel(service: client, pasteboard: SystemPasteboard())
        self.grants = GrantsViewModel(service: client)
        self.activity = ActivityViewModel(service: client)
        let login = loginItem
        self.settings = SettingsModel(
            control: actions, loginItem: login, developmentSocket: devSocket, resolvedSocket: socket.path,
            location: location, onChanged: refresh, externallyBusy: { serviceActivity.busy(besides: [.settings]) })
        // The link points at the helper of THIS bundle, never at the development override.
        let bundledHelper = try? HelperLocator.resolve(bundleURL: Bundle.main.bundleURL)
        self.commandLine = CommandLineToolModel(
            tool: CommandLineTool(bundleURL: Bundle.main.bundleURL, helper: bundledHelper),
            location: location, isDevelopment: socket.isDevelopment, shell: CommandLineToolModel.loginShell())
        self.onboarding = OnboardingModel(
            control: actions, loginItem: login, isDevelopment: socket.isDevelopment, location: location,
            onFinished: { UserDefaults.standard.set(true, forKey: AppModel.onboardingDoneKey) },
            onActionFinished: refresh, externallyBusy: { serviceActivity.busy(besides: [.onboarding]) })
        // The service status is only looked at while the daemon is down, and never in development mode.
        let watcher = ServiceWatcher(control: socket.isDevelopment ? nil : actions)
        self.serviceWatcher = watcher
        let popoverModel = self.popover
        // Restores the service itself only when the person installed it before
        // (the `service.wanted` marker); otherwise it asks (ServiceAskGate).
        // Restarts it after an update while nothing runs through it
        // (ServiceRestartPolicy); otherwise it asks as well.
        self.serviceRecovery = ServiceRecovery(
            connection: { monitor.state }, location: location, isDevelopment: socket.isDevelopment,
            onboardingPending: { !UserDefaults.standard.bool(forKey: AppModel.onboardingDoneKey) },
            popoverOpen: { AppModel.current?.isPopoverOpen ?? false },
            suspended: { serviceActivity.busy(besides: [.restore]) },
            refresh: refresh,
            diagnose: { await watcher.poll(); return watcher.diagnosis },
            restore: {
                // The same action as the Start button; what this run did, not
                // the screen's `lastResult`, which may be dismissed meanwhile.
                await popoverModel.perform(.startService)
            },
            // The helper's version as the popover knows it, determined once per launch below.
            helperVersion: { AppModel.current?.helperVersion },
            // The same action as the Restart button.
            restart: { await popoverModel.perform(.restart) })
        serviceActivity.popover = popoverModel
        serviceActivity.settings = self.settings
        serviceActivity.onboarding = self.onboarding
        serviceActivity.recovery = self.serviceRecovery

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
        // The recovery decision follows these facts for the app's lifetime,
        // starting with one look now (the first state is not in yet, so this
        // is the "checking" look; the first poll brings the next).
        watchRecoveryTriggers()
        serviceRecoveryCheck()
    }

    // MARK: the recovery decision's triggers

    /// What `serviceRecoveryCheck()` is driven by: the connection, whether a
    /// service action is running (`ServiceActivity`), onboarding being done,
    /// what `service status` says and the helper's version.
    private struct RecoveryTriggers: Equatable {
        var state: ConnectionState?
        var anyBusy: Bool
        var onboardingFinished: Bool
        var diagnosis: ServiceDiagnosis?
        var helperVersion: String?
    }

    /// Reads the triggers; inside `withObservationTracking` that also records
    /// which observable properties they depend on.
    private func currentRecoveryTriggers() -> RecoveryTriggers {
        RecoveryTriggers(state: monitor.state, anyBusy: serviceActivity.anyBusy, onboardingFinished: onboarding.finished,
                         diagnosis: serviceWatcher.diagnosis, helperVersion: helperVersion)
    }

    /// Watches the triggers with the Observation framework instead of
    /// `onChange` modifiers on the menu-bar label: the label must depend only
    /// on what the icon shows, because a `.window`-style `MenuBarExtra` whose
    /// label re-evaluates while the popover is open, or at the moment a popover
    /// row hands over to a new window, can leave the popover standing (the
    /// 0.2.4 regression). `withObservationTracking` fires once, before the
    /// change is applied, so the work is deferred to the main actor's next
    /// turn, compared with the facts last seen and re-armed.
    private func watchRecoveryTriggers() {
        let seen = withObservationTracking {
            currentRecoveryTriggers()
        } onChange: {
            // Called before the change lands, from any thread, and not Sendable
            // safe for `self`: the running instance is reached as the delegate does.
            Task { @MainActor in AppModel.current?.recoveryTriggersChanged() }
        }
        if lastRecoveryTriggers == nil { lastRecoveryTriggers = seen }
    }

    /// The same rules the label's `onChange` modifiers had: every change of
    /// the connection, of `service status` or of the helper's version looks
    /// again; a service action ending (busy going false) and onboarding
    /// finishing (finished going true) do too; nothing else does.
    private func recoveryTriggersChanged() {
        let previous = lastRecoveryTriggers
        watchRecoveryTriggers()  // re-arm first: a change made by the check itself must be seen
        let now = currentRecoveryTriggers()
        lastRecoveryTriggers = now
        guard let previous, previous != now else { return }  // a write of the same value
        var due = previous.state != now.state || previous.diagnosis != now.diagnosis || previous.helperVersion != now.helperVersion
        if previous.anyBusy && !now.anyBusy { due = true }
        if !previous.onboardingFinished && now.onboardingFinished { due = true }
        if due { serviceRecoveryCheck() }
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

    /// The window that hosts the popover's content, handed over by the
    /// popover's `WindowKeyObserver` while it is in one.
    @ObservationIgnored weak var popoverWindow: NSWindow?

    /// Closes the popover (docs/UI-SPEC.md 3.1): a row or button that opens a
    /// window or Finder calls this first, so the new window becomes key
    /// instead of appearing behind the popover. SwiftUI offers no way to
    /// dismiss a `.window`-style `MenuBarExtra` from its content, so this goes
    /// to the hosting `NSWindow`. Nothing happens when the popover is not
    /// showing. The key observer's `didResignKey`/`willClose` notifications
    /// still report the popover as gone (`surfaceDisappeared`).
    func closePopover() {
        guard let window = popoverWindow, window.isVisible else { return }
        window.close()
        if window.isVisible { window.orderOut(nil) }
    }

    /// Brings the background service back by itself when the person had
    /// installed it, restarts it after an update while nothing runs through
    /// it, and otherwise opens the "background service" window once (see
    /// `ServiceRecovery`, `ServiceRestorePolicy`, `ServiceRestartPolicy` and
    /// `ServiceAskGate` for when). Called on every connection change, when a
    /// service action ends, when onboarding finishes, when `service status`
    /// changes, when the helper's version becomes known (`watchRecoveryTriggers`)
    /// and again when the next decision is due. The service is never installed
    /// here unless the marker says the person installed it before.
    func serviceRecoveryCheck() {
        recoveryTimer?.cancel()
        recoveryTimer = nil
        Task { [weak self] in
            guard let self else { return }
            switch await serviceRecovery.check() {
            case .askNow: await presentServiceAsk()
            case .askRestart: presentRestartAsk()
            case .nothing: break
            }
            guard let wait = serviceRecovery.nextCheck() else { return }
            recoveryTimer?.cancel()
            recoveryTimer = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64((wait + 0.5) * 1_000_000_000))
                guard !Task.isCancelled else { return }
                self?.serviceRecoveryCheck()
            }
        }
    }

    private func presentServiceAsk() async {
        // Know which of "not set up" and "stopped" is true before the window shows.
        await serviceWatcher.poll()
        guard case .notRunning? = monitor.state, !isPopoverOpen else { return }
        requestWindow(WindowID.serviceAsk)
    }

    /// The same window, with the "grantpin was updated" line and its Restart
    /// button (the closing button reads "Later"); only while that is still
    /// what the daemon's answer says.
    private func presentRestartAsk() {
        guard ServiceRestartPolicy.isMismatch(monitor.state, helperVersion: helperVersion), !isPopoverOpen else { return }
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
    /// Also hands over the hosting window itself (nil when the view leaves
    /// it); the popover uses it to close itself (`AppModel.closePopover`).
    var onWindow: ((NSWindow?) -> Void)? = nil

    func makeNSView(context: Context) -> NSView { Tracker(onChange: onChange, onWindow: onWindow) }
    func updateNSView(_ nsView: NSView, context: Context) {
        (nsView as? Tracker)?.onChange = onChange
        (nsView as? Tracker)?.onWindow = onWindow
    }

    final class Tracker: NSView {
        var onChange: (Bool) -> Void
        var onWindow: ((NSWindow?) -> Void)?
        private var observers = [NSObjectProtocol]()

        init(onChange: @escaping (Bool) -> Void, onWindow: ((NSWindow?) -> Void)?) {
            self.onChange = onChange
            self.onWindow = onWindow
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }

        deinit { observers.forEach(NotificationCenter.default.removeObserver) }

        override func viewDidMoveToWindow() {
            observers.forEach(NotificationCenter.default.removeObserver)
            observers = []
            onWindow?(window)
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
