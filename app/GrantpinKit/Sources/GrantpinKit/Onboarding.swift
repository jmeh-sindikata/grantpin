import Foundation
import Observation

/// The five steps of onboarding (docs/UI-SPEC.md 3.6).
public enum OnboardingStep: Int, CaseIterable, Sendable, Comparable {
    case welcome, service, vault, firstSecret, connect

    public static func < (a: OnboardingStep, b: OnboardingStep) -> Bool { a.rawValue < b.rawValue }

    public var title: String {
        switch self {
        case .welcome: return "Welcome"
        case .service: return "Background service"
        case .vault: return "Vault"
        case .firstSecret: return "First secret"
        case .connect: return "Connect Claude Code"
        }
    }
}

/// The Welcome window. State-derived, not flag-derived: a step shows as done
/// when its condition already holds, so an existing install skips straight to
/// Connect. The `onboardingDone` preference only decides whether the window
/// opens by itself at launch.
@Observable
@MainActor
public final class OnboardingModel {
    public private(set) var connection: ConnectionState?
    public var location: AppLocation
    public private(set) var step: OnboardingStep = .welcome
    public private(set) var running: OnboardingStep?
    public private(set) var lastResult: ActionResult?
    /// Creating the vault failed because the Secure Enclave is unavailable;
    /// the weaker Keychain protection may be offered.
    public private(set) var offersWeakerProtection = false
    /// The person pressed Done on the last step.
    public private(set) var finished = false
    public var startAtLogin = true
    public private(set) var loginError: String?

    public let isDevelopment: Bool

    @ObservationIgnored private let control: ServiceControl?
    @ObservationIgnored private let loginItem: LoginItemControl?
    @ObservationIgnored private let onFinished: @MainActor () -> Void
    @ObservationIgnored private let onActionFinished: @MainActor () async -> Void
    @ObservationIgnored private var positioned = false

    public static let welcomeLines = [
        "Agents like Claude Code can use your passwords and API keys without ever seeing them.",
        "Each time one asks, you see the exact command and approve with Touch ID.",
        "Your secrets stay on this Mac, encrypted.",
    ]
    public static let serviceText =
        "grantpin needs a small background service so agents can reach it. macOS may tell you a background item was added; that is this."
    public static let vaultText =
        "Your vault is where secrets are kept. Its key lives in this Mac's Secure Enclave and can't be copied off. "
        + "You'll use Touch ID when an agent asks to use a secret. Saving a secret here doesn't need it."
    public static let firstSecretText = "Add your first secret, or import a .env file."
    public static let noHardwareText = "This Mac can't create a hardware key (for example inside a virtual machine)."
    public static let weakerConfirmation = Confirmation(
        title: "Use weaker protection?",
        message: "The vault key will be kept in your Keychain instead of the Secure Enclave. Programs running as you could read it. Touch ID still protects every use of a secret.",
        confirmLabel: "Use Keychain")
    public static let loginLabel = "Start grantpin when I log in"

    public init(control: ServiceControl?, loginItem: LoginItemControl?, isDevelopment: Bool, location: AppLocation = .ok,
                onFinished: @escaping @MainActor () -> Void = {}, onActionFinished: @escaping @MainActor () async -> Void = {}) {
        self.control = control
        self.loginItem = loginItem
        self.isDevelopment = isDevelopment
        self.location = location
        self.onFinished = onFinished
        self.onActionFinished = onActionFinished
    }

    // MARK: derived state

    public func connectionChanged(_ state: ConnectionState?) {
        connection = state
        if !positioned, state != nil {
            positioned = true
            step = firstOpenStep
        }
    }

    public func isDone(_ s: OnboardingStep) -> Bool {
        switch s {
        case .welcome: return location.isOK || isDevelopment
        case .service:
            switch connection {
            case nil, .notRunning?: return false
            default: return true
            }
        case .vault:
            switch connection {
            case .ready?, .locked?: return true
            default: return false
            }
        case .firstSecret:
            if case .ready(let st)? = connection { return st.secrets > 0 }
            return false
        case .connect: return finished
        }
    }

    /// Where the window opens. A person whose daemon does not answer yet is
    /// new here and starts at the Welcome page; anyone whose service already
    /// answers gets the first later step that is still open, so an existing
    /// install skips straight to Connect.
    public var firstOpenStep: OnboardingStep {
        if !isDone(.welcome) || !isDone(.service) { return .welcome }
        return OnboardingStep.allCases.first { !isDone($0) } ?? .connect
    }

    public var vaultProtectionLine: String? {
        if case .ready(let s)? = connection {
            return "Protection: " + (s.keystoreTier.rank >= 2 ? "Secure Enclave" : s.keystoreTier.rank == 1 ? "Keychain only (weaker)" : "None (development build)")
        }
        return nil
    }

    public var actionsDisabledReason: String? {
        if isDevelopment { return "In development mode the background service and the vault are not touched." }
        if control == nil { return "The helper inside this app could not be found." }
        if !location.isOK { return AppLocation.blockedMessage }
        return nil
    }

    // MARK: navigation

    public var canGoBack: Bool { step > .welcome }

    /// Continue is available when the current step's condition holds. The
    /// Welcome step is held back by the location check (the move button
    /// replaces Continue); the last step ends with Done.
    public var canContinue: Bool { step < .connect && isDone(step) }

    /// Skip on the first-secret step.
    public var canSkip: Bool { step == .firstSecret && !isDone(.firstSecret) }

    public func next() {
        guard let n = OnboardingStep(rawValue: step.rawValue + 1) else { return }
        step = n
        lastResult = nil
    }

    public func skip() { if canSkip { next() } }

    public func back() {
        guard let p = OnboardingStep(rawValue: step.rawValue - 1) else { return }
        step = p
        lastResult = nil
    }

    /// Jumps to a step (the popover's Set Up opens the window at the vault
    /// step). Once the person or the app chose a step, later status polls no
    /// longer move it.
    public func go(to s: OnboardingStep) { step = s; lastResult = nil; positioned = true }

    // MARK: actions

    public func installService() async {
        guard step == .service, actionsDisabledReason == nil, let control, running == nil else { return }
        running = .service
        lastResult = nil
        lastResult = await control.installService(path: nil)
        running = nil
        await onActionFinished()
    }

    public func createVault() async {
        guard actionsDisabledReason == nil, let control, running == nil else { return }
        running = .vault
        lastResult = nil
        offersWeakerProtection = false
        let r = await control.initVault(keychainFallback: false)
        lastResult = r
        offersWeakerProtection = r.secureEnclaveUnavailable
        running = nil
        await onActionFinished()
    }

    /// After the person confirmed `weakerConfirmation`: `init --keychain-fallback`.
    public func createVaultWithWeakerProtection() async {
        guard offersWeakerProtection, actionsDisabledReason == nil, let control, running == nil else { return }
        running = .vault
        lastResult = nil
        let r = await control.initVault(keychainFallback: true)
        lastResult = r
        offersWeakerProtection = r.secureEnclaveUnavailable
        running = nil
        await onActionFinished()
    }

    /// Done: starts the app at login if asked, and records that onboarding is over.
    public func finish() {
        loginError = nil
        if startAtLogin, !isDevelopment, location.isOK, let loginItem, loginItem.status == .notRegistered {
            do { try loginItem.register() } catch { loginError = "grantpin could not be added to the login items." }
        }
        finished = true
        onFinished()
    }
}
