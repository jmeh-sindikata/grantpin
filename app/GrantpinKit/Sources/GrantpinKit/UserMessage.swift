import Foundation

/// An error, worded for the person looking at the window (docs/UI-SPEC.md 3.0
/// "Error mapping"). The headline is fixed text; `detail` is the daemon's own
/// message, already sanitised, and shown in smaller type underneath.
public struct UserMessage: Equatable, Sendable {
    public enum Action: Equatable, Sendable {
        /// "Create your vault first." -> the popover's Create vault button.
        case setUp
        /// "Use Repair in Settings."
        case repair
        /// "Open Logs Folder."
        case openLogs
    }

    public enum Severity: Equatable, Sendable {
        case error, warning, info
    }

    public var headline: String
    public var detail: String?
    public var action: Action?
    public var severity: Severity
    /// The data on screen may be out of date; reload it.
    public var refreshAdvised: Bool

    public init(_ headline: String, detail: String? = nil, action: Action? = nil,
                severity: Severity = .error, refreshAdvised: Bool = false) {
        self.headline = headline
        self.detail = detail
        self.action = action
        self.severity = severity
        self.refreshAdvised = refreshAdvised
    }

    /// The text of the banner as one string (tests, accessibility).
    public var text: String {
        guard let detail, !detail.isEmpty else { return headline }
        return headline + " " + detail
    }

    /// Maps any error a call can throw.
    public static func from(_ error: Error) -> UserMessage {
        if error is CancellationError { return UserMessage("The request was cancelled.", severity: .info) }
        guard let e = error as? GrantpinError else { return UserMessage("grantpin could not finish this.") }
        return from(e)
    }

    public static func from(_ error: GrantpinError) -> UserMessage {
        switch error {
        case .notRunning:
            return UserMessage("grantpin is not running.", detail: "Start it from the menu bar item.")
        case .socketPathTooLong:
            return UserMessage("Your account name is too long for grantpin's default socket path.")
        case .requestTooLarge:
            return UserMessage("That is too large to send.", detail: "A value can be 1 MiB at most.")
        case .invalidRequest(let why):
            return UserMessage("Not sent.", detail: DisplayText.sanitise(why))
        case .peerNotGrantpin:
            return UserMessage(PeerVerifier.mismatchMessage)
        case .noResponse:
            return UserMessage("grantpin closed the connection without answering.")
        case .timeout:
            return UserMessage("grantpin took too long to answer.")
        case .malformedResponse:
            return UserMessage("grantpin printed something unexpected.")
        case .io:
            return UserMessage("The app could not talk to grantpin.")
        case .daemon(let category, let reason, let message):
            let detail = message.isEmpty ? nil : DisplayText.sanitise(message)
            return fromDaemon(category: category, reason: reason, detail: detail)
        }
    }

    private static func fromDaemon(category: ErrorCategory, reason: ErrorReason, detail: String?) -> UserMessage {
        switch reason {
        case .vaultNotInitialized:
            return UserMessage("Create your vault first.", action: .setUp)
        case .secretExists:
            return UserMessage("A secret with this name already exists.", refreshAdvised: true)
        case .secretNotFound:
            return UserMessage("That secret no longer exists.", refreshAdvised: true)
        case .grantNotFound:
            return UserMessage("That grant is already gone.", refreshAdvised: true)
        case .userDenied:
            return UserMessage("You cancelled the confirmation.", severity: .info)
        case .approverUnavailable:
            return UserMessage("grantpin could not show the confirmation dialog. Make sure you are logged in at this Mac and have a device password, then try again.")
        case .policyRefused:
            return UserMessage("A .grantpin.yml file in that folder does not allow this.", detail: detail)
        case .tierUnmet:
            return UserMessage("This secret needs a stronger protection level than this vault provides.", detail: detail)
        case .secretExpired:
            return UserMessage("That secret has expired.", refreshAdvised: true)
        case .badRequest:
            return UserMessage("grantpin rejected the request:", detail: detail)
        case .unsupportedVersion:
            return UserMessage("This app and the background service are out of step. Use Repair in Settings.", action: .repair)
        case .canceled:
            return UserMessage("The request was cancelled.", severity: .info)
        case .timeout:
            return UserMessage("grantpin took too long to answer.")
        case .internalError:
            return UserMessage("grantpin had an internal error. Details are in the log.", action: .openLogs)
        case .vaultLocked:
            return UserMessage("Unlock your Mac to use secrets.", severity: .warning)
        case .responseTooLarge:
            return UserMessage("The answer was too large to send in one piece.")
        default:
            break
        }
        switch category {
        case .denied: return UserMessage("grantpin said no.", detail: detail)
        case .refused: return UserMessage("grantpin refused this.", detail: detail)
        case .badRequest: return UserMessage("grantpin rejected this request.", detail: detail)
        case .notFound: return UserMessage("Not found.", detail: detail, refreshAdvised: true)
        case .failed, .unknown: return UserMessage("grantpin could not finish this.", detail: detail)
        }
    }
}

/// The wording of the confirmations (docs/UI-SPEC.md 3.2). One place, so the
/// strings are tested and the views only show them.
public struct Confirmation: Equatable, Sendable {
    public var title: String
    public var message: String
    public var confirmLabel: String

    /// `Delete "{name}"?`, or `Delete {n} secrets?` for several.
    /// `grantsMentioning` is how many active grants name exactly one of them.
    public static func delete(names: [String], grantsMentioning: Int = 0) -> Confirmation {
        if names.count == 1 {
            var message = "This permanently deletes the secret and its value from this Mac. "
                + "Programs and agents that ask for it will get \"secret not found\". This can't be undone."
            if grantsMentioning == 1 {
                message += "\n\n1 active grant mentions this secret. It stays in place but won't work until you add it again."
            } else if grantsMentioning > 1 {
                message += "\n\n\(grantsMentioning) active grants mention this secret. They stay in place but won't work until you add it again."
            }
            return Confirmation(title: "Delete \"\(DisplayText.sanitise(names[0]))\"?", message: message, confirmLabel: "Delete")
        }
        let n = names.count
        return Confirmation(
            title: "Delete \(n) secrets?",
            message: "This permanently deletes \(n) secrets and their values from this Mac. This can't be undone.",
            confirmLabel: "Delete")
    }

    /// `Replace "{name}"?`
    public static func replace(name: String) -> Confirmation {
        Confirmation(
            title: "Replace \"\(DisplayText.sanitise(name))\"?",
            message: "The current value will be overwritten. It can't be recovered.",
            confirmLabel: "Replace")
    }

    /// `Overwrite {n} existing secrets?` with up to ten names.
    public static func importOverwrite(names: [String]) -> Confirmation {
        let shown = names.prefix(10).map { DisplayText.sanitise($0) }.joined(separator: ", ")
        let more = names.count > 10 ? " and \(names.count - 10) more" : ""
        let n = names.count
        return Confirmation(
            title: n == 1 ? "Overwrite 1 existing secret?" : "Overwrite \(n) existing secrets?",
            message: "These secrets will get the values from the file: \(shown)\(more). The old values can't be recovered.",
            confirmLabel: "Overwrite")
    }

    /// Shown before a protection level is lowered; the daemon then asks itself.
    public static let lowerProtectionNote =
        "Lowering the protection asks for confirmation: a dialog first, then Touch ID. "
        + "Nothing changes unless you approve both."
}
