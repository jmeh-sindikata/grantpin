import Foundation
import GrantdKit

/// Plain-text rendering of the daemon's connection state for the stub popover
/// (docs/UI-SPEC.md 3.1). The real status header, with colours and actions,
/// arrives with the shell step; this only proves `DaemonMonitor` is wired up.
enum StatusText {
    static func headline(_ state: ConnectionState?) -> String {
        switch state {
        case nil: return "Checking…"
        case .notRunning?: return "grantd is not running"
        case .locked?: return "Waiting for the vault key"
        case .notInitialized?: return "grantd is running · no vault yet"
        case .ready(let s)?:
            let secrets = s.secrets == 1 ? "1 secret" : "\(s.secrets) secrets"
            let grants = s.activeGrants == 1 ? "1 active grant" : "\(s.activeGrants) active grants"
            return "grantd is running · \(secrets) · \(grants)"
        }
    }

    /// A second line, or nil. Daemon text is untrusted: it goes through the sanitiser.
    static func detail(_ state: ConnectionState?) -> String? {
        switch state {
        case .locked(let lastError)?:
            let base = "The Mac may be locked. grantd keeps trying."
            guard let lastError, !lastError.isEmpty else { return base }
            return base + " " + DisplayText.sanitise(lastError)
        default:
            return nil
        }
    }
}
