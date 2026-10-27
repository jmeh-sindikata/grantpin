import Foundation
import Security

/// What macOS says when the background service is installed, and who it says
/// it is from. macOS shows a "background item added" notification that names
/// the developer from the app's signature, so the person is told what to
/// expect before it happens (docs/UI-SPEC.md 3.6).
public enum BackgroundItemNotice {
    /// The developer name shown when the app's own signature cannot be read
    /// (an unsigned or ad-hoc build, a fork that has not changed this). A
    /// signed build reads the name from its certificate instead (`developerName`).
    public static let fallbackDeveloperName = "S.A.P. SH.P.K."

    /// The developer as macOS names it: the name in the signing certificate of
    /// this app, read once, or `fallbackDeveloperName`.
    public static let developerName: String = {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return fallbackDeveloperName }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(me, [], &staticCode) == errSecSuccess, let staticCode else { return fallbackDeveloperName }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let chain = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = chain.first,
              let summary = SecCertificateCopySubjectSummary(leaf) as String?,
              let name = name(fromCertificateSummary: summary)
        else { return fallbackDeveloperName }
        return name
    }()

    /// "Developer ID Application: Some Name (ABCDE12345)" -> "Some Name". Nil
    /// for anything that does not have that shape, or an empty name.
    static func name(fromCertificateSummary summary: String) -> String? {
        let s = summary.trimmingCharacters(in: .whitespaces)
        guard let prefix = ["Developer ID Application: ", "Apple Distribution: ", "Apple Development: ", "Mac Developer: "]
            .first(where: { s.hasPrefix($0) }) else { return nil }
        var name = String(s.dropFirst(prefix.count))
        // A trailing " (TEAMID)".
        if name.hasSuffix(")"), let open = name.range(of: "(", options: .backwards),
           PeerVerifier.isTeamIdentifier(String(name[open.upperBound...].dropLast())) {
            name = String(name[..<open.lowerBound])
        }
        let clean = DisplayText.sanitise(name, limit: 60).trimmingCharacters(in: .whitespaces)
        return clean.isEmpty ? nil : clean
    }

    /// The onboarding step's sentence.
    public static func full(developer: String = developerName) -> String {
        "macOS will tell you that \(developer) (the developer of grantpin) added a background item. "
            + "That is grantpin's service; you can switch it off any time in System Settings > General > Login Items & Extensions."
    }

    /// The popover's line.
    public static func short(developer: String = developerName) -> String {
        "macOS will tell you that \(developer) added a background item. That is grantpin's service."
    }
}

/// Decides when the app opens a window on its own to ask the person to start
/// the background service, so a menu-bar icon that looks alive is never the
/// only sign of a service that is not.
///
/// A pure state machine: it is told the connection state and the time and
/// answers "open it now". The rules:
/// - The daemon must stay down for `grace` seconds first (at login the app can
///   start a moment before the service does).
/// - At most once per continuous not-running period. The period is used up
///   when the ask is made, whether the person acts on it or closes it, so it
///   is not repeated until the daemon has answered and gone down again.
/// - A daemon that was up for less than `stableUp` seconds before going down
///   again is the same trouble, not a new period (a service that keeps
///   stopping must not open a window every time).
/// - Never during first-run onboarding (the Welcome window asks already), in
///   development mode, or when the popover is open (the person is looking at it).
///   In those cases the period is used up without asking.
public struct ServiceAskGate: Sendable {
    public static let grace: TimeInterval = 10
    public static let stableUp: TimeInterval = 60

    enum Phase: Equatable, Sendable {
        case unknown
        case up(since: Date)
        case down(since: Date, handled: Bool)
    }

    private(set) var phase = Phase.unknown

    public init() {}

    /// Call on every connection change and again when `waitTime` has passed.
    /// Returns true exactly when the window should open now.
    public mutating func evaluate(
        _ state: ConnectionState?, now: Date, onboardingPending: Bool, isDevelopment: Bool, popoverOpen: Bool
    ) -> Bool {
        guard !isDevelopment, let state else { return false }
        guard case .notRunning = state else {
            if case .up = phase {} else { phase = .up(since: now) }
            return false
        }
        switch phase {
        case .unknown:
            phase = .down(since: now, handled: false)
            return false
        case .up(let since):
            phase = .down(since: now, handled: now.timeIntervalSince(since) < Self.stableUp)
            return false
        case .down(let since, let handled):
            guard !handled, now.timeIntervalSince(since) >= Self.grace else { return false }
            phase = .down(since: since, handled: true)
            return !onboardingPending && !popoverOpen
        }
    }

    /// How long until `evaluate` should be called again for a decision, nil
    /// when nothing is pending.
    public func waitTime(now: Date) -> TimeInterval? {
        guard case .down(let since, false) = phase else { return nil }
        return max(Self.grace - now.timeIntervalSince(since), 0)
    }
}
