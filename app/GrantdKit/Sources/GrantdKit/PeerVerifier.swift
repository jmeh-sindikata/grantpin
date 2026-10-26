import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

/// Checks who answers on the daemon's socket before the app sends a typed
/// secret value there (docs/UI-SPEC.md 4.8).
///
/// The socket lives in a folder the user owns, so any program running as the
/// user can bind that path before the real daemon does, or after it was
/// stopped, and receive whatever the app sends. Read-only requests reveal
/// nothing a program with the same rights could not read anyway, so they are
/// not checked. A request that carries a plaintext value is: the peer's code
/// must be signed by the same team as this app.
///
/// - The peer's pid comes from `LOCAL_PEERPID` on the connected socket, its
///   code object from `SecCodeCopyGuestWithAttributes` (`kSecGuestAttributePid`),
///   and `SecCodeCheckValidity` tests it against
///   `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`.
/// - `<TEAMID>` is read from this app's own signature at run time. A build
///   with no team identifier (an unsigned or ad-hoc development build, the
///   unit tests) skips the check, and says nothing.
public struct PeerCheck: Sendable {
    /// The team identifier peers must be signed with, or nil to skip the check.
    let teamIdentifier: @Sendable () -> String?

    public init(teamIdentifier: @escaping @Sendable () -> String?) {
        self.teamIdentifier = teamIdentifier
    }

    /// This app's own team identifier, if it has one.
    public static let automatic = PeerCheck { PeerVerifier.ownTeamIdentifier }
    /// No check (development mode, which talks to the insecure dev daemon).
    public static let off = PeerCheck { nil }
    /// A fixed team, for tests.
    public static func team(_ id: String) -> PeerCheck { PeerCheck { id } }
}

public enum PeerVerifier {
    /// Shown when the check fails. Nothing was sent.
    public static let mismatchMessage = "The process answering grantd's socket is not grantd. Nothing was sent."

    /// `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`,
    /// or nil unless `teamID` looks like a team identifier (ten upper-case
    /// letters or digits), so nothing but that can ever reach the requirement
    /// language.
    public static func requirement(teamID: String) -> String? {
        guard isTeamIdentifier(teamID) else { return nil }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    static func isTeamIdentifier(_ s: String) -> Bool {
        s.utf8.count == 10 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) }
    }

    /// The team identifier in this process's signature, read once. Nil for an
    /// unsigned or ad-hoc signed build.
    public static let ownTeamIdentifier: String? = {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(me, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              isTeamIdentifier(team)
        else { return nil }
        return team
    }()

    public enum Outcome: Equatable, Sendable {
        /// The check does not apply (no team identifier).
        case skipped
        /// The peer is signed by the team.
        case verified
        /// Anything else, including every failure to find out.
        case mismatch
    }

    /// Checks the peer of the connected socket `fd`. Fails closed: when a
    /// team is known and the pid, the code object or the requirement cannot be
    /// had, the answer is `mismatch`.
    static func check(socket fd: Int32, using policy: PeerCheck) -> Outcome {
        guard let team = policy.teamIdentifier() else { return .skipped }
        guard let requirement = requirement(teamID: team) else { return .skipped }
        guard let pid = peerPID(of: fd) else { return .mismatch }
        return isSigned(pid: pid, requirement: requirement) ? .verified : .mismatch
    }

    /// The pid of the process at the other end of the connected socket
    /// (`LOCAL_PEERPID`).
    static func peerPID(of fd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0, pid > 0 else { return nil }
        return pid
    }

    /// True if the process `pid` satisfies `requirement`.
    static func isSigned(pid: pid_t, requirement: String) -> Bool {
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest else { return false }
        var parsed: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess, let parsed else { return false }
        return SecCodeCheckValidity(guest, [], parsed) == errSecSuccess
    }
}
