import Foundation

/// One logical thing that happened, built from one or two audit rows.
///
/// A released run is two rows in the log (README "Audit"): an `allowed_*` row
/// with reason `released`, then a `completed` row with the result. There is no
/// run ID, so `AuditPairing` matches them by caller, folder, command, secrets
/// and grant. Every string is untrusted for display; `title`, `command` and
/// `summary` are already sanitised (`DisplayText`).
public struct AuditEvent: Equatable, Identifiable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// A command that was given secrets (released, possibly completed).
        case run
        /// A change made through the protocol: set, delete, update, show.
        case change
        /// A standing grant created from the app.
        case standingGrant
        /// Denied, blocked or errored: nothing was released.
        case refused
        /// A `completed` row whose `released` row is not in the loaded rows.
        case resultOnly
    }

    public enum Result: Equatable, Sendable {
        /// Not a run, or no result to show.
        case none
        /// Finished with this exit code (nil if the row carried none).
        case finished(exitCode: Int?, durationMS: Int64)
        /// Released less than an hour ago and not completed yet.
        case running
        /// Released more than an hour ago and never completed: the daemon
        /// stopped mid-run.
        case noResultRecorded
        /// The partner row is outside the loaded window.
        case outsideWindow
    }

    /// The id of the newest row of the event; unique within one list.
    public var id: String
    /// Every row id merged into this event, oldest first.
    public var rowIDs: [String]
    /// When the event started (the released row), or when it happened.
    public var time: Date
    public var kind: Kind
    /// "Used a grant", "You said no", "Secret saved", ...
    public var title: String
    /// The command line, or the secret name for a change; sanitised and cut
    /// for a table cell. Empty when there is nothing to show.
    public var command: String
    public var caller: String
    public var secrets: [String]
    public var result: Result
    /// One line for lists: `Ran "php artisan" (DB_URL) · exit 0 · 1.2 s`.
    public var summary: String
    /// The `decision` of the event's first row (`allowed_once`, `denied_user`, ...).
    public var decision: String = ""
    /// The `reason` of the first row, sanitised.
    public var reason: String = ""
}

public enum AuditPairing {
    /// A released run with no result younger than this is shown as running.
    public static let runningWindow: TimeInterval = 3600

    /// The label for a row (docs/UI-SPEC.md 3.4). `reason` is the row's
    /// `reason` field.
    public static func label(decision: String, reason: String) -> String {
        switch (decision, reason) {
        case ("allowed_grant", _): return "Used a grant"
        case ("allowed_once", "set"): return "Secret saved"
        case ("allowed_once", "delete"): return "Secret deleted"
        case ("allowed_once", "show"): return "Secret revealed in a terminal"
        case ("allowed_once", let r) where r == "update" || r.hasPrefix("update"): return "Secret details changed"
        case ("allowed_once", "grants revoke"): return "Grant revoked"
        case ("allowed_once", "grants revoke_all"): return "All grants revoked"
        case ("allowed_once", _): return "Allowed once"
        case ("allowed_new_grant", "standing"): return "Standing grant created"
        case ("allowed_new_grant", _): return "Allowed for a while (grant created)"
        case ("denied_user", _): return "You said no"
        case ("refused_policy", _): return "Blocked by .grantpin.yml"
        case ("refused_tier", _): return "Blocked: protection level"
        case ("error", _): return "Error"
        case ("completed", _): return "Finished"
        default: return "Activity"
        }
    }

    /// Pairs and labels the rows.
    ///
    /// - Parameters:
    ///   - entries: rows as `audit list` returns them, newest first.
    ///   - windowIsComplete: true when the log was loaded to its start (fewer
    ///     rows came back than were asked for); false when older rows exist.
    ///     A `completed` row without its `released` row is then probably cut
    ///     at the edge and shows a neutral "…" instead of a verdict.
    ///   - now: for the one-hour "Running…" rule.
    /// - Returns: events, newest first.
    public static func pair(_ entries: [AuditEntry], windowIsComplete: Bool, now: Date = Date()) -> [AuditEvent] {
        struct Open { var index: Int; var entry: AuditEntry }
        let oldestFirst = Array(entries.reversed())
        var events = [AuditEvent]()
        var open = [Open]()

        func tagged(_ e: AuditEvent, _ entry: AuditEntry) -> AuditEvent {
            var e = e
            e.decision = entry.decision
            e.reason = DisplayText.sanitise(entry.reason)
            return e
        }
        for entry in oldestFirst {
            if isReleased(entry) {
                events.append(tagged(event(for: entry, now: now), entry))
                open.append(Open(index: events.count - 1, entry: entry))
            } else if entry.decision == "completed" {
                if let k = partner(for: entry, in: open.map(\.entry)) {
                    let o = open.remove(at: k)
                    events[o.index] = tagged(merged(released: o.entry, completed: entry), o.entry)
                } else {
                    events.append(tagged(resultOnly(entry, windowIsComplete: windowIsComplete), entry))
                }
            } else {
                events.append(tagged(event(for: entry, now: now), entry))
            }
        }
        return events.reversed()
    }

    /// The last `count` events, newest first (the popover).
    public static func recent(_ entries: [AuditEntry], windowIsComplete: Bool, count: Int = 3, now: Date = Date()) -> [AuditEvent] {
        Array(pair(entries, windowIsComplete: windowIsComplete, now: now).prefix(count))
    }

    // MARK: rows

    static func isReleased(_ e: AuditEntry) -> Bool {
        e.decision.hasPrefix("allowed_") && e.reason == "released" && e.exitCode == nil
    }

    /// How far after a run's computed start a `released` row may be and still
    /// count as its own (millisecond rounding: the daemon writes the released row before it
    /// spawns the command, so a run never starts before its own row).
    static let startTolerance: TimeInterval = 0.01

    /// The index (into `open`, oldest first) of the `released` row that
    /// `completed` belongs to, or nil when no open row has the same shape.
    ///
    /// There is no run ID, so identical runs are told apart by time: the
    /// completed row's start is its `ts` minus `durationMS`, and the owner is
    /// the open row nearest at or before that instant (`startTolerance`
    /// allowed after it). That keeps a retry from attaching to an older run
    /// whose daemon died (the orphan stays "no result recorded") and keeps
    /// concurrent identical runs that finish out of order from swapping
    /// results. If no open row qualifies, the newest matching one is used.
    static func partner(for completed: AuditEntry, in open: [AuditEntry]) -> Int? {
        let candidates = open.indices.filter { sameRun(open[$0], completed) }
        guard let newest = candidates.last else { return nil }
        let start = completed.ts.addingTimeInterval(-Double(max(completed.durationMS, 0)) / 1000)
        let limit = start.addingTimeInterval(startTolerance)
        return candidates.filter { open[$0].ts <= limit }.max(by: { open[$0].ts < open[$1].ts }) ?? newest
    }

    static func sameRun(_ a: AuditEntry, _ b: AuditEntry) -> Bool {
        a.caller == b.caller && a.cwd == b.cwd && a.argv == b.argv && a.secrets == b.secrets && a.grantID == b.grantID
    }

    // MARK: events

    private static func command(_ e: AuditEntry) -> String {
        DisplayText.argvLine(e.argv, limit: DisplayText.cellLimit)
    }

    private static func secretsText(_ e: AuditEntry) -> String {
        let names = (e.expanded?.isEmpty == false ? e.expanded! : e.secrets)
        return DisplayText.sanitise(names.joined(separator: ", "), limit: DisplayText.cellLimit)
    }

    /// A grant revocation: `grants revoke` (one row, with the grant id) or
    /// `grants revoke_all` (one row per removed grant, or one row without a
    /// grant id when there was none). Never paired with a run.
    private static func isRevocation(_ e: AuditEntry) -> Bool {
        e.decision == "allowed_once" && (e.reason == "grants revoke" || e.reason == "grants revoke_all")
    }

    private static func isLifecycle(_ e: AuditEntry) -> Bool {
        // Only a row the daemon allowed is a change. A denied or failed lower-protection
        // update has reason "update: lower min_tier..." too, and stays a refusal (with its reason).
        e.decision == "allowed_once" && (["set", "delete", "show"].contains(e.reason) || e.reason.hasPrefix("update"))
    }

    /// A row that stands alone (or a released row that is still open).
    private static func event(for e: AuditEntry, now: Date) -> AuditEvent {
        let title = label(decision: e.decision, reason: e.reason)
        if isReleased(e) {
            let age = now.timeIntervalSince(e.ts)
            let result: AuditEvent.Result = age < runningWindow ? .running : .noResultRecorded
            let cmd = command(e)
            let tail = result == .running ? "Running…" : "no result recorded"
            let summary = result == .running
                ? "Running \"\(cmd)\" (\(secretsText(e))) · \(tail)"
                : "Started \"\(cmd)\" - \(tail)"
            return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: .run, title: title, command: cmd,
                              caller: DisplayText.sanitise(e.caller), secrets: e.secrets, result: result, summary: summary)
        }
        if isLifecycle(e) {
            // The daemon records these with argv ["grantpin", verb, name].
            let name = e.argv.count >= 3 ? DisplayText.sanitise(e.argv[2]) : secretsText(e)
            return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: .change, title: title, command: name,
                              caller: DisplayText.sanitise(e.caller), secrets: e.secrets, result: .none,
                              summary: "\(title): \(name)")
        }
        if isRevocation(e) {
            // The daemon records the revoked grant in grant_id; a revoke-all that found
            // nothing has none.
            let id = DisplayText.sanitise(e.grantID)
            let summary = !id.isEmpty ? "\(title): \(id)"
                : e.reason == "grants revoke_all" ? "\(title): none were active" : title
            return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: .change, title: title, command: id,
                              caller: DisplayText.sanitise(e.caller), secrets: e.secrets, result: .none, summary: summary)
        }
        if e.decision == "allowed_new_grant" && e.reason == "standing" {
            let cmd = command(e)
            return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: .standingGrant, title: title, command: cmd,
                              caller: DisplayText.sanitise(e.caller), secrets: e.secrets, result: .none,
                              summary: cmd.isEmpty ? title : "\(title): \(cmd)")
        }
        let cmd = command(e)
        let reason = DisplayText.sanitise(e.reason)
        var summary = cmd.isEmpty ? title : "\(title): \(cmd)"
        if e.decision == "error", !reason.isEmpty { summary += " (\(reason))" }
        let kind: AuditEvent.Kind = e.decision.hasPrefix("allowed_") ? .run : .refused
        return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: kind, title: title, command: cmd,
                          caller: DisplayText.sanitise(e.caller), secrets: e.secrets, result: .none, summary: summary)
    }

    private static func merged(released: AuditEntry, completed: AuditEntry) -> AuditEvent {
        let title = label(decision: released.decision, reason: released.reason)
        let cmd = command(released)
        var summary = "Ran \"\(cmd)\" (\(secretsText(released)))"
        if let code = completed.exitCode { summary += " · exit \(code)" }
        let note = DisplayText.sanitise(completed.reason)
        if !note.isEmpty { summary += " · \(note)" }
        summary += " · \(duration(milliseconds: completed.durationMS))"
        return AuditEvent(id: completed.id, rowIDs: [released.id, completed.id], time: released.ts, kind: .run,
                          title: title, command: cmd, caller: DisplayText.sanitise(released.caller),
                          secrets: released.secrets,
                          result: .finished(exitCode: completed.exitCode, durationMS: completed.durationMS),
                          summary: summary)
    }

    private static func resultOnly(_ e: AuditEntry, windowIsComplete: Bool) -> AuditEvent {
        let cmd = command(e)
        var summary = "…"
        if windowIsComplete { summary = "Finished \"\(cmd)\" - no start recorded" }
        return AuditEvent(id: e.id, rowIDs: [e.id], time: e.ts, kind: .resultOnly, title: "Finished", command: cmd,
                          caller: DisplayText.sanitise(e.caller), secrets: e.secrets,
                          result: windowIsComplete ? .none : .outsideWindow, summary: summary)
    }

    /// `340 ms`, `1.2 s`, `2 min 5 s`.
    public static func duration(milliseconds: Int64) -> String {
        if milliseconds < 1000 { return "\(max(milliseconds, 0)) ms" }
        if milliseconds < 60_000 {
            let tenths = (milliseconds + 50) / 100
            return tenths % 10 == 0 ? "\(tenths / 10) s" : "\(tenths / 10).\(tenths % 10) s"
        }
        let totalSeconds = milliseconds / 1000
        return "\(totalSeconds / 60) min \(totalSeconds % 60) s"
    }
}
