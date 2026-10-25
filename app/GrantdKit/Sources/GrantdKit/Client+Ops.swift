import Foundation

// The ops the app uses, typed (docs/PROTOCOL.md "Ops"). The app never sends
// `show` or `run`: there is deliberately no method for either
// (docs/UI-SPEC.md 4.2).
extension Client {
    // MARK: status

    /// `status`. Works without a vault and while the vault is locked.
    public func status() async throws -> StatusResult {
        try await call(.status).decodeResult(StatusResult.self)
    }

    // MARK: secrets

    /// `list`: metadata of every secret (never a value), sorted by name.
    /// `tag` and `expiringWithin` filter on the daemon side.
    public func list(tag: String? = nil, expiringWithin: TimeInterval? = nil) async throws -> [SecretInfo] {
        var r = Request(op: "list")
        r.tag = tag
        r.expiringWithinS = expiringWithin.map { Int($0.rounded(.up)) }
        return try await call(r).decodeResult([SecretInfo].self)
    }

    /// `exists`.
    public func exists(_ name: String) async throws -> Bool {
        struct Result: Decodable { var exists: Bool }
        var r = Request(op: "exists")
        r.name = name
        return try await call(r).decodeResult(Result.self).exists
    }

    /// `masked`: `****` plus the last four characters for a value of at least
    /// 12 characters, else `********`. Needs no approval.
    public func masked(_ name: String) async throws -> String {
        struct Result: Decodable { var masked: String }
        var r = Request(op: "masked")
        r.name = name
        return try await call(r).decodeResult(Result.self).masked
    }

    /// `set`: stores `value` under `name`.
    ///
    /// `value` is the secret's bytes, typically taken from the sheet's
    /// `SecureField` the moment Save is pressed. It must be valid UTF-8 and is
    /// escaped straight into the request buffer. The request buffer is
    /// overwritten with zeros as soon as it has been written, and `value`
    /// itself is overwritten with zeros when this call returns or throws,
    /// whatever the outcome (so build a fresh `Data` for a retry). The value
    /// is never logged and appears in no error.
    ///
    /// Without `overwrite` an existing name fails with `secret_exists`. An
    /// overwrite replaces the old tags, URL, notes and expiry with the ones
    /// given here (`created_at` is kept). `minTier` nil is the vault default;
    /// the app never sends `none`. Not presence-gated.
    ///
    /// - Returns: the audit row's id.
    @discardableResult
    public func set(
        name: String, value: inout Data,
        tags: [String] = [], url: String? = nil, notes: String? = nil,
        expires: Date? = nil, minTier: Tier? = nil, overwrite: Bool = false
    ) async throws -> String {
        var r = Request(op: "set")
        r.name = name
        r.tags = tags.isEmpty ? nil : tags
        r.url = (url ?? "").isEmpty ? nil : url
        r.notes = (notes ?? "").isEmpty ? nil : notes
        r.expires = expires
        r.minTier = minTier
        r.overwrite = overwrite ? true : nil
        return try await call(r, value: &value).auditID
    }

    /// `update`: changes the metadata of an existing secret and never touches
    /// its value. A parameter that is nil (and not named in `clear`) is left as
    /// it is; `tags` replaces the whole list and must not be empty. An empty
    /// `url` or `notes` is the same as nil to the daemon: to remove a field use
    /// `clear` (`.tags`, `.url`, `.notes`, `.expires`). At least one thing must change, and a
    /// field cannot be both set and cleared (`bad_request`).
    ///
    /// Passing `minTier` can show a dialog and Touch ID: **lowering** a
    /// secret's level asks the human (docs/PROTOCOL.md `update`), so the call
    /// then uses the long human timeout and can be cancelled. Raising it, or
    /// leaving it, answers at once. Cancel, a refused dialog or an unavailable
    /// prompt change nothing, not even the other fields of the same request.
    ///
    /// - Returns: the audit row's id.
    @discardableResult
    public func update(
        name: String, tags: [String]? = nil, url: String? = nil, notes: String? = nil,
        expires: Date? = nil, minTier: Tier? = nil, clear: Set<ClearField> = []
    ) async throws -> String {
        if let tags, tags.isEmpty {
            throw GrantdError.invalidRequest("an empty tag list is not sent; use clear: [.tags]")
        }
        var r = Request(op: "update")
        r.name = name
        r.tags = tags
        r.url = url
        r.notes = notes
        r.expires = expires
        r.minTier = minTier
        r.clear = clear.isEmpty ? nil : clear.map(\.rawValue).sorted()
        let timeout = minTier == nil ? Timeout.standard : Timeout.human
        return try await call(r, timeout: timeout).auditID
    }

    /// `delete`. Not presence-gated.
    @discardableResult
    public func delete(_ name: String) async throws -> String {
        var r = Request(op: "delete")
        r.name = name
        return try await call(r).auditID
    }

    // MARK: grants

    /// `grants` `list`: the active grants. A row with `tampered` set failed
    /// verification; only its `id` may be trusted.
    public func listGrants() async throws -> [GrantInfo] {
        var r = Request(op: "grants")
        r.action = "list"
        return try await call(r).decodeResult([GrantInfo].self)
    }

    /// `grants` `revoke`. Fails with `not_found` / `grant_not_found` for an
    /// unknown id. Also removes a tampered row.
    public func revokeGrant(id: String) async throws {
        var r = Request(op: "grants")
        r.action = "revoke"
        r.grantID = id
        _ = try await call(r)
    }

    /// `grants` `revoke_all`.
    public func revokeAllGrants() async throws {
        var r = Request(op: "grants")
        r.action = "revoke_all"
        _ = try await call(r)
    }

    /// `grants` `add`: creates a **standing grant**.
    ///
    /// This does not create anything by itself. The daemon validates the
    /// request, applies the folder's `.grantd.yml`, then shows its own
    /// "Create a standing grant?" dialog and, after "Create standing grant",
    /// the Touch ID sheet. Nothing is stored before both succeed, and this
    /// call returns only when the human has answered, which may take minutes:
    /// it uses an 11 minute timeout (`Timeout.human`). Cancelling the calling
    /// task closes the connection, which makes the daemon cancel the dialog.
    ///
    /// The app must not retry it, send a second `add` while one is pending, or
    /// stand in for the dialog (docs/UI-SPEC.md 3.3).
    ///
    /// Failures are the daemon's: `denied` / `user_denied` or
    /// `approver_unavailable`, `refused` / `policy_refused` / `tier_unmet` /
    /// `secret_expired`, `not_found` / `secret_not_found`, `bad_request`
    /// (including a lifetime above the ceiling, with the limit in the message).
    public func addStandingGrant(_ grant: StandingGrantRequest) async throws -> GrantInfo {
        var r = Request(op: "grants")
        r.action = "add"
        r.grantCaller = grant.forCaller
        r.cwd = grant.cwd
        r.secrets = grant.secrets
        r.argv = grant.argv
        r.ttlS = grant.ttlSeconds
        r.uses = grant.uses
        return try await call(r, timeout: Timeout.human).decodeResult(GrantInfo.self)
    }

    // MARK: audit

    /// `audit` `list`, newest first. `limit` nil is the daemon's default (100);
    /// the maximum is 1000. `truncated` means fewer rows than `limit` fit in
    /// one protocol line.
    public func listAudit(limit: Int? = nil) async throws -> AuditList {
        var r = Request(op: "audit")
        r.action = "list"
        r.limit = limit
        return try await call(r).decodeResult(AuditList.self)
    }

    /// `audit` `verify`: recomputes the whole chain. The call succeeds even
    /// when the chain is broken; read `ok` and `firstBadID` of the result.
    public func verifyAudit() async throws -> AuditVerifyResult {
        var r = Request(op: "audit")
        r.action = "verify"
        return try await call(r, timeout: Timeout.auditVerify).decodeResult(AuditVerifyResult.self)
    }

    /// `audit` `export`: the whole log as CSV text, oldest first, exactly as
    /// the daemon sent it (cells are text chosen by other programs; do not
    /// interpret them). Fails with `failed` / `response_too_large` when it
    /// would not fit in one protocol line.
    public func exportAudit() async throws -> String {
        struct Result: Decodable { var csv: String }
        var r = Request(op: "audit")
        r.action = "export"
        return try await call(r, timeout: Timeout.auditExport).decodeResult(Result.self).csv
    }
}
