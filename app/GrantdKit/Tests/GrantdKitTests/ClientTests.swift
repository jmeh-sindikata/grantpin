import Foundation
import XCTest
@testable import GrantdKit

/// Framing, decoding and error mapping against canned daemon answers.
final class ClientTests: XCTestCase {
    static let statusJSON = #"{"ok":true,"result":{"version":"v0.1.0","proto_v":1,"pid":4242,"started_at":"2026-10-25T20:00:00.123456Z","vault_initialized":true,"keystore_tier":"hardware","approver_tier":"hardware","secrets":3,"active_grants":2,"socket":"/x/grantd.sock","future_field":[1,2]}}"#

    // MARK: framing

    func testStatusDecodes() async throws {
        let server = try FakeServer(answer: Self.statusJSON)
        let s = try await server.client.status()
        XCTAssertEqual(s.version, "v0.1.0")
        XCTAssertEqual(s.protoV, 1)
        XCTAssertEqual(s.pid, 4242)
        XCTAssertTrue(s.vaultInitialized)
        XCTAssertFalse(s.vaultLocked)
        XCTAssertEqual(s.keystoreTier, .hardware)
        XCTAssertEqual(s.approverTier, "hardware")
        XCTAssertEqual(s.secrets, 3)
        XCTAssertEqual(s.activeGrants, 2)
        XCTAssertEqual(s.tamperedGrants, 0)  // absent decodes to 0
        XCTAssertEqual(s.socket, "/x/grantd.sock")
        XCTAssertNotNil(s.startedAt)
        // the request is exactly one line, with the protocol version, op and caller
        XCTAssertEqual(server.requests.count, 1)
        let line = server.requests[0]
        XCTAssertTrue(line.hasSuffix("\n") && line.dropLast().firstIndex(of: "\n") == nil)
        let obj = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        XCTAssertEqual(obj?["v"] as? Int, 1)
        XCTAssertEqual(obj?["op"] as? String, "status")
        XCTAssertEqual(obj?["caller"] as? String, "grantd-app")
        XCTAssertEqual(obj?.count, 3)
    }

    func testStreamFramesBeforeTheFinalResponseAreSkipped() async throws {
        let server = try FakeServer(answer: #"{"stream":"stdout","data":"hi"}"#, "", Self.statusJSON)
        let s = try await server.client.status()
        XCTAssertEqual(s.pid, 4242)
    }

    func testResponseSplitAcrossWrites() async throws {
        let server = try FakeServer { fd, _ in
            let half = Self.statusJSON.index(Self.statusJSON.startIndex, offsetBy: 40)
            FakeServer.send(fd, String(Self.statusJSON[..<half]))
            Thread.sleep(forTimeInterval: 0.1)
            FakeServer.send(fd, String(Self.statusJSON[half...]) + "\n")
        }
        let s = try await server.client.status()
        XCTAssertEqual(s.secrets, 3)
    }

    func testResponseOfSeveralMegabytesIsRead() async throws {
        // A 3 MiB export: under the 4 MiB line limit.
        let csv = String(repeating: "x", count: 3 << 20)
        let server = try FakeServer(answer: #"{"ok":true,"result":{"csv":"\#(csv)"}}"#)
        let got = try await server.client.exportAudit()
        XCTAssertEqual(got.count, csv.count)
    }

    func testResponseLineOverFourMiBIsRefused() async throws {
        let big = String(repeating: "x", count: (4 << 20) + 10)
        let server = try FakeServer(answer: #"{"ok":true,"result":{"csv":"\#(big)"}}"#)
        let e = await expectGrantdError(try await server.client.exportAudit())
        guard case .malformedResponse = e else { return XCTFail("\(String(describing: e))") }
    }

    func testRequestOverFourMiBIsRefusedBeforeConnecting() async throws {
        // 700,000 control characters escape to 4.2 MB of \u00XX.
        var value = Data(repeating: 0x01, count: 700_000)
        let missing = "/tmp/gdt-never-\(UUID().uuidString.prefix(6)).sock"
        let e = await expectGrantdError(try await Client(socketPath: missing).set(name: "k", value: &value))
        XCTAssertEqual(e, .requestTooLarge)  // not .notRunning: nothing was sent
        XCTAssertTrue(value.allSatisfy { $0 == 0 }, "the value was not wiped on a local refusal")
    }

    func testCallerLabelIsConfigurable() async throws {
        let server = try FakeServer(answer: Self.statusJSON)
        _ = try await Client(socketPath: server.path, caller: "test-label").status()
        XCTAssertTrue(server.requests[0].contains(#""caller":"test-label""#))
    }

    // MARK: errors

    func testDaemonErrorCarriesCategoryReasonAndMessage() async throws {
        let server = try FakeServer(answer: #"{"ok":false,"error":"failed","reason":"vault_not_initialized","message":"run grantd init"}"#)
        let e = await expectGrantdError(try await server.client.call(.status))
        XCTAssertEqual(e, .daemon(category: .failed, reason: .vaultNotInitialized, message: "run grantd init"))
        XCTAssertEqual(e?.isVaultNotInitialized, true)
        XCTAssertEqual(e?.message, "run grantd init")
    }

    func testEveryProtocolReasonMapsAndRoundTrips() {
        let cases: [(String, ErrorReason)] = [
            ("user_denied", .userDenied), ("approver_unavailable", .approverUnavailable), ("no_grant", .noGrant),
            ("policy_refused", .policyRefused), ("tier_unmet", .tierUnmet), ("peer_rejected", .peerRejected),
            ("secret_expired", .secretExpired), ("not_tty", .notTTY), ("bad_request", .badRequest),
            ("unsupported_version", .unsupportedVersion), ("unknown_op", .unknownOp), ("secret_exists", .secretExists),
            ("secret_not_found", .secretNotFound), ("grant_not_found", .grantNotFound),
            ("vault_not_initialized", .vaultNotInitialized), ("vault_locked", .vaultLocked), ("timeout", .timeout),
            ("canceled", .canceled), ("internal", .internalError), ("response_too_large", .responseTooLarge), ("", .absent),
        ]
        for (wire, reason) in cases {
            XCTAssertEqual(ErrorReason(wire: wire), reason, wire)
            XCTAssertEqual(reason.wire, wire)
        }
        XCTAssertEqual(ErrorReason(wire: "brand_new"), .unknown("brand_new"))
        XCTAssertEqual(ErrorReason(wire: "brand_new").wire, "brand_new")
        for (wire, cat) in [("denied", ErrorCategory.denied), ("refused", .refused), ("bad_request", .badRequest), ("not_found", .notFound), ("failed", .failed)] {
            XCTAssertEqual(ErrorCategory(wire: wire), cat)
            XCTAssertEqual(cat.wire, wire)
        }
        XCTAssertEqual(ErrorCategory(wire: "weird"), .unknown("weird"))
    }

    func testTypedPredicates() async throws {
        func err(_ category: String, _ reason: String) async throws -> GrantdError? {
            let server = try FakeServer(answer: #"{"ok":false,"error":"\#(category)","reason":"\#(reason)","message":"m"}"#)
            return await expectGrantdError(try await server.client.call(.status))
        }
        let locked = try await err("failed", "vault_locked")
        XCTAssertEqual(locked?.isVaultLocked, true)
        XCTAssertEqual(locked?.category, .failed)
        await assertEqual(try await err("denied", "user_denied")?.isDenied, true)
        await assertEqual(try await err("denied", "approver_unavailable")?.reason, .approverUnavailable)
        await assertEqual(try await err("refused", "policy_refused")?.isRefused, true)
        await assertEqual(try await err("not_found", "secret_not_found")?.isNotFound, true)
        await assertEqual(try await err("bad_request", "secret_exists")?.isBadRequest, true)
        await assertEqual(try await err("failed", "response_too_large")?.isResponseTooLarge, true)
        // an unknown reason keeps its category, so the UI falls back to it
        let unknown = try await err("refused", "from_the_future")
        XCTAssertEqual(unknown?.reason, .unknown("from_the_future"))
        XCTAssertEqual(unknown?.isRefused, true)
        XCTAssertEqual(GrantdError.notRunning.isNotRunning, true)
        XCTAssertNil(GrantdError.notRunning.category)
    }

    func testVaultLockedIsNotConfusedWithNotInitialized() {
        // vault_locked is not reproducible with the dev keystore; the mapping is unit-tested.
        let e = GrantdError.daemon(category: .failed, reason: ErrorReason(wire: "vault_locked"),
                                   message: "vault keystore unavailable (screen locked?); retrying")
        XCTAssertTrue(e.isVaultLocked)
        XCTAssertFalse(e.isVaultNotInitialized)
        XCTAssertFalse(e.isNotRunning)
        XCTAssertTrue(e.localizedDescription.hasPrefix("failed: vault_locked"))
    }

    func testDescriptionOfAHostileMessageIsSanitised() {
        let e = GrantdError.daemon(category: .badRequest, reason: .badRequest, message: "bad \u{1B}[31m \u{202E}name")
        let text = e.localizedDescription
        XCTAssertFalse(text.unicodeScalars.contains("\u{1B}"))
        XCTAssertFalse(text.unicodeScalars.contains("\u{202E}"))
        XCTAssertTrue(text.contains("⟦U+001B⟧") && text.contains("⟦U+202E⟧"))
    }

    func testNotRunningWhenTheSocketIsMissingOrRefuses() async throws {
        let missing = "/tmp/gdt-missing-\(UUID().uuidString.prefix(6)).sock"
        var e = await expectGrantdError(try await Client(socketPath: missing).call(.status))
        XCTAssertEqual(e, .notRunning)

        // A socket file nobody listens on refuses the connection.
        let dir = "/tmp/gdt-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/s.sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            for (i, b) in bytes.enumerated() { dst[i] = b }
            dst[bytes.count] = 0
        }
        _ = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        close(fd)  // bound, never listened: the file stays, connect is refused
        e = await expectGrantdError(try await Client(socketPath: path).call(.status))
        XCTAssertEqual(e, .notRunning)
    }

    func testClosedWithoutAResponse() async throws {
        let server = try FakeServer { _, _ in }
        let e = await expectGrantdError(try await server.client.call(.status))
        XCTAssertEqual(e, .noResponse)
    }

    func testTimeout() async throws {
        let server = try FakeServer { _, _ in Thread.sleep(forTimeInterval: 1.5) }
        let e = await expectGrantdError(try await server.client.call(.status, timeout: 0.3))
        XCTAssertEqual(e, .timeout)
    }

    func testMalformedLines() async throws {
        for bad in ["not json\n", #"{"neither":true}"# + "\n", "[1,2]\n"] {
            let server = try FakeServer { fd, _ in FakeServer.send(fd, bad) }
            let e = await expectGrantdError(try await server.client.call(.status))
            guard case .malformedResponse = e else { return XCTFail("\(String(describing: e))") }
        }
    }

    func testResultThatDoesNotDecodeIsMalformed() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"result":{"exists":"yes"}}"#)
        let e = await expectGrantdError(try await server.client.exists("a"))
        guard case .malformedResponse = e else { return XCTFail("\(String(describing: e))") }
        let none = try FakeServer(answer: #"{"ok":true}"#)
        let e2 = await expectGrantdError(try await none.client.exists("a"))
        guard case .malformedResponse = e2 else { return XCTFail("\(String(describing: e2))") }
    }

    func testSocketPathTooLong() async throws {
        let long = "/tmp/" + String(repeating: "a", count: 120)
        let e = await expectGrantdError(try await Client(socketPath: long).call(.status))
        XCTAssertEqual(e, .socketPathTooLong(long.utf8.count))
    }

    // MARK: transport behaviour

    func testClientNeverHalfClosesTheConnection() async throws {
        // The daemon cancels a request when it reads EOF. After sending the
        // request the client must keep its write side open until it has the
        // answer: the server waits, then checks a read would block (no EOF).
        let sawEOF = ManagedFlag()
        let server = try FakeServer { fd, _ in
            Thread.sleep(forTimeInterval: 0.3)
            var b = [UInt8](repeating: 0, count: 8)
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            if read(fd, &b, b.count) == 0 { sawEOF.set() }
            FakeServer.send(fd, Self.statusJSON + "\n")
        }
        _ = try await server.client.status()
        XCTAssertFalse(sawEOF.value, "client half-closed its write side before the response")
    }

    func testCancellingClosesTheConnection() async throws {
        let sawClose = ManagedFlag()
        let server = try FakeServer { fd, _ in
            var b = [UInt8](repeating: 0, count: 8)
            let deadline = Date().addingTimeInterval(3)
            while Date() < deadline {
                if read(fd, &b, b.count) == 0 { sawClose.set(); return }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        let client = server.client
        let task = Task { try await client.call(.status, timeout: 30) }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch is CancellationError {} catch { XCTFail("\(error)") }
        try await Task.sleep(nanoseconds: 400_000_000)
        XCTAssertTrue(sawClose.value, "the server never saw the connection close")
    }

    func testStandingGrantRequestWaitsForTheHumanAndCanBeCancelled() async throws {
        // The daemon answers `grants add` only after the dialog and Touch ID.
        // The request uses the long human timeout, and cancelling closes the
        // connection (so the daemon cancels the dialog).
        XCTAssertEqual(Client.Timeout.human, 11 * 60)
        let sawClose = ManagedFlag()
        let server = try FakeServer { fd, _ in
            var b = [UInt8](repeating: 0, count: 8)
            let deadline = Date().addingTimeInterval(5)
            while Date() < deadline {
                if read(fd, &b, b.count) == 0 { sawClose.set(); return }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        let client = server.client
        let grant = StandingGrantRequest(forCaller: "claude-code", cwd: "/tmp", secrets: ["A"], argv: ["php"], ttlSeconds: 3600)
        let task = Task { try await client.addStandingGrant(grant) }
        try await Task.sleep(nanoseconds: 800_000_000)
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch is CancellationError {} catch { XCTFail("\(error)") }
        try await Task.sleep(nanoseconds: 400_000_000)
        XCTAssertTrue(sawClose.value)
        let obj = try JSONSerialization.jsonObject(with: Data(server.requests[0].utf8)) as? [String: Any]
        XCTAssertEqual(obj?["op"] as? String, "grants")
        XCTAssertEqual(obj?["action"] as? String, "add")
        XCTAssertEqual(obj?["grant_caller"] as? String, "claude-code")
        XCTAssertEqual(obj?["ttl_s"] as? Int, 3600)
        XCTAssertNil(obj?["uses"])
    }

    func testConcurrentRequestsEachUseTheirOwnConnection() async throws {
        let server = try FakeServer(answer: Self.statusJSON)
        let client = server.client
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<8 { group.addTask { try await client.status().pid } }
            for try await pid in group { XCTAssertEqual(pid, 4242) }
        }
        XCTAssertEqual(server.requests.count, 8)
    }

    // MARK: request shapes

    func testOpsSendTheDocumentedFields() async throws {
        let server = try FakeServer { fd, line in
            let op = (try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])?["op"] as? String ?? ""
            let action = (try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])?["action"] as? String ?? ""
            let result: String
            switch (op, action) {
            case ("list", _): result = "[]"
            case ("exists", _): result = #"{"exists":true}"#
            case ("masked", _): result = #"{"masked":"****abcd"}"#
            case ("audit", "list"): result = #"{"entries":[]}"#
            case ("audit", "verify"): result = #"{"ok":true,"entries":0}"#
            default: result = "null"
            }
            FakeServer.send(fd, #"{"ok":true,"audit_id":"7","result":\#(result)}"# + "\n")
        }
        let c = server.client
        _ = try await c.list(tag: "prod", expiringWithin: 90)
        _ = try await c.exists("a/b")
        _ = try await c.masked("a/b")
        let exp = Date(timeIntervalSince1970: 1_800_000_000)
        let id = try await c.update(name: "a/b", tags: ["x"], url: "https://u", notes: "n", expires: exp, clear: [.notes, .tags])
        XCTAssertEqual(id, "7")
        try await c.revokeGrant(id: "g1")
        try await c.revokeAllGrants()
        _ = try await c.listAudit(limit: 5)
        _ = try await c.verifyAudit()
        _ = try await c.delete("a/b")

        func req(_ i: Int) throws -> [String: Any] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: Data(server.requests[i].utf8)) as? [String: Any])
        }
        var r = try req(0)
        XCTAssertEqual(r["op"] as? String, "list"); XCTAssertEqual(r["tag"] as? String, "prod"); XCTAssertEqual(r["expiring_within_s"] as? Int, 90)
        r = try req(1); XCTAssertEqual(r["op"] as? String, "exists"); XCTAssertEqual(r["name"] as? String, "a/b")
        r = try req(2); XCTAssertEqual(r["op"] as? String, "masked")
        r = try req(3)
        XCTAssertEqual(r["op"] as? String, "update")
        XCTAssertEqual(r["tags"] as? [String], ["x"])
        XCTAssertEqual(r["clear"] as? [String], ["notes", "tags"])  // the clear list, sorted; never clear_expires
        XCTAssertNil(r["clear_expires"])
        XCTAssertNil(r["value"])
        XCTAssertEqual(r["expires"] as? String, "2027-01-15T08:00:00Z")
        XCTAssertNil(r["min_tier"])
        r = try req(4); XCTAssertEqual(r["action"] as? String, "revoke"); XCTAssertEqual(r["grant_id"] as? String, "g1")
        r = try req(5); XCTAssertEqual(r["action"] as? String, "revoke_all")
        r = try req(6); XCTAssertEqual(r["op"] as? String, "audit"); XCTAssertEqual(r["action"] as? String, "list"); XCTAssertEqual(r["limit"] as? Int, 5)
        r = try req(7); XCTAssertEqual(r["action"] as? String, "verify")
        r = try req(8); XCTAssertEqual(r["op"] as? String, "delete")
    }

    func testUpdateRefusesAnEmptyTagListLocally() async throws {
        let missing = "/tmp/gdt-never-\(UUID().uuidString.prefix(6)).sock"
        let e = await expectGrantdError(try await Client(socketPath: missing).update(name: "a", tags: []))
        guard case .invalidRequest = e else { return XCTFail("\(String(describing: e))") }
    }

    func testSetSendsTheValueAndMetadataAndWipesTheCallersBuffer() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"audit_id":"10"}"#)
        var value = Data("p@ss\"w\\ord\nline2 \u{00E9}\u{1F511}".utf8)
        let expected = String(decoding: value, as: UTF8.self)
        let exp = Date(timeIntervalSince1970: 1_800_000_000)
        let id = try await server.client.set(name: "tmp/x", value: &value, tags: ["b", "a"], url: "https://x", notes: "n",
                                             expires: exp, minTier: .dialog, overwrite: true)
        XCTAssertEqual(id, "10")
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(server.requests[0].utf8)) as? [String: Any])
        XCTAssertEqual(obj["op"] as? String, "set")
        XCTAssertEqual(obj["value"] as? String, expected)
        XCTAssertEqual(obj["min_tier"] as? String, "dialog")
        XCTAssertEqual(obj["overwrite"] as? Bool, true)
        XCTAssertEqual(obj["tags"] as? [String], ["b", "a"])
        XCTAssertEqual(obj["expires"] as? String, "2027-01-15T08:00:00Z")
        XCTAssertEqual(value, Data(repeating: 0, count: value.count), "the caller's buffer still holds the value")
        XCTAssertFalse(value.isEmpty)

        // and when the daemon refuses, the buffer is wiped as well
        let refusing = try FakeServer(answer: #"{"ok":false,"error":"bad_request","reason":"secret_exists","message":"secret already exists (overwrite to replace)"}"#)
        var again = Data("another-secret-value".utf8)
        let e = await expectGrantdError(try await refusing.client.set(name: "tmp/x", value: &again))
        XCTAssertEqual(e?.reason, .secretExists)
        XCTAssertEqual(again, Data(repeating: 0, count: again.count))
    }

    func testUpdateWithATierUsesTheLongTimeout() async throws {
        // A dialog may be on screen while the daemon decides to lower a tier:
        // the call must outlast the standard 10 s timeout. The server answers
        // after 0.6 s, so this only checks the request is accepted slowly.
        let server = try FakeServer { fd, _ in
            Thread.sleep(forTimeInterval: 0.6)
            FakeServer.send(fd, #"{"ok":true,"audit_id":"3"}"# + "\n")
        }
        let id = try await server.client.update(name: "k", minTier: .dialog)
        XCTAssertEqual(id, "3")
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(server.requests[0].utf8)) as? [String: Any])
        XCTAssertEqual(obj["min_tier"] as? String, "dialog")
    }

    // MARK: decoding

    func testListIgnoresUnknownFieldsAndDefaultsMissingOnes() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"result":[{"name":"stripe/api_key","tags":["payments","prod"],"url":"https://dashboard.stripe.com","notes":"n","expires_at":"2026-12-01T10:00:00Z","min_tier":"hardware","created_at":"2026-10-25T13:15:47.259Z","updated_at":"2026-10-25T13:15:47.259Z","future":{"a":1}},{"name":"b","min_tier":"none","created_at":"2026-10-25T13:15:47Z","updated_at":"2026-10-25T13:15:47Z"}]}"#)
        let items = try await server.client.list()
        XCTAssertEqual(items.map(\.name), ["stripe/api_key", "b"])
        XCTAssertEqual(items[0].tags, ["payments", "prod"])
        XCTAssertEqual(items[0].minTier, .hardware)
        XCTAssertNotNil(items[0].expiresAt)
        XCTAssertEqual(items[1].tags, [])
        XCTAssertEqual(items[1].url, "")
        XCTAssertNil(items[1].expiresAt)
        XCTAssertEqual(items[1].minTier, .vaultDefault)
    }

    func testGrantsDecodeIncludingATamperedRow() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"result":[{"id":"g1","caller":"claude-code","cwd_prefix":"/p","secrets":["A","aws/*"],"cmd_prefix":["php","artisan"],"expires_at":"2026-11-01T00:00:00Z","uses_remaining":3,"created_at":"2026-10-25T00:00:00Z","standing":true},{"id":"g2","tampered":true}]}"#)
        let grants = try await server.client.listGrants()
        XCTAssertEqual(grants.count, 2)
        XCTAssertEqual(grants[0].cmdPrefix, ["php", "artisan"])
        XCTAssertEqual(grants[0].usesRemaining, 3)
        XCTAssertTrue(grants[0].standing)
        XCTAssertFalse(grants[0].tampered)
        XCTAssertTrue(grants[1].tampered)
        XCTAssertEqual(grants[1].id, "g2")
        XCTAssertNil(grants[1].usesRemaining)
    }

    func testAuditListVerifyAndExportDecode() async throws {
        let list = try FakeServer(answer: #"{"ok":true,"result":{"entries":[{"id":"9","ts":"2026-10-25T14:03:04.312789Z","caller":"claude-code","cwd":"/p","argv":["sleep","5"],"secrets":["API_KEY"],"expanded":["API_KEY"],"decision":"completed","exit_code":124,"duration_ms":1004,"reason":"timeout"},{"id":"8","ts":"2026-10-25T14:03:04Z","caller":"c","cwd":"/p","argv":["a"],"secrets":[],"decision":"allowed_once","reason":"released"}],"truncated":true}}"#)
        let a = try await list.client.listAudit(limit: 2)
        XCTAssertTrue(a.truncated)
        XCTAssertEqual(a.entries.map(\.id), ["9", "8"])
        XCTAssertEqual(a.entries[0].exitCode, 124)
        XCTAssertEqual(a.entries[0].durationMS, 1004)
        XCTAssertEqual(a.entries[0].expanded, ["API_KEY"])
        XCTAssertNil(a.entries[1].expanded)
        XCTAssertNil(a.entries[1].exitCode)

        let bad = try FakeServer(answer: #"{"ok":true,"result":{"ok":false,"entries":9,"first_bad_id":"4"}}"#)
        let v = try await bad.client.verifyAudit()
        XCTAssertFalse(v.ok)  // the response is ok; the chain is not
        XCTAssertEqual(v.firstBadID, "4")
        XCTAssertEqual(v.entries, 9)

        let csv = try FakeServer(answer: #"{"ok":true,"result":{"csv":"id,ts\r\n1,x\r\n"}}"#)
        let text = try await csv.client.exportAudit()
        XCTAssertEqual(text, "id,ts\r\n1,x\r\n")
    }

    func testAnEmptyAuditListDecodes() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"result":{"entries":[]}}"#)
        let a = try await server.client.listAudit()
        XCTAssertTrue(a.entries.isEmpty)
        XCTAssertFalse(a.truncated)
    }

    func testStatusWhileLockedDecodes() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"result":{"version":"v","proto_v":1,"pid":1,"started_at":"2026-10-25T20:00:00Z","vault_initialized":true,"vault_locked":true,"vault_locked_error":"keychain: user interaction is not allowed","keystore_tier":"hardware","approver_tier":"hardware"}}"#)
        let s = try await server.client.status()
        XCTAssertTrue(s.vaultLocked)
        XCTAssertEqual(s.vaultLockedError, "keychain: user interaction is not allowed")
        XCTAssertEqual(ConnectionState.from(s), .locked(lastError: "keychain: user interaction is not allowed"))
    }

    func testGrantAddResultDecodesFromTheResponse() async throws {
        let server = try FakeServer(answer: #"{"ok":true,"grant_id":"4f6c","audit_id":"57","result":{"id":"4f6c","caller":"claude-code","cwd_prefix":"/p","secrets":["DB_URL"],"cmd_prefix":["php","artisan"],"expires_at":"2026-11-24T00:00:00Z","created_at":"2026-10-25T00:00:00Z","standing":true}}"#)
        let g = try await server.client.addStandingGrant(StandingGrantRequest(
            forCaller: "claude-code", cwd: "/p", secrets: ["DB_URL"], argv: ["php", "artisan"], ttlSeconds: 2_592_000))
        XCTAssertEqual(g.id, "4f6c")
        XCTAssertTrue(g.standing)
    }
}
