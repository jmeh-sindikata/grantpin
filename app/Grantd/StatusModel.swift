import Foundation
import Observation
import GrantdKit

/// Polls the daemon's `status` op. The stub polls every 5 seconds for as long
/// as the app runs; the real Monitor (UI-SPEC 2.4) adapts the interval to what
/// is visible.
@Observable
@MainActor
final class StatusModel {
    private(set) var line = "Checking…"
    let developmentSocket: String?

    private let client: Client
    private var poller: Task<Void, Never>?  // lives as long as the app

    init(client: Client = Client()) {
        self.client = client
        developmentSocket = SocketPath.isDevelopment() ? client.socketPath : nil
        poller = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    func refresh() async {
        do {
            let s = try await client.status()
            line = Self.describe(s)
        } catch let e as DaemonError {
            line = e == .notRunning ? "grantd is not running" : "grantd did not answer"
        } catch {
            line = "grantd did not answer"
        }
    }

    static func describe(_ s: StatusResult) -> String {
        if !s.vaultInitialized { return "grantd is running · no vault yet" }
        if s.vaultLocked { return "grantd is running · waiting for the vault key (locked session)" }
        let secrets = s.secrets == 1 ? "1 secret" : "\(s.secrets) secrets"
        let grants = s.activeGrants == 1 ? "1 active grant" : "\(s.activeGrants) active grants"
        return "grantd is running · \(secrets) · \(grants)"
    }
}
