import AppKit
import SwiftUI
import GrantdKit

/// The Grants window (docs/UI-SPEC.md 3.3): what is pre-approved, with its
/// badges and time left, revoke one, revoke all, and the "New standing
/// grant…" form.
///
/// Everything from the daemon (callers, folders, secrets, commands) is
/// untrusted text: `GrantRow` has already sanitised it and it is drawn with
/// `Text(verbatim:)`. A tampered row shows only its id and the review text.
struct GrantsWindow: View {
    let app: AppModel
    @State private var form: StandingGrantFormModel?
    @State private var confirmation: Confirmation?
    @State private var pendingRevoke: PendingRevoke?

    private var model: GrantsViewModel { app.grants }

    private enum PendingRevoke: Equatable {
        case one(String)
        case all
    }

    var body: some View {
        content
            .frame(minWidth: 760, minHeight: 320)
            .safeAreaInset(edge: .top, spacing: 0) { banners }
            .toolbar { toolbar }
            .navigationTitle("Grants")
            .navigationSubtitle(subtitle)
            .sheet(item: $form) { f in
                StandingGrantSheet(form: f) { message in
                    // Only a preset lifetime is remembered. The folder never is:
                    // UserDefaults is writable by any program running as the user,
                    // and a folder prefilled from it would be a scope an agent chose.
                    if f.ttl != .custom { UserDefaults.standard.set(f.ttl.rawValue, forKey: StandingGrantSheet.ttlKey) }
                    Task { await model.formDidCreate(message) }
                }
            }
            .alert(
                Text(verbatim: confirmation?.title ?? ""),
                isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil; pendingRevoke = nil } }),
                presenting: confirmation
            ) { c in
                Button(c.confirmLabel, role: .destructive) { performRevoke() }
                Button("Cancel", role: .cancel) {}
            } message: { c in
                Text(verbatim: c.message)
            }
            .background(WindowKeyObserver { key in
                if key { app.surfaceAppeared("grants") } else { app.surfaceDisappeared("grants") }
            })
            .onChange(of: app.monitor.state, initial: true) { _, new in model.connectionChanged(new) }
            .task {
                // Every 5 seconds while the window exists (docs/UI-SPEC.md 2.4).
                while !Task.isCancelled {
                    if model.isEnabled { await model.refresh() } else { model.tick() }
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                }
            }
            .background(WindowSetup())
    }

    @ViewBuilder
    private var content: some View {
        if model.isEmpty && model.isEnabled {
            ContentUnavailableView {
                Label("No active grants", systemImage: "checkmark.shield")
            } description: {
                Text("When you choose \"Allow for 1h\" in an approval dialog, it appears here. You can also create a standing grant.")
            } actions: {
                Button("New Standing Grant…", action: newGrant)
            }
        } else {
            table
        }
    }

    // MARK: table

    private var table: some View {
        Table(model.rows, selection: Bindable(model).selection) {
            TableColumn("Status") { r in
                HStack(spacing: 4) {
                    ForEach(r.badges, id: \.self) { BadgeView(badge: $0) }
                }
            }
            .width(min: 90, ideal: 120, max: 220)
            TableColumn("Caller") { r in
                if r.tampered {
                    Text(verbatim: "ID " + DisplayText.sanitise(r.id, limit: 40))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else {
                    Text(verbatim: r.caller).lineLimit(1).truncationMode(.tail)
                }
            }
            .width(min: 80, ideal: 100)
            TableColumn("Command") { r in
                if let note = r.tamperedNote {
                    Text(verbatim: note)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                        .help(note)
                } else {
                    Text(verbatim: r.command).font(.body.monospaced()).lineLimit(1).truncationMode(.tail)
                }
            }
            .width(min: 140, ideal: 190)
            TableColumn("Folder") { r in
                Text(verbatim: r.folder).lineLimit(1).truncationMode(.middle).help(r.folder)
            }
            .width(min: 100, ideal: 150)
            TableColumn("Secrets") { r in
                Text(verbatim: r.secrets).lineLimit(1).truncationMode(.tail).help(r.secrets)
            }
            .width(min: 80, ideal: 110)
            TableColumn("Expires") { r in
                Text(verbatim: r.timeLeft)
                    .monospacedDigit()
                    .foregroundStyle(r.badges.contains(.expiringSoon) ? Color.orange : Color.primary)
            }
            .width(min: 80, ideal: 90, max: 130)
            TableColumn("Uses left") { r in
                Text(verbatim: r.usesLeft).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 65, max: 100)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if ids.count == 1, let id = ids.first {
                Button(model.grant(id: id)?.tampered == true ? "Remove…" : "Revoke…", role: .destructive) { requestRevoke(id) }
            }
        }
        .onDeleteCommand {
            if model.selection.count == 1, let id = model.selection.first { requestRevoke(id) }
        }
        .overlay {
            if !model.hasLoaded && model.isEnabled { ProgressView() }
        }
        .disabled(!model.isEnabled)
    }

    // MARK: banners

    @ViewBuilder
    private var banners: some View {
        VStack(spacing: 0) {
            if let reason = model.disabledReason {
                BannerView(symbol: "exclamationmark.triangle.fill", tint: .orange, headline: reason, detail: nil, dismiss: nil)
            }
            if app.socket.isDevelopment {
                BannerView(symbol: "hammer.fill", tint: .orange, headline: "Development socket: " + DisplayText.sanitise(app.socket.path),
                           detail: nil, dismiss: nil)
            }
            if model.tamperedCount > 0 {
                let n = model.tamperedCount
                BannerView(symbol: "exclamationmark.shield.fill", tint: .red,
                           headline: n == 1 ? "1 grant failed verification" : "\(n) grants failed verification",
                           detail: "grantd ignores them and they never allow anything. Select one and choose Remove.", dismiss: nil)
            }
            if let notice = model.notice {
                BannerView(symbol: "checkmark.circle.fill", tint: .green, headline: notice, detail: nil, dismiss: { model.notice = nil })
            }
            if let banner = model.banner {
                BannerView(symbol: banner.severity == .info ? "info.circle.fill" : "exclamationmark.octagon.fill",
                           tint: banner.severity == .info ? .blue : .red, headline: banner.headline, detail: banner.detail,
                           dismiss: { model.banner = nil })
            }
        }
    }

    private var subtitle: String {
        guard model.isEnabled, model.hasLoaded else { return "" }
        let n = model.rows.count
        return n == 1 ? "1 grant" : "\(n) grants"
    }

    // MARK: toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button(action: newGrant) {
                Label("New Standing Grant…", systemImage: "plus")
            }
            .keyboardShortcut("n", modifiers: .command)
            .help("Create a standing grant (⌘N). grantd asks you to confirm.")
            .disabled(!model.isEnabled)

            Button {
                if model.selection.count == 1, let id = model.selection.first { requestRevoke(id) }
            } label: {
                Label(revokeTitle, systemImage: "xmark.shield")
            }
            .help(model.selection.count == 1 ? "Revoke the selected grant" : "Select one grant to revoke it")
            .disabled(!model.isEnabled || model.selection.count != 1)

            Button {
                if let c = model.revokeAllConfirmation() { pendingRevoke = .all; confirmation = c }
            } label: {
                Label("Revoke All", systemImage: "trash")
            }
            .help("Revoke every grant")
            .disabled(!model.isEnabled || model.rows.isEmpty)
        }
    }

    private var revokeTitle: String {
        if model.selection.count == 1, let id = model.selection.first, model.grant(id: id)?.tampered == true { return "Remove" }
        return "Revoke"
    }

    // MARK: actions

    private func newGrant() {
        guard model.isEnabled else { return }
        let defaults = UserDefaults.standard
        // An earlier version remembered the folder; forget it.
        defaults.removeObject(forKey: StandingGrantSheet.legacyFolderKey)
        let ttl = StandingTTL.remembered(defaults.string(forKey: StandingGrantSheet.ttlKey))
        form = model.makeStandingForm(initialTTL: ttl)
    }

    private func requestRevoke(_ id: String) {
        guard model.isEnabled, let c = model.revokeConfirmation(for: id) else { return }
        pendingRevoke = .one(id)
        confirmation = c
    }

    private func performRevoke() {
        let what = pendingRevoke
        pendingRevoke = nil
        Task {
            switch what {
            case .one(let id)?: await model.revoke(id: id)
            case .all?: await model.revokeAll()
            case nil: break
            }
        }
    }
}

/// A coloured capsule: Standing (blue), Expiring soon (orange), Expired
/// (gray), Tampered (red). The text says it too, so colour is not the only cue.
struct BadgeView: View {
    let badge: GrantBadge

    var body: some View {
        Text(verbatim: badge.title)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.15), in: Capsule())
            .lineLimit(1)
            .fixedSize()
    }

    private var color: Color {
        switch badge {
        case .standing: return .blue
        case .expiringSoon: return .orange
        case .expired: return .secondary
        case .tampered: return .red
        }
    }
}
