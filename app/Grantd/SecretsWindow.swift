import AppKit
import SwiftUI
import GrantdKit

/// The Secrets window (docs/UI-SPEC.md 3.2): a table of names with search,
/// a detail inspector, and the Add, Import, Edit and Delete actions.
///
/// Everything from the daemon (names, tags, URLs, notes) is untrusted text:
/// it goes through `DisplayText.sanitise` and is drawn with
/// `Text(verbatim:)`.
struct SecretsWindow: View {
    let app: AppModel
    @State private var sortOrder = [KeyPathComparator(\SecretInfo.name)]
    @State private var form: SecretFormModel?
    @State private var importSession: ImportSession?
    @State private var deleteNames: [String] = []
    @State private var deleteConfirmation: Confirmation?
    @State private var showInspector = true
    @State private var dropTargeted = false

    private var model: SecretsViewModel { app.secrets }

    var body: some View {
        mainContent
            .frame(minWidth: 640, minHeight: 360)
            .safeAreaInset(edge: .top, spacing: 0) { banners }
            .inspector(isPresented: $showInspector) {
                SecretDetail(model: model, edit: { editSecret($0) })
                    .inspectorColumnWidth(min: 240, ideal: 280, max: 380)
            }
            .searchable(text: Bindable(model).searchText, placement: .toolbar, prompt: "Search")
            .toolbar { toolbar }
            .navigationTitle("Secrets")
            .navigationSubtitle(subtitle)
            .sheet(item: $form) { f in
                SecretFormSheet(form: f, onSaved: { name in
                    Task { await model.formDidSave(name: name) }
                })
            }
            .sheet(item: $importSession) { session in
                ImportSheet(session: session) { importSession = nil }
            }
            .alert(
                Text(verbatim: deleteConfirmation?.title ?? ""),
                isPresented: deleteAlertShown,
                presenting: deleteConfirmation,
                actions: deleteActions,
                message: deleteMessage)
            .modifier(FileDropModifier(targeted: $dropTargeted, onDrop: beginImport))
            .modifier(LifecycleModifier(app: app, sortOrder: $sortOrder))
            .background(WindowSetup())
    }

    @ViewBuilder
    private var mainContent: some View {
        if model.emptyState == .noSecrets && model.isEnabled {
            EmptyState(canImport: app.importRunner != nil, add: addSecret, importFile: chooseEnvFile)
        } else {
            table(model)
        }
    }

    private var deleteAlertShown: Binding<Bool> {
        Binding(get: { deleteConfirmation != nil }, set: { if !$0 { deleteConfirmation = nil } })
    }

    @ViewBuilder
    private func deleteActions(_ c: Confirmation) -> some View {
        Button(c.confirmLabel, role: .destructive) {
            let names = deleteNames
            Task { await model.delete(names: names) }
        }
        Button("Cancel", role: .cancel) {}
    }

    private func deleteMessage(_ c: Confirmation) -> some View {
        Text(verbatim: c.message)
    }

    // MARK: table

    @ViewBuilder
    private func table(_ model: SecretsViewModel) -> some View {
        Table(model.visibleSecrets, selection: Bindable(model).selection, sortOrder: $sortOrder) {
            TableColumn("Name", value: \.name) { s in
                Text(verbatim: DisplayText.sanitise(s.name))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .width(min: 140, ideal: 220)
            TableColumn("Protection") { s in
                TierLabel(tier: s.minTier)
            }
            .width(min: 80, ideal: 100, max: 130)
            TableColumn("Expires") { s in
                ExpiryText(date: s.expiresAt)
            }
            .width(min: 70, ideal: 90, max: 130)
            TableColumn("Tags") { s in
                Text(verbatim: DisplayText.sanitise(s.tags.joined(separator: ", ")))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
        .contextMenu(forSelectionType: String.self) { names in
            if names.count == 1, let n = names.first, let s = model.secret(named: n) {
                Button("Edit…") { editSecret(s) }
            }
            if !names.isEmpty {
                Button(names.count == 1 ? "Delete…" : "Delete \(names.count) Secrets…", role: .destructive) { requestDelete(Array(names)) }
            }
        } primaryAction: { names in
            if names.count == 1, let n = names.first, let s = model.secret(named: n) { editSecret(s) }
        }
        .onDeleteCommand { requestDelete(model.selectedSecrets.map(\.name)) }
        .overlay {
            if model.emptyState == .noMatches {
                ContentUnavailableView.search(text: model.searchText)
            }
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
            if let banner = model.banner {
                BannerView(symbol: banner.severity == .info ? "info.circle.fill" : "exclamationmark.octagon.fill",
                           tint: banner.severity == .info ? .blue : .red, headline: banner.headline, detail: banner.detail,
                           dismiss: { app.secrets.banner = nil })
            }
        }
    }

    private var subtitle: String {
        guard model.isEnabled, model.hasLoaded else { return "" }
        let n = model.secrets.count
        return n == 1 ? "1 secret" : "\(n) secrets"
    }

    // MARK: toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button(action: addSecret) {
                Label("Add Secret", systemImage: "plus")
            }
            .keyboardShortcut("n", modifiers: .command)
            .help("Add a secret (⌘N)")
            .disabled(!model.isEnabled)

            Button(action: chooseEnvFile) {
                Label("Import .env…", systemImage: "square.and.arrow.down")
            }
            .help(app.importRunner == nil ? "The helper inside this app could not be found." : "Import secrets from a .env file")
            .disabled(!model.isEnabled || app.importRunner == nil)

            Button {
                if let s = model.detailSecret { editSecret(s) }
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .help("Edit the selected secret")
            .disabled(!model.isEnabled || model.detailSecret == nil)

            Button {
                requestDelete(model.selectedSecrets.map(\.name))
            } label: {
                Label("Delete", systemImage: "trash")
            }
            .keyboardShortcut(.delete, modifiers: .command)
            .help("Delete the selected secrets")
            .disabled(!model.isEnabled || model.selection.isEmpty)
        }
        ToolbarItem(placement: .automatic) {
            Button {
                showInspector.toggle()
            } label: {
                Label("Details", systemImage: "sidebar.trailing")
            }
            .help("Show or hide the details")
        }
    }

    // MARK: actions

    private func addSecret() {
        guard model.isEnabled else { return }
        form = model.makeAddForm()
    }

    private func editSecret(_ s: SecretInfo) {
        guard model.isEnabled else { return }
        form = model.makeEditForm(for: s)
    }

    private func requestDelete(_ names: [String]) {
        guard model.isEnabled, !names.isEmpty else { return }
        Task {
            let c = await model.deleteConfirmation(for: names)
            deleteNames = names
            deleteConfirmation = c
        }
    }

    /// NSOpenPanel with hidden files shown: `.env` starts with a dot and has
    /// no content type. The panel's URL carries the access the person granted.
    private func chooseEnvFile() {
        guard model.isEnabled, app.importRunner != nil else { return }
        let panel = NSOpenPanel()
        panel.title = "Import .env"
        panel.message = "Choose a .env file. grantd reads the names; the values go straight to the vault."
        panel.prompt = "Choose"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.treatsFilePackagesAsDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        beginImport(url)
    }

    private func beginImport(_ url: URL) {
        guard model.isEnabled, let runner = app.importRunner else { return }
        let secrets = app.secrets
        importSession = ImportSession(url: url, runner: runner, onImported: { await secrets.refresh() })
    }
}

// MARK: - pieces

private struct EmptyState: View {
    let canImport: Bool
    let add: () -> Void
    let importFile: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label("No secrets yet", systemImage: "key")
        } description: {
            Text("Add one, or import a .env file.")
        } actions: {
            Button("Add Secret…", action: add)
                .keyboardShortcut("n", modifiers: .command)
            Button("Import .env…", action: importFile).disabled(!canImport)
        }
    }
}

private struct BannerView: View {
    let symbol: String
    let tint: Color
    let headline: String
    let detail: String?
    let dismiss: (() -> Void)?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: headline)
                if let detail, !detail.isEmpty {
                    Text(verbatim: detail).font(.caption).foregroundStyle(.secondary)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            Spacer()
            if let dismiss {
                Button(action: dismiss) { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Dismiss")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
        .overlay(alignment: .bottom) { Divider() }
        .accessibilityElement(children: .combine)
    }
}

struct TierLabel: View {
    let tier: Tier

    var body: some View {
        switch tier.rank {
        case 2: Label("Hardware", systemImage: "lock.shield.fill").lineLimit(1)
        case 1: Label("Dialog", systemImage: "lock.fill").lineLimit(1)
        default: Label("None", systemImage: "lock.open").lineLimit(1).foregroundStyle(.secondary)
        }
    }
}

/// `in 12 d`, red when expired, orange under seven days.
struct ExpiryText: View {
    let date: Date?

    var body: some View {
        if let text = ExpiryFormatter.relative(date) {
            Text(verbatim: text)
                .foregroundStyle(color)
                .monospacedDigit()
        } else {
            Text(verbatim: "—").foregroundStyle(.tertiary)
                .accessibilityLabel("Never expires")
        }
    }

    private var color: Color {
        switch ExpiryFormatter.state(date) {
        case .expired: return .red
        case .soon: return .orange
        default: return .primary
        }
    }
}

// MARK: - detail

private struct SecretDetail: View {
    let model: SecretsViewModel
    let edit: (SecretInfo) -> Void

    var body: some View {
        Group {
            if let s = model.detailSecret {
                detail(s)
            } else if model.selection.count > 1 {
                ContentUnavailableView("\(model.selection.count) secrets selected", systemImage: "key.horizontal")
            } else {
                ContentUnavailableView("No selection", systemImage: "key", description: Text("Select a secret to see its details."))
            }
        }
    }

    @ViewBuilder
    private func detail(_ s: SecretInfo) -> some View {
        Form {
            Section {
                Text(verbatim: DisplayText.sanitise(s.name, limit: DisplayText.detailLimit))
                    .font(.headline)
                    .textSelection(.enabled)
                Text(verbatim: "Programs see this as $" + Validators.environmentVariable(for: s.name))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .help("Unless another secret ends in the same word; then the full name is used.")
            }
            Section {
                LabeledContent("Protection") { TierLabel(tier: s.minTier) }
                LabeledContent("Expires") {
                    Text(verbatim: ExpiryFormatter.sentence(s.expiresAt))
                        .foregroundStyle(expiryColor(s.expiresAt))
                }
                if !s.tags.isEmpty {
                    LabeledContent("Tags") {
                        Text(verbatim: DisplayText.sanitise(s.tags.joined(separator: ", "), limit: DisplayText.detailLimit))
                            .multilineTextAlignment(.trailing)
                            .textSelection(.enabled)
                    }
                }
                LabeledContent("Updated") {
                    Text(s.updatedAt, format: .dateTime.year().month().day().hour().minute())
                }
            }
            if !s.url.isEmpty {
                Section("URL") {
                    Text(verbatim: DisplayText.sanitise(s.url, limit: DisplayText.detailLimit))
                        .textSelection(.enabled)
                    if let web = Validators.webURL(s.url), let host = web.host {
                        Button {
                            NSWorkspace.shared.open(web)
                        } label: {
                            Text(verbatim: "Open " + DisplayText.sanitise(host, limit: 60))
                        }
                    }
                }
            }
            if !s.notes.isEmpty {
                Section("Notes (not encrypted)") {
                    Text(verbatim: DisplayText.sanitise(s.notes, limit: DisplayText.detailLimit, allowNewlines: true))
                        .textSelection(.enabled)
                }
            }
            Section {
                switch model.masked {
                case .idle:
                    Button("Check last 4 characters") { Task { await model.checkLastCharacters(of: s.name) } }
                        .help("Asks grantd for the end of the stored value, to tell two keys apart. The full value is never shown.")
                case .loading:
                    ProgressView().controlSize(.small)
                case .value(let text):
                    LabeledContent("Ends with") {
                        Text(verbatim: DisplayText.sanitise(text, limit: 40)).font(.body.monospaced()).textSelection(.enabled)
                    }
                case .failed(let m):
                    Text(verbatim: m.headline).foregroundStyle(.red)
                }
            } footer: {
                Text("grantd never shows a stored value. Use grantd show in a terminal if you need it.")
            }
        }
        .formStyle(.grouped)
        .disabled(!model.isEnabled)
    }

    private func expiryColor(_ date: Date?) -> Color {
        switch ExpiryFormatter.state(date) {
        case .expired: return .red
        case .soon: return .orange
        default: return .primary
        }
    }
}

/// A file dropped on the window starts an import (docs/UI-SPEC.md 3.2).
private struct FileDropModifier: ViewModifier {
    @Binding var targeted: Bool
    let onDrop: (URL) -> Void

    func body(content: Content) -> some View {
        content
            .dropDestination(for: URL.self, action: { urls, _ in
                guard let url = urls.first, url.isFileURL else { return false }
                onDrop(url)
                return true
            }, isTargeted: { targeted = $0 })
            .overlay {
                if targeted {
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.accentColor, lineWidth: 3)
                        .padding(4)
                        .allowsHitTesting(false)
                }
            }
    }
}

/// Keeps the model in step with the daemon: the monitor's state, the sort
/// order, the selection, and a reload every 10 seconds (an agent can `set`
/// too, docs/UI-SPEC.md 2.4).
private struct LifecycleModifier: ViewModifier {
    let app: AppModel
    @Binding var sortOrder: [KeyPathComparator<SecretInfo>]

    func body(content: Content) -> some View {
        let model = app.secrets
        content
            .background(WindowKeyObserver { key in
                if key { app.surfaceAppeared("secrets") } else { app.surfaceDisappeared("secrets") }
            })
            .onChange(of: app.monitor.state, initial: true) { _, new in model.connectionChanged(new) }
            .onChange(of: model.selection) { _, _ in model.resetMasked() }
            .onChange(of: sortOrder) { _, new in model.sortAscending = new.first?.order != .reverse }
            .task {
                while !Task.isCancelled {
                    if model.isEnabled { await model.refresh() }
                    try? await Task.sleep(nanoseconds: 10_000_000_000)
                }
            }
    }
}
