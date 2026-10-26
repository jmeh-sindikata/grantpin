import AppKit
import SwiftUI
import UniformTypeIdentifiers
import GrantdKit

/// The Activity window (docs/UI-SPEC.md 3.4): what agents asked for, what you
/// answered, whether the record is intact.
///
/// A released run and its result are one row. Denials and blocks are drawn
/// distinctly (icon, colour and a word). Every cell comes from the audit log
/// and is untrusted text: it was sanitised by `AuditPairing` and is drawn
/// with `Text(verbatim:)`.
struct ActivityWindow: View {
    let app: AppModel
    @State private var selection: String?
    @State private var showDetail: Bool
    @State private var exportMessage: UserMessage?

    init(app: AppModel, showDetail: Bool = true) {
        self.app = app
        _showDetail = State(initialValue: showDetail)
    }

    private var model: ActivityViewModel { app.activity }

    var body: some View {
        content
            .frame(minWidth: 760, minHeight: 360)
            .safeAreaInset(edge: .top, spacing: 0) { banners }
            .safeAreaInset(edge: .bottom, spacing: 0) { footer }
            .inspector(isPresented: $showDetail) {
                ActivityDetailPane(model: model, selection: selection)
                    .inspectorColumnWidth(min: 240, ideal: 300, max: 420)
            }
            .searchable(text: Bindable(model).searchText, placement: .toolbar, prompt: "Search")
            .toolbar { toolbar }
            .navigationTitle("Activity")
            .navigationSubtitle(subtitle)
            .background(WindowKeyObserver { key in
                if key { app.surfaceAppeared("activity") } else { app.surfaceDisappeared("activity") }
            })
            .onChange(of: app.monitor.state, initial: true) { _, new in model.connectionChanged(new) }
            .task {
                // Every 5 seconds while the window exists (docs/UI-SPEC.md 2.4).
                while !Task.isCancelled {
                    if model.isEnabled { await model.refresh() }
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                }
            }
            .background(WindowSetup())
    }

    @ViewBuilder
    private var content: some View {
        if model.isEmpty && model.isEnabled {
            ContentUnavailableView {
                Label("No activity yet", systemImage: "list.bullet.rectangle")
            } description: {
                Text("When an agent asks to use a secret, it shows up here.")
            }
        } else {
            table
        }
    }

    // MARK: table

    private var table: some View {
        Table(model.visibleEvents, selection: $selection) {
            TableColumn("Time") { e in
                Text(e.time, format: .dateTime.month(.abbreviated).day().hour().minute().second())
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 110, ideal: 130, max: 160)
            TableColumn("Event") { e in
                EventLabel(event: e)
            }
            .width(min: 140, ideal: 190)
            TableColumn("Detail") { e in
                Text(verbatim: e.command)
                    .font(.body.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(e.command)
            }
            .width(min: 120, ideal: 220)
            TableColumn("Caller") { e in
                Text(verbatim: e.caller).lineLimit(1).truncationMode(.tail)
            }
            .width(min: 70, ideal: 100)
            TableColumn("Secrets") { e in
                Text(verbatim: DisplayText.sanitise(e.secrets.joined(separator: ", ")))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .width(min: 80, ideal: 130)
            TableColumn("Result") { e in
                ResultCell(event: e)
            }
            .width(min: 100, ideal: 140)
        }
        .overlay {
            if model.visibleEvents.isEmpty && !model.events.isEmpty {
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
            verifyBanner
            if let m = exportMessage {
                BannerView(symbol: "exclamationmark.octagon.fill", tint: .red, headline: m.headline, detail: m.detail,
                           dismiss: { exportMessage = nil })
            }
            if let banner = model.banner {
                BannerView(symbol: banner.severity == .info ? "info.circle.fill" : "exclamationmark.octagon.fill",
                           tint: banner.severity == .info ? .blue : .red, headline: banner.headline, detail: banner.detail,
                           dismiss: { model.banner = nil })
            }
        }
    }

    @ViewBuilder
    private var verifyBanner: some View {
        switch model.verify {
        case .idle:
            EmptyView()
        case .running:
            BannerView(symbol: "hourglass", tint: .secondary, headline: "Checking the log…", detail: nil, dismiss: nil)
        case .ok(let entries):
            BannerView(symbol: "checkmark.seal.fill", tint: .green,
                       headline: ActivityViewModel.verifiedText(entries: entries),
                       detail: ActivityViewModel.verifiedCaption, dismiss: { model.dismissVerify() })
        case .broken(let id):
            VStack(alignment: .leading, spacing: 0) {
                BannerView(symbol: "xmark.seal.fill", tint: .red, headline: ActivityViewModel.brokenText(firstBadID: id),
                           detail: nil, dismiss: { model.dismissVerify() })
                HStack {
                    Spacer()
                    Button("Export CSV…", action: exportCSV).padding(.horizontal, 12).padding(.vertical, 6)
                }
                .background(.bar)
                .overlay(alignment: .bottom) { Divider() }
            }
        case .failed(let m):
            BannerView(symbol: "exclamationmark.octagon.fill", tint: .red, headline: m.headline, detail: m.detail,
                       dismiss: { model.dismissVerify() })
        }
    }

    private var footer: some View {
        Group {
            if model.canLoadMore || model.footer != nil {
                HStack {
                    if let f = model.footer {
                        Text(verbatim: f).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.canLoadMore {
                        Button("Load More") { Task { await model.loadMore() } }
                            .disabled(model.isLoading)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(.bar)
                .overlay(alignment: .top) { Divider() }
            }
        }
    }

    private var subtitle: String {
        guard model.isEnabled, model.hasLoaded else { return "" }
        let n = model.visibleEvents.count
        return n == 1 ? "1 event" : "\(n) events"
    }

    // MARK: toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .principal) {
            Picker("Show", selection: Bindable(model).filter) {
                ForEach(ActivityFilter.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .help("Filter the log")
            .frame(minWidth: 300)
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button {
                Task { await model.verifyLog() }
            } label: {
                Label("Verify Log", systemImage: "checkmark.seal")
            }
            .help("Check that nobody edited or removed entries in the middle of the log")
            .disabled(!model.isEnabled || model.verify == .running)

            Button(action: exportCSV) {
                Label("Export CSV…", systemImage: "square.and.arrow.up")
            }
            .help("Save the whole log as a CSV file")
            .disabled(!model.isEnabled || model.isExporting)

            Button {
                showDetail.toggle()
            } label: {
                Label("Details", systemImage: "sidebar.trailing")
            }
            .help("Show or hide the details")
        }
    }

    // MARK: export

    private func exportCSV() {
        Task {
            exportMessage = nil
            switch await model.exportCSV() {
            case .failed(let m):
                exportMessage = m
            case .csv(let text, let name):
                let panel = NSSavePanel()
                panel.title = "Export Activity"
                panel.message = ActivityViewModel.exportPanelMessage
                panel.nameFieldStringValue = name
                panel.allowedContentTypes = [.commaSeparatedText]
                panel.directoryURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
                guard panel.runModal() == .OK, let url = panel.url else { return }
                // The CSV is written exactly as the daemon sent it.
                do { try Data(text.utf8).write(to: url, options: .atomic) } catch {
                    exportMessage = UserMessage("The file could not be saved.")
                }
            }
        }
    }
}

/// Icon, title and (for a denial or block) the colour.
private struct EventLabel: View {
    let event: AuditEvent

    var body: some View {
        Label {
            Text(verbatim: event.title).lineLimit(1)
        } icon: {
            Image(systemName: symbol).foregroundStyle(color)
        }
        .accessibilityElement(children: .combine)
    }

    private var symbol: String {
        switch event.tone {
        case .denied: return "hand.raised.fill"
        case .blocked: return "nosign"
        case .error: return "exclamationmark.triangle.fill"
        case .succeeded: return "checkmark.circle"
        case .failed: return "xmark.circle"
        case .neutral:
            switch event.kind {
            case .change: return "pencil"
            case .standingGrant: return "checkmark.shield"
            case .run, .resultOnly: return "terminal"
            case .refused: return "nosign"
            }
        }
    }

    private var color: Color {
        switch event.tone {
        case .denied: return .orange
        case .blocked: return .red
        case .error: return .orange
        case .succeeded: return .green
        case .failed: return .red
        case .neutral: return .secondary
        }
    }
}

private struct ResultCell: View {
    let event: AuditEvent

    var body: some View {
        Text(verbatim: event.resultText)
            .monospacedDigit()
            .lineLimit(1)
            .foregroundStyle(color)
    }

    private var color: Color {
        switch event.tone {
        case .denied: return .orange
        case .blocked, .failed: return .red
        case .error: return .orange
        default: return .secondary
        }
    }
}

/// The detail pane: the full command as one selectable monospaced string,
/// the folder, the secrets (as asked and as expanded), grant, result, row ids.
private struct ActivityDetailPane: View {
    let model: ActivityViewModel
    let selection: String?

    var body: some View {
        if let id = selection, let d = model.detail(for: id) {
            Form {
                Section {
                    Text(verbatim: d.title).font(.headline)
                    Text(d.time, format: .dateTime.year().month().day().hour().minute().second())
                        .foregroundStyle(.secondary)
                }
                if !d.command.isEmpty {
                    Section("Command") {
                        Text(verbatim: d.command)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Section {
                    row("Result", d.result)
                    row("Caller", d.caller)
                    row("Folder", d.cwd)
                    row("Secrets asked for", d.secretsRequested)
                    if let x = d.secretsExpanded { row("Secrets used", x) }
                    row("Grant", d.grantID)
                    row("Reason", d.reason)
                    row(d.rowIDs.count == 1 ? "Log entry" : "Log entries", d.rowIDs.joined(separator: ", "))
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView("No selection", systemImage: "list.bullet.rectangle", description: Text("Select an event to see its details."))
        }
    }

    @ViewBuilder
    private func row(_ title: String, _ value: String) -> some View {
        if !value.isEmpty {
            LabeledContent(title) {
                Text(verbatim: value)
                    .multilineTextAlignment(.trailing)
                    .textSelection(.enabled)
            }
        }
    }
}
