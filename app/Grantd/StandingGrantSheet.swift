import AppKit
import SwiftUI
import GrantdKit

/// The "New standing grant" form (docs/UI-SPEC.md 3.3).
///
/// The button is **Ask Me to Confirm…**, not "Create": it sends exactly one
/// `grants add`, and the daemon then shows its own dialog and Touch ID. This
/// view has no approve button of its own, never retries, and its Cancel
/// closes the request, which makes the daemon withdraw its dialog.
struct StandingGrantSheet: View {
    @Bindable var form: StandingGrantFormModel
    let onCreated: (String) -> Void

    static let ttlKey = "standingGrantTTL"
    static let folderKey = "standingGrantFolder"

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if form.isWaiting { waitingSection }
                if let error = form.error { errorSection(error) }
                Section {
                    Text(verbatim: StandingGrantFormModel.explanation)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                callerSection
                folderSection
                secretsSection
                commandSection
                if form.isRisky { riskSection }
                lifetimeSection
            }
            .formStyle(.grouped)
            .disabled(form.isWaiting)

            Divider()
            footer
        }
        .frame(width: 560)
        .frame(minHeight: 460, idealHeight: 720, maxHeight: 820)
        .task { await form.loadChoices() }
        .onChange(of: form.phase) { _, phase in
            if case .created(let message) = phase {
                onCreated(message)
                dismiss()
            }
        }
        .onDisappear { form.cancel() }
    }

    // MARK: sections

    private var waitingSection: some View {
        Section {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text(verbatim: StandingGrantFormModel.waitingText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func errorSection(_ error: UserMessage) -> some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: error.headline).fixedSize(horizontal: false, vertical: true)
                    if let d = error.detail { Text(verbatim: d).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                }
            } icon: {
                Image(systemName: error.severity == .info ? "info.circle.fill" : "exclamationmark.octagon.fill")
                    .foregroundStyle(error.severity == .info ? Color.blue : Color.red)
            }
        }
    }

    private var callerSection: some View {
        Section("Who is it for") {
            HStack {
                TextField("Who is it for", text: $form.forCaller, prompt: Text("claude-code"))
                    .autocorrectionDisabled()
                    .labelsHidden()
                Menu {
                    ForEach(form.knownCallers, id: \.self) { c in
                        Button(action: { form.forCaller = c }) { Text(verbatim: DisplayText.sanitise(c, limit: 64)) }
                    }
                } label: {
                    Image(systemName: "chevron.down.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Callers seen in the activity log")
            }
            if let m = form.callerMessage { Hint(m, tint: .red) }
            Hint(StandingGrantFormModel.callerHelp, tint: .secondary)
        }
    }

    private var folderSection: some View {
        Section("Folder") {
            HStack {
                Text(verbatim: form.folder.map { DisplayText.sanitise(form.folderResolved ?? $0, limit: 200) } ?? "No folder chosen")
                    .foregroundStyle(form.folder == nil ? .secondary : .primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Spacer()
                Button("Choose Folder…", action: chooseFolder)
            }
            if let m = form.folderMessage, form.folder != nil { Hint(m, tint: .red) }
            Hint("The grant covers this folder and everything inside it.", tint: .secondary)
        }
    }

    private var secretsSection: some View {
        Section("Secrets") {
            if form.availableSecrets.isEmpty {
                Text(form.choicesFailed ? "The secrets could not be listed. Type a name or pattern below." : "No secrets to choose from. Type a name or pattern below.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(form.availableSecrets, id: \.self) { name in
                            Toggle(isOn: Binding(
                                get: { form.selectedSecrets.contains(name) },
                                set: { on in if on { form.selectedSecrets.insert(name) } else { form.selectedSecrets.remove(name) } })
                            ) {
                                Text(verbatim: DisplayText.sanitise(name)).lineLimit(1).truncationMode(.middle)
                            }
                            .toggleStyle(.checkbox)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                }
                .frame(maxHeight: 130)
            }
            TextField("Pattern", text: $form.patternsText, prompt: Text("Optional: aws/*, db/{prod,stage}"))
                .autocorrectionDisabled()
            if let m = form.secretsMessage { Hint(m, tint: .red) }
            if form.hasGlob { Hint(StandingGrantFormModel.globHelp, tint: .orange) }
        }
    }

    private var commandSection: some View {
        Section("Command") {
            TextField("Command", text: $form.commandText, prompt: Text("php artisan"))
                .autocorrectionDisabled()
                .font(.body.monospaced())
            if !form.commandTokens.isEmpty {
                FlowLayout(spacing: 4) {
                    ForEach(Array(form.commandTokens.enumerated()), id: \.offset) { _, token in
                        Text(verbatim: DisplayText.sanitise(token, limit: 40))
                            .font(.caption.monospaced())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(.quaternary, in: Capsule())
                    }
                }
            }
            if let m = form.commandMessage { Hint(m, tint: .red) }
            Hint(StandingGrantFormModel.commandHelp, tint: .secondary)
        }
    }

    private var lifetimeSection: some View {
        Section("Lasts") {
            Picker("Lasts", selection: $form.ttl) {
                ForEach(StandingTTL.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            if form.ttl == .custom {
                TextField("Time", text: $form.customTTL, prompt: Text("7d, 12h, 90m"))
                    .autocorrectionDisabled()
            }
            if let m = form.ttlMessage { Hint(m, tint: .red) }
            Hint("90 days at most. A .grantd.yml in the folder can lower that.", tint: .secondary)
            TextField("Run limit", text: $form.usesText, prompt: Text("Optional: stop after this many runs"))
                .autocorrectionDisabled()
            if let m = form.usesMessage { Hint(m, tint: .red) }
        }
    }

    private var riskSection: some View {
        Section {
            Label {
                Text(verbatim: form.riskText).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            .foregroundStyle(.red)
            Toggle("I understand", isOn: $form.understood)
        }
    }

    // MARK: footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: form.summary)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            HStack {
                Spacer()
                Button(form.isWaiting ? "Cancel Request" : "Cancel", role: .cancel) {
                    form.cancel()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button("Ask Me to Confirm…") { form.start() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!form.canSubmit)
                    .help("grantd shows its own dialog next, then Touch ID.")
            }
        }
        .padding(12)
    }

    // MARK: actions

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.title = "Choose Folder"
        panel.message = "Choose the folder this standing grant covers."
        panel.prompt = "Choose"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        if let last = form.folder, RealPath.isDirectory(last) {
            panel.directoryURL = URL(fileURLWithPath: last)
        } else {
            panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        }
        if panel.runModal() == .OK, let url = panel.url { form.chooseFolder(url.path) }
    }
}

/// Lays children out left to right and wraps to the next line.
struct FlowLayout: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(width: proposal.width ?? 400, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrange(width: bounds.width, subviews: subviews)
        for (i, p) in result.positions.enumerated() {
            subviews[i].place(at: CGPoint(x: bounds.minX + p.x, y: bounds.minY + p.y), proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> (size: CGSize, positions: [CGPoint]) {
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, maxX: CGFloat = 0
        var positions = [CGPoint]()
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x > 0, x + s.width > width { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            positions.append(CGPoint(x: x, y: y))
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
            maxX = max(maxX, x - spacing)
        }
        return (CGSize(width: maxX, height: y + rowHeight), positions)
    }
}
