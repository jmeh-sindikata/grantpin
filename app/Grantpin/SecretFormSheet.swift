import AppKit
import SwiftUI
import GrantdKit

/// The Add, Edit and Replace sheet (docs/UI-SPEC.md 3.2).
///
/// The value lives in `SecretFormModel.value` only while the sheet is open and
/// is dropped on save, on cancel and when the sheet goes away. It is never
/// stored in `@AppStorage`, `@SceneStorage` or anywhere else, and never logged.
struct SecretFormSheet: View {
    @Bindable var form: SecretFormModel
    let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.controlActiveState) private var activeState
    @FocusState private var focus: Field?
    @State private var confirmingReplace = false
    /// The request in flight. Cancel cancels it, which closes the connection
    /// and makes the daemon withdraw its dialog (a tier change can be waiting
    /// for the person to answer a dialog and Touch ID).
    @State private var saveTask: Task<Void, Never>?

    private enum Field { case name, value }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let error = form.error { errorSection(error) }
                nameSection
                if !form.isAdding { modeSection }
                if form.needsValue { valueSection }
                detailsSection
                protectionSection
                notesSection
            }
            .formStyle(.grouped)
            .disabled(form.isSaving)

            Divider()
            HStack {
                Text("If you use a clipboard manager, it may keep a copy of what you paste.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .opacity(form.needsValue ? 1 : 0)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                if form.isSaving { ProgressView().controlSize(.small) }
                Button("Cancel", role: .cancel) { close() }
                    .keyboardShortcut(.cancelAction)
                Button(form.saveTitle) { saveTapped() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!form.canSave)
            }
            .padding(12)
        }
        .frame(width: 520)
        .frame(minHeight: 420, idealHeight: 640, maxHeight: 760)
        .alert(
            Text(verbatim: form.replaceConfirmation?.title ?? ""),
            isPresented: $confirmingReplace,
            presenting: form.replaceConfirmation
        ) { c in
            Button(c.confirmLabel, role: .destructive) { startSave() }
            Button("Cancel", role: .cancel) {}
        } message: { c in
            Text(verbatim: c.message)
        }
        .onAppear { focus = form.isAdding ? .name : (form.needsValue ? .value : nil) }
        .onDisappear {
            form.discardSensitive()
            NSApp.keyWindow?.undoManager?.removeAllActions()
        }
        // "Show characters" hides again when the app loses focus and after 30 s.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            form.showCharacters = false
        }
        .task(id: form.showCharacters) {
            guard form.showCharacters else { return }
            try? await Task.sleep(nanoseconds: 30_000_000_000)
            if !Task.isCancelled { form.showCharacters = false }
        }
    }

    // MARK: sections

    private func errorSection(_ error: UserMessage) -> some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: error.headline)
                    if let d = error.detail { Text(verbatim: d).font(.caption).foregroundStyle(.secondary) }
                }
            } icon: {
                Image(systemName: error.severity == .info ? "info.circle.fill" : "exclamationmark.octagon.fill")
                    .foregroundStyle(error.severity == .info ? Color.blue : Color.red)
            }
        }
    }

    private var nameSection: some View {
        Section {
            if form.nameIsEditable {
                TextField("Name", text: $form.name, prompt: Text("aws/prod/access_key"))
                    .focused($focus, equals: .name)
                    .autocorrectionDisabled()
                    .textContentType(.none)
                if let m = form.nameMessage { Hint(m, tint: .red) }
                else if form.nameExists { Hint("A secret with this name exists. Replace it?", tint: .orange) }
            } else {
                LabeledContent("Name") { Text(verbatim: DisplayText.sanitise(form.name)).textSelection(.enabled) }
            }
            if !form.name.isEmpty, form.nameIssue == nil {
                Text(verbatim: "Programs see this as $" + Validators.environmentVariable(for: form.name))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help("Unless another secret ends in the same word; then the full name is used.")
            }
        }
    }

    private var modeSection: some View {
        Section {
            Picker("Change", selection: $form.mode) {
                Text("Edit details").tag(SecretFormModel.Mode.editDetails)
                Text("Replace value").tag(SecretFormModel.Mode.replaceValue)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if form.mode == .replaceValue {
                Hint("The new value overwrites the old one. The details below are kept as they are, unless you change them.", tint: .secondary)
            }
        }
    }

    private var valueSection: some View {
        Section("Value") {
            if form.multiline {
                TextEditor(text: $form.value)
                    .font(.body.monospaced())
                    .frame(minHeight: 110)
                    .focused($focus, equals: .value)
                    .autocorrectionDisabled()
                    // Not readable over the shoulder while another window is in front.
                    .blur(radius: activeState == .key ? 0 : 8)
                    .accessibilityLabel("Value")
            } else {
                HStack {
                    Group {
                        if form.showCharacters {
                            TextField("Value", text: $form.value)
                                .privacySensitive()
                                .autocorrectionDisabled()
                        } else {
                            SecureField("Value", text: $form.value)
                        }
                    }
                    .focused($focus, equals: .value)
                    Button {
                        form.paste()
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    .help("Paste the clipboard into the value")
                    Toggle("Show characters", isOn: $form.showCharacters)
                        .toggleStyle(.checkbox)
                }
            }
            if form.multiline {
                HStack {
                    Spacer()
                    Button { form.paste() } label: { Label("Paste", systemImage: "doc.on.clipboard") }
                }
            }
            Toggle("Multi-line value (certificate, key file)", isOn: Binding(
                get: { form.multiline },
                set: { form.multiline = $0; if $0 { form.showCharacters = false } }))
            if let m = form.valueMessage { Hint(m, tint: .red) }
            if let counter = form.valueCounter { Hint(counter, tint: form.valueIssue == nil ? .secondary : .red) }
            if let note = form.valueNote { Hint(note, tint: .secondary) }
            if form.pastedFromClipboard {
                Toggle("Clear the clipboard after saving", isOn: $form.clearClipboardAfterSaving)
            }
        }
    }

    private var detailsSection: some View {
        Section("Details") {
            TextField("Tags", text: $form.tagsText, prompt: Text("Optional, separated by commas"))
                .autocorrectionDisabled()
            if let m = form.tagParse.message { Hint(m, tint: .red) }
            TextField("URL", text: $form.url, prompt: Text("Optional"))
                .autocorrectionDisabled()
            if let m = form.urlMessage { Hint(m, tint: .red) }
            else if let note = form.urlNote { Hint(note, tint: .secondary) }

            Picker("Expires", selection: $form.expiryKind) {
                ForEach(ExpiryKind.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            if form.expiryKind == .date {
                DatePicker("Date", selection: $form.expiryDate, in: Date()..., displayedComponents: .date)
            }
            if form.expiryKind == .custom {
                TextField("Time from now", text: $form.expiryCustom, prompt: Text("30d, 2w, 12h"))
                    .autocorrectionDisabled()
            }
            if let m = form.expiryMessage { Hint(m, tint: .red) }
        }
    }

    private var protectionSection: some View {
        Section("Protection") {
            Picker("Protection", selection: $form.tier) {
                if form.isAdding || form.tier == .vaultDefault {
                    Text(TierChoice.vaultDefault.title).tag(TierChoice.vaultDefault)
                }
                Text(TierChoice.dialog.title).tag(TierChoice.dialog)
                Text(TierChoice.hardware.title).tag(TierChoice.hardware)
                    .disabled(!form.isAllowed(.hardware))
            }
            .disabled(!form.tierIsEditable)
            Hint(form.tier.explanation, tint: .secondary)
            if !form.isAllowed(.hardware) { Hint(form.hardwareDisabledHelp, tint: .secondary) }
            if !form.tierIsEditable {
                Hint("Set when the secret was created. To change it, use Edit details.", tint: .secondary)
            }
            if let note = form.lowerTierNote { Hint(note, tint: .orange) }
        }
    }

    private var notesSection: some View {
        Section("Notes") {
            TextField("Notes", text: $form.notes, axis: .vertical)
                .lineLimit(3...6)
            if let m = form.notesMessage { Hint(m, tint: .red) }
            Hint("Notes are stored unencrypted. Don't put secrets here.", tint: .secondary)
        }
    }

    // MARK: actions

    private func saveTapped() {
        if form.replaceConfirmation != nil {
            confirmingReplace = true
        } else {
            startSave()
        }
    }

    private func startSave() {
        saveTask = Task {
            if await form.save(), let name = form.savedName {
                onSaved(name)
                dismiss()
            }
        }
    }

    private func close() {
        saveTask?.cancel()
        form.discardSensitive()
        dismiss()
    }
}

/// A small line of help or validation text under a field.
struct Hint: View {
    let text: String
    let tint: Color
    init(_ text: String, tint: Color) { self.text = text; self.tint = tint }

    var body: some View {
        Text(verbatim: text)
            .font(.caption)
            .foregroundStyle(tint == .secondary ? AnyShapeStyle(.secondary) : AnyShapeStyle(tint))
            .fixedSize(horizontal: false, vertical: true)
    }
}
