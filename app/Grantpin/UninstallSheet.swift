import AppKit
import SwiftUI
import GrantpinKit

/// The Uninstall sheet (docs/UI-SPEC.md 3.5): checkboxes, nothing destructive
/// pre-ticked except stopping the service; deleting the vault needs the
/// typed word. The result says what stays on this Mac.
struct UninstallSheet: View {
    @Bindable var model: UninstallModel
    let app: AppModel
    let close: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch model.phase {
                case .choosing: choosing
                case .running(let step): running(step)
                case .finished(let report): finished(report)
                }
            }
            Divider()
            buttons.padding(12)
        }
        .frame(width: 520)
        .frame(minHeight: 340)
        .interactiveDismissDisabled(isRunning)
    }

    private var isRunning: Bool {
        if case .running = model.phase { return true }
        return false
    }

    // MARK: choosing

    private var choosing: some View {
        Form {
            if let reason = model.disabledReason {
                Section { Label { Text(verbatim: reason) } icon: { Image(systemName: "hammer.fill").foregroundStyle(.orange) } }
            }
            Section("Remove") {
                Toggle(UninstallModel.stopLabel, isOn: $model.stopService)
                    .disabled(model.stopIsForced)
                    .help(model.stopIsForced ? "The vault and its key are only deleted after the background service has stopped." : "")
                Toggle(model.deleteVaultLabel, isOn: $model.deleteVault)
                Toggle(UninstallModel.logsLabel, isOn: $model.deleteLogs)
                if model.offersCommandLine {
                    Toggle(UninstallModel.commandLineLabel, isOn: $model.removeCommandLine)
                }
                if model.offersKeychainItem {
                    Toggle(UninstallModel.keychainLabel, isOn: $model.deleteKeychainItem)
                }
                if model.offersHardwareKey {
                    Toggle(UninstallModel.hardwareKeyLabel, isOn: $model.deleteHardwareKey)
                }
                if model.tierUnknown {
                    Text(verbatim: model.tierUnknownText)
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            if model.needsTypedConfirmation {
                Section {
                    if model.deleteVault {
                        Label {
                            Text(verbatim: UninstallModel.deleteWarning).fixedSize(horizontal: false, vertical: true)
                        } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red) }
                    }
                    if model.showsKeyWarning {
                        Label {
                            Text(verbatim: UninstallModel.keyWarning).fixedSize(horizontal: false, vertical: true)
                        } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red) }
                    }
                    TextField(UninstallModel.confirmationPrompt, text: $model.confirmationText, prompt: Text("delete"))
                        .autocorrectionDisabled()
                }
            }
        }
        .formStyle(.grouped)
    }

    private func running(_ step: String) -> some View {
        VStack(spacing: 12) {
            Spacer()
            ProgressView()
            Text(verbatim: step).foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, minHeight: 260)
    }

    private func finished(_ report: UninstallReport) -> some View {
        Form {
            Section {
                ForEach(report.done, id: \.self) { line in
                    Label { Text(verbatim: line) } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
                }
                ForEach(report.notices, id: \.self) { line in
                    Label { Text(verbatim: line).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: "info.circle.fill").foregroundStyle(.secondary) }
                }
                if let problem = report.problem {
                    Label {
                        Text(verbatim: problem).fixedSize(horizontal: false, vertical: true)
                    } icon: { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
                }
            }
            if !report.remains.isEmpty {
                Section("What stays") {
                    ForEach(report.remains, id: \.self) { line in
                        Text(verbatim: line).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Section("To finish") {
                Text(verbatim: UninstallModel.disconnectText)
                CopyBox(text: UninstallModel.disconnectCommand, label: "Copy Command")
                Text(verbatim: UninstallModel.trashText)
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: buttons

    @ViewBuilder
    private var buttons: some View {
        HStack {
            Spacer()
            switch model.phase {
            case .choosing:
                Button("Cancel", role: .cancel, action: close)
                    .keyboardShortcut(.cancelAction)
                Button(UninstallModel.removeLabel, role: .destructive) { Task { await model.remove() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canRemove)
            case .running:
                EmptyView()
            case .finished:
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
        }
    }
}
