import AppKit
import SwiftUI
import GrantdKit

/// One run of the Import .env sheet: the chosen file, the access the person
/// granted to it, and the view model that talks to the helper.
///
/// The app never reads the file. Each run opens it with `FileHandle` and hands
/// the descriptor to the helper as standard input (docs/UI-SPEC.md 3.2).
@MainActor
final class ImportSession: Identifiable {
    let id = UUID()
    let url: URL
    let model: ImportViewModel
    private let scoped: Bool

    init(url: URL, runner: ImportRunner, onImported: @escaping @MainActor () async -> Void) {
        self.url = url
        // For a file the person picked in a panel or dropped; false (and
        // harmless) when the app is not sandboxed.
        scoped = url.startAccessingSecurityScopedResource()
        model = ImportViewModel(
            service: runner, fileName: url.lastPathComponent,
            openFile: { try FileHandle(forReadingFrom: url) }, onImported: onImported)
    }

    func close() {
        if scoped { url.stopAccessingSecurityScopedResource() }
    }
}

struct ImportSheet: View {
    let session: ImportSession
    let dismiss: () -> Void
    @State private var confirmingOverwrite = false
    @State private var started = false

    private var model: ImportViewModel { session.model }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Import .env")
                    .font(.headline)
                Text(verbatim: model.fileName)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding([.horizontal, .top], 20)
            .padding(.bottom, 12)

            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)

            Spacer(minLength: 12)
            Divider()
            buttons.padding(12)
        }
        .frame(width: 480)
        .frame(minHeight: 300, idealHeight: 420, maxHeight: 640)
        .task {
            guard !started else { return }
            started = true
            await model.preview()
        }
        .alert(
            Text(verbatim: model.overwriteConfirmation?.title ?? ""),
            isPresented: $confirmingOverwrite,
            presenting: model.overwriteConfirmation
        ) { c in
            Button(c.confirmLabel, role: .destructive) { Task { await model.performImport() } }
            Button("Cancel", role: .cancel) {}
        } message: { c in
            Text(verbatim: c.message)
        }
    }

    // MARK: content

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .previewing:
            progress("Reading the file…")
        case .importing:
            progress("Importing…")
        case .preview(let report):
            VStack(alignment: .leading, spacing: 12) {
                if report.nothingToImport {
                    Text("There is nothing to import in this file.").foregroundStyle(.secondary)
                } else {
                    Counts(report: report)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            NameGroup(title: "New", symbol: "plus.circle", names: report.added)
                            NameGroup(title: report.overwritten.isEmpty ? "Already exist" : "Will be overwritten",
                                      symbol: "arrow.triangle.2.circlepath",
                                      names: report.overwritten.isEmpty ? report.skipped : report.overwritten)
                            NameGroup(title: "Empty, ignored", symbol: "minus.circle", names: report.ignoredEmpty)
                        }
                    }
                    .frame(maxHeight: 220)
                }
                conflictPicker
            }
        case .failed(let f):
            VStack(alignment: .leading, spacing: 10) {
                Label {
                    Text(verbatim: f.headline).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
                }
                if !f.conflicts.isEmpty {
                    NameGroup(title: "Already exist", symbol: "arrow.triangle.2.circlepath", names: f.conflicts)
                    Text("Choose Skip existing or Overwrite existing below.").font(.callout).foregroundStyle(.secondary)
                    conflictPicker
                }
                if let detail = f.detail {
                    Text(verbatim: detail)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if f.partial { Text(verbatim: ImportFailure.partialNote).font(.callout) }
            }
        case .done(let report):
            VStack(alignment: .leading, spacing: 10) {
                Label {
                    Text(verbatim: report.summary)
                } icon: {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
                Text("Your .env file is still on disk. Consider deleting it.")
                    .foregroundStyle(.secondary)
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([session.url]) }
            }
        }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(text).foregroundStyle(.secondary)
        }
    }

    private var conflictPicker: some View {
        Picker("If a name already exists", selection: Binding(
            get: { model.mode },
            set: { new in Task { await model.setMode(new) } })
        ) {
            Text("Skip existing").tag(ImportConflictMode.skip)
            Text("Overwrite existing").tag(ImportConflictMode.overwrite)
            Text("Stop if any exist").tag(ImportConflictMode.error)
        }
        .disabled(model.isBusy)
    }

    // MARK: buttons

    @ViewBuilder
    private var buttons: some View {
        HStack {
            Spacer()
            if case .done = model.phase {
                Button("Done") { finish() }
                    .keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel", role: .cancel) { finish() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.phase == .importing)
                Button("Import") {
                    if model.overwriteConfirmation != nil { confirmingOverwrite = true } else { Task { await model.performImport() } }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canImport)
            }
        }
    }

    private func finish() {
        session.close()
        dismiss()
    }
}

private struct Counts: View {
    let report: ImportReport

    var body: some View {
        HStack(spacing: 18) {
            count("Added", report.addedCount)
            count("Overwritten", report.overwrittenCount)
            count("Skipped", report.skippedCount)
            count("Empty", report.emptyCount)
        }
        .accessibilityElement(children: .combine)
    }

    private func count(_ title: String, _ n: Int) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(n)").font(.title2.monospacedDigit())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct NameGroup: View {
    let title: String
    let symbol: String
    let names: [String]

    var body: some View {
        if !names.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Label("\(title) (\(names.count))", systemImage: symbol).font(.subheadline.weight(.medium))
                Text(verbatim: DisplayText.sanitise(names.joined(separator: ", "), limit: DisplayText.detailLimit))
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
