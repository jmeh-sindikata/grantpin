import AppKit
import SwiftUI
import GrantdKit

/// "Connect Claude Code" (docs/UI-SPEC.md 3.5): the exact `claude mcp add`
/// command, the `.mcp.json` snippet, the test prompt, each with a Copy
/// button. Used by the Connect tab of Settings and by the last onboarding step.
///
/// The app does not run `claude`, does not look for it and does not read
/// `~/.claude.json`; copying text is all it does with the clipboard here.
struct ConnectPanel: View {
    let app: AppModel
    /// The Settings tab shows the heading; the onboarding step has its own.
    var showsHeading = true
    @State private var scope = ConnectSnippets.Scope.allProjects
    @State private var testing = false
    @State private var testResult: ConnectionTest.Result?

    private var helperPath: String {
        app.helper?.path ?? ConnectSnippets.defaultHelperPath(bundleURL: Bundle.main.bundleURL)
    }

    /// The job still runs the pre-0.2 bundle layout: a registration with that
    /// path breaks, and the panel says so up front.
    private var oldPathLikely: Bool {
        app.serviceWatcher.status?.usesLegacyBundlePath == true || app.settings.service?.usesLegacyBundlePath == true
    }

    var body: some View {
        Form {
            Section {
                Picker("Scope", selection: $scope) {
                    Text("All my projects").tag(ConnectSnippets.Scope.allProjects)
                    Text("Only one project").tag(ConnectSnippets.Scope.oneProject)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                CopyBox(text: ConnectSnippets.command(scope: scope, helper: helperPath), label: "Copy Command")
                if scope == .oneProject {
                    Hint(ConnectSnippets.projectHint, tint: .secondary)
                }
                if app.socket.isDevelopment {
                    Hint("Development mode: this path is the development helper, not an installed app.", tint: .orange)
                }
                Hint(ConnectSnippets.restartNote, tint: .secondary)
            } header: {
                if showsHeading { Text("Connect Claude Code") }
            }

            Section(".mcp.json") {
                CopyBox(text: ConnectSnippets.mcpJSON(helper: helperPath), label: "Copy JSON")
                Hint(ConnectSnippets.jsonCaption, tint: .secondary)
            }

            Section("Older path") {
                Label {
                    Text(verbatim: ConnectSnippets.oldPathCallout).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: oldPathLikely ? "exclamationmark.triangle.fill" : "arrow.triangle.2.circlepath")
                        .foregroundStyle(oldPathLikely ? Color.orange : Color.secondary)
                }
                CopyBox(text: ConnectSnippets.removeCommand, label: "Copy Command")
            }

            Section("Test") {
                CopyBox(text: ConnectSnippets.testPrompt, label: "Copy Prompt", monospaced: false)
                Hint(ConnectSnippets.testPromptCaption, tint: .secondary)
                Text(verbatim: "Claude Code should list " + ConnectSnippets.toolNames.joined(separator: ", ") + " under /mcp.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Test Connection") { runTest() }
                        .disabled(testing)
                        .help("Asks the background service whether a secret exists, the same question Claude Code's secret_exists tool asks")
                    if testing { ProgressView().controlSize(.small) }
                }
                if let r = testResult {
                    Label {
                        Text(verbatim: r.text).fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: r == .answered ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(r == .answered ? Color.green : Color.red)
                    }
                    if r == .answered {
                        Hint("This checks the background service. It cannot tell whether Claude Code has the server registered.", tint: .secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private func runTest() {
        testing = true
        testResult = nil
        let client = app.client
        Task {
            let r = await ConnectionTest.run(client)
            testResult = r
            testing = false
        }
    }
}

/// A monospaced, selectable box with a Copy button next to it.
struct CopyBox: View {
    let text: String
    var label = "Copy"
    var monospaced = true
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(verbatim: text)
                .font(monospaced ? .callout.monospaced() : .callout)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            HStack {
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(text, forType: .string)
                    copied = true
                    Task {
                        try? await Task.sleep(nanoseconds: 1_500_000_000)
                        copied = false
                    }
                } label: {
                    Label(copied ? "Copied" : label, systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .controlSize(.small)
                Spacer()
            }
        }
    }
}
