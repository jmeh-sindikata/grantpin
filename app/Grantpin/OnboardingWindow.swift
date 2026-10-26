import AppKit
import SwiftUI
import GrantpinKit

/// The Welcome window (docs/UI-SPEC.md 3.6). Each step shows as done when its
/// condition already holds, so an existing install goes straight to Connect.
/// Every step has Back, and no step is blocked by a later one; closing the
/// window half-way is fine, the popover carries what is left.
struct OnboardingWindow: View {
    let app: AppModel
    @State private var confirmingWeaker = false
    @State private var moveProblem: String?

    private var model: OnboardingModel { app.onboarding }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if model.step == .connect {
                VStack(alignment: .leading, spacing: 10) { stepBody }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .padding(.horizontal, 24)
                    .padding(.top, 16)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) { stepBody }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(24)
                }
            }
            Divider()
            bottomBar.padding(12)
        }
        .frame(width: 560, height: 560)
        .onChange(of: app.monitor.state, initial: true) { _, new in model.connectionChanged(new) }
        .background(WindowKeyObserver { key in
            if key { app.surfaceAppeared("onboarding") } else { app.surfaceDisappeared("onboarding") }
        })
        .background(WindowSetup())
        .alert(
            Text(verbatim: OnboardingModel.weakerConfirmation.title),
            isPresented: $confirmingWeaker
        ) {
            Button(OnboardingModel.weakerConfirmation.confirmLabel) { Task { await model.createVaultWithWeakerProtection() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: OnboardingModel.weakerConfirmation.message)
        }
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 10) {
            ForEach(OnboardingStep.allCases, id: \.self) { s in
                HStack(spacing: 4) {
                    Image(systemName: model.isDone(s) && s != model.step ? "checkmark.circle.fill" : (s == model.step ? "circle.inset.filled" : "circle"))
                        .foregroundStyle(model.isDone(s) ? Color.green : (s == model.step ? Color.accentColor : Color.secondary))
                        .accessibilityHidden(true)
                    if s == model.step { Text(s.title).font(.callout.weight(.semibold)) }
                }
                .help(s.title)
                .accessibilityElement(children: .combine)
                .accessibilityLabel(Text(s.title + (model.isDone(s) ? ", done" : "")))
            }
            Spacer()
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 12)
    }

    // MARK: steps

    @ViewBuilder
    private var stepBody: some View {
        if app.socket.isDevelopment {
            Label {
                Text(verbatim: "Development socket: " + DisplayText.sanitise(app.socket.path))
            } icon: { Image(systemName: "hammer.fill").foregroundStyle(.orange) }
                .font(.callout)
        }
        switch model.step {
        case .welcome: welcome
        case .service: service
        case .vault: vault
        case .firstSecret: firstSecret
        case .connect: connect
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 44))
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            Text("Welcome to grantpin").font(.title.weight(.semibold))
            ForEach(OnboardingModel.welcomeLines, id: \.self) { line in
                Text(verbatim: line).fixedSize(horizontal: false, vertical: true)
            }
            if !model.location.isOK && !app.socket.isDevelopment {
                Label {
                    Text(verbatim: AppLocation.blockedMessage)
                } icon: { Image(systemName: "folder.badge.questionmark").foregroundStyle(.orange) }
                if let p = moveProblem { Hint(p, tint: .red) }
            }
        }
    }

    private var service: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Background service").font(.title2.weight(.semibold))
            Text(verbatim: OnboardingModel.serviceText).fixedSize(horizontal: false, vertical: true)
            if model.isDone(.service) {
                Label("The background service is running.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            } else {
                HStack {
                    Button("Install Service") { Task { await model.installService() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.running != nil || model.actionsDisabledReason != nil)
                    if model.running == .service { ProgressView().controlSize(.small) }
                }
                if let r = model.actionsDisabledReason { Hint(r, tint: .secondary) }
            }
            if let r = model.lastResult { ResultLine(result: r) }
        }
    }

    private var vault: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vault").font(.title2.weight(.semibold))
            Text(verbatim: OnboardingModel.vaultText).fixedSize(horizontal: false, vertical: true)
            if model.isDone(.vault) {
                Label("Your vault is ready.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                if let line = model.vaultProtectionLine { Text(verbatim: line).foregroundStyle(.secondary) }
            } else if !model.isDone(.service) {
                Hint("Install the background service first.", tint: .secondary)
            } else {
                HStack {
                    Button("Create Vault") { Task { await model.createVault() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.running != nil || model.actionsDisabledReason != nil)
                    if model.running == .vault { ProgressView().controlSize(.small) }
                }
                if let r = model.actionsDisabledReason { Hint(r, tint: .secondary) }
            }
            if model.offersWeakerProtection {
                Label {
                    Text(verbatim: OnboardingModel.noHardwareText).fixedSize(horizontal: false, vertical: true)
                } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                Button("Use Weaker Protection…") { confirmingWeaker = true }
                    .disabled(model.running != nil)
            }
            if let r = model.lastResult, !(model.isDone(.vault) && r.isSuccess) { ResultLine(result: r) }
        }
    }

    private var firstSecret: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("First secret").font(.title2.weight(.semibold))
            Text(verbatim: OnboardingModel.firstSecretText)
            if model.isDone(.firstSecret) {
                Label("You have a secret in your vault.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            }
            HStack {
                Button("Add Secret…") { openSecrets(.add) }
                Button("Import .env…") { openSecrets(.importFile) }
            }
        }
    }

    private var connect: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect Claude Code").font(.title2.weight(.semibold))
            ConnectPanel(app: app, showsHeading: false)
                .frame(maxHeight: .infinity)
            Toggle(OnboardingModel.loginLabel, isOn: Bindable(model).startAtLogin)
                .disabled(app.socket.isDevelopment || !model.location.isOK)
            if let e = model.loginError { Hint(e, tint: .red) }
        }
        .padding(.bottom, 8)
    }

    // MARK: bottom bar

    private var bottomBar: some View {
        HStack {
            Button("Back") { model.back() }
                .disabled(!model.canGoBack)
            Spacer()
            if model.canSkip {
                Button("Skip") { model.skip() }
            }
            if model.step == .welcome && !model.location.isOK && !app.socket.isDevelopment {
                Button(AppLocation.moveButton) { moveProblem = app.moveToApplicationsAndRelaunch() }
                    .buttonStyle(.borderedProminent)
            } else if model.step == .connect {
                Button("Done") {
                    model.finish()
                    NSApp.keyWindow?.close()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            } else {
                Button("Continue") { model.next() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canContinue)
            }
        }
    }

    private func openSecrets(_ intent: SecretsIntent) {
        app.secretsIntent = intent
        app.requestWindow(WindowID.secrets)
    }
}
