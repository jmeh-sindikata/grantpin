import Foundation
import XCTest
@testable import GrantdKit

@MainActor
final class OnboardingModelTests: XCTestCase {
    func model(control: ServiceControl? = FakeServiceControl(), login: LoginItemControl? = FakeLoginItem(), dev: Bool = false,
               location: AppLocation = .ok, finished: @escaping @MainActor () -> Void = {}) -> OnboardingModel {
        OnboardingModel(control: control, loginItem: login, isDevelopment: dev, location: location, onFinished: finished)
    }

    let ready1 = ConnectionState.ready(StatusResult(vaultInitialized: true, keystoreTier: .hardware, secrets: 1))
    let ready0 = ConnectionState.ready(StatusResult(vaultInitialized: true, keystoreTier: .hardware, secrets: 0))

    func testAFreshInstallStartsAtWelcome() {
        let m = model()
        m.connectionChanged(.notRunning)
        XCTAssertEqual(m.step, .welcome)
        XCTAssertTrue(m.isDone(.welcome))
        XCTAssertFalse(m.isDone(.service))
        XCTAssertFalse(m.isDone(.vault))
    }

    func testAnExistingInstallSkipsToTheFirstOpenStep() {
        let m = model()
        m.connectionChanged(ready1)
        XCTAssertEqual(m.step, .connect, "service, vault and a secret exist: only Connect is left")
        let m2 = model()
        m2.connectionChanged(ready0)
        XCTAssertEqual(m2.step, .firstSecret)
        let m3 = model()
        m3.connectionChanged(.notInitialized)
        XCTAssertEqual(m3.step, .vault)
        let m4 = model(location: .elsewhere)
        m4.connectionChanged(ready1)
        XCTAssertEqual(m4.step, .welcome, "not in Applications: the move comes first")
    }

    func testTheModelPositionsItselfOnlyOnce() {
        let m = model()
        m.connectionChanged(.notInitialized)
        XCTAssertEqual(m.step, .vault)
        m.back()
        m.connectionChanged(ready1)
        XCTAssertEqual(m.step, .service, "later polls do not move the person around")
    }

    func testAnExplicitJumpIsNotUndoneByTheFirstStatus() {
        let m = model()
        m.go(to: .vault)
        m.connectionChanged(ready1)
        XCTAssertEqual(m.step, .vault)
    }

    func testDoneConditions() {
        let m = model()
        m.connectionChanged(.locked(lastError: nil))
        XCTAssertTrue(m.isDone(.service))
        XCTAssertTrue(m.isDone(.vault), "a locked vault exists")
        XCTAssertFalse(m.isDone(.firstSecret))
        m.connectionChanged(ready1)
        XCTAssertTrue(m.isDone(.firstSecret))
        XCTAssertFalse(m.isDone(.connect))
    }

    func testNavigationAndSkip() {
        let m = model()
        m.connectionChanged(.notRunning)
        XCTAssertFalse(m.canGoBack)
        XCTAssertTrue(m.canContinue)
        m.next()
        XCTAssertEqual(m.step, .service)
        XCTAssertFalse(m.canContinue, "the service is not answering yet")
        XCTAssertTrue(m.canGoBack)
        m.connectionChanged(.notInitialized)
        XCTAssertTrue(m.canContinue)
        m.next()
        XCTAssertEqual(m.step, .vault)
        XCTAssertFalse(m.canContinue)
        m.connectionChanged(ready0)
        m.next()
        XCTAssertEqual(m.step, .firstSecret)
        XCTAssertFalse(m.canContinue)
        XCTAssertTrue(m.canSkip)
        m.skip()
        XCTAssertEqual(m.step, .connect)
        XCTAssertFalse(m.canContinue, "Connect ends with Done")
        m.back()
        XCTAssertEqual(m.step, .firstSecret)
    }

    func testWelcomeIsHeldBackOutsideApplications() {
        let m = model(location: .elsewhere)
        m.connectionChanged(.notRunning)
        XCTAssertFalse(m.canContinue)
        XCTAssertEqual(m.actionsDisabledReason, "Move grantd to your Applications folder first")
        m.location = .ok
        XCTAssertTrue(m.canContinue)
    }

    func testInstallServiceRunsOnlyOnItsStep() async {
        let c = FakeServiceControl()
        let m = model(control: c)
        m.connectionChanged(.notRunning)
        await m.installService()
        XCTAssertEqual(c.installs.count, 0, "not on the service step")
        m.go(to: .service)
        await m.installService()
        XCTAssertEqual(c.installs.count, 1)
        XCTAssertEqual(m.lastResult?.outcome, .succeeded)
        XCTAssertNil(m.running)
    }

    func testCreateVault() async {
        let c = FakeServiceControl()
        var polled = 0
        let m = OnboardingModel(control: c, loginItem: nil, isDevelopment: false, onActionFinished: { polled += 1 })
        m.connectionChanged(.notInitialized)
        await m.createVault()
        XCTAssertEqual(c.inits, [false])
        XCTAssertFalse(m.offersWeakerProtection)
        XCTAssertEqual(m.lastResult?.summary, "Vault created. Its key is in the Secure Enclave.")
        XCTAssertEqual(polled, 1)
        m.connectionChanged(ready0)
        XCTAssertEqual(m.vaultProtectionLine, "Protection: Secure Enclave")
        m.connectionChanged(.ready(StatusResult(keystoreTier: .dialog)))
        XCTAssertEqual(m.vaultProtectionLine, "Protection: Keychain only (weaker)")
    }

    func testSecureEnclaveFailureOffersTheWeakerRetry() async {
        let c = FakeServiceControl()
        var fail = ActionResult(outcome: .failed, summary: "The vault could not be created.", detail: "Secure Enclave unavailable")
        fail.secureEnclaveUnavailable = true
        c.initResults = [fail, ActionResult(outcome: .succeeded, summary: "Vault created. Its key is protected by the Keychain only.")]
        let m = model(control: c)
        m.connectionChanged(.notInitialized)
        await m.createVault()
        XCTAssertTrue(m.offersWeakerProtection)
        XCTAssertEqual(OnboardingModel.noHardwareText, "This Mac can't create a hardware key (for example inside a virtual machine).")
        XCTAssertEqual(OnboardingModel.weakerConfirmation.title, "Use weaker protection?")
        XCTAssertEqual(OnboardingModel.weakerConfirmation.message, "The vault key will be kept in your Keychain instead of the Secure Enclave. Programs running as you could read it. Touch ID still protects every use of a secret.")
        XCTAssertEqual(OnboardingModel.weakerConfirmation.confirmLabel, "Use Keychain")
        await m.createVaultWithWeakerProtection()
        XCTAssertEqual(c.inits, [false, true], "init --keychain-fallback only after the first attempt failed")
        XCTAssertFalse(m.offersWeakerProtection)
        XCTAssertEqual(m.lastResult?.outcome, .succeeded)
    }

    func testTheWeakerRetryIsNotAvailableWithoutAFailure() async {
        let c = FakeServiceControl()
        let m = model(control: c)
        await m.createVaultWithWeakerProtection()
        XCTAssertTrue(c.inits.isEmpty)
    }

    func testOtherFailuresDoNotOfferTheWeakerRetry() async {
        let c = FakeServiceControl()
        c.initResults = [ActionResult(outcome: .failed, summary: "The vault could not be created.", detail: "vault already exists")]
        let m = model(control: c)
        await m.createVault()
        XCTAssertFalse(m.offersWeakerProtection)
        XCTAssertEqual(m.lastResult?.detail, "vault already exists")
    }

    func testDevelopmentModeAndNoHelperRunNothing() async {
        let c = FakeServiceControl()
        let dev = model(control: c, dev: true)
        dev.go(to: .service)
        await dev.installService()
        await dev.createVault()
        XCTAssertEqual(c.installs.count + c.inits.count, 0)
        XCTAssertTrue(dev.isDone(.welcome), "development builds are not asked to move")
        let none = model(control: nil)
        await none.createVault()
        XCTAssertNotNil(none.actionsDisabledReason)
    }

    func testFinishRegistersTheLoginItemByDefault() {
        let l = FakeLoginItem()
        var done = 0
        let m = model(login: l, finished: { done += 1 })
        XCTAssertTrue(m.startAtLogin, "on by default")
        m.finish()
        XCTAssertEqual(l.registered, 1)
        XCTAssertEqual(done, 1)
        XCTAssertTrue(m.finished)
        XCTAssertTrue(m.isDone(.connect))
    }

    func testFinishRespectsTheToggleAndExistingRegistration() {
        let l = FakeLoginItem()
        let m = model(login: l)
        m.startAtLogin = false
        m.finish()
        XCTAssertEqual(l.registered, 0)
        let l2 = FakeLoginItem()
        l2.status = .enabled
        model(login: l2).finish()
        XCTAssertEqual(l2.registered, 0, "already registered")
        let l3 = FakeLoginItem()
        model(login: l3, dev: true).finish()
        XCTAssertEqual(l3.registered, 0, "development mode never touches the login item")
    }

    func testLoginFailureIsReportedButOnboardingStillEnds() {
        struct Boom: Error {}
        let l = FakeLoginItem()
        l.registerFailure = Boom()
        let m = model(login: l)
        m.finish()
        XCTAssertEqual(m.loginError, "grantd could not be added to the login items.")
        XCTAssertTrue(m.finished)
    }

    func testTheWelcomeTexts() {
        XCTAssertEqual(OnboardingModel.welcomeLines, [
            "Agents like Claude Code can use your passwords and API keys without ever seeing them.",
            "Each time one asks, you see the exact command and approve with Touch ID.",
            "Your secrets stay on this Mac, encrypted.",
        ])
        XCTAssertEqual(OnboardingStep.allCases.map(\.title), ["Welcome", "Background service", "Vault", "First secret", "Connect Claude Code"])
    }
}
