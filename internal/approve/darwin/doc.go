// Package darwin implements approve.Approver on macOS with the
// LocalAuthentication framework: an LAContext evaluating
// LAPolicyDeviceOwnerAuthentication (Touch ID, falling back to the account
// password), tier presence.TierHardware.
//
// # Why the agent's shell cannot satisfy it
//
// The decision is made solely by the return value of
// -[LAContext evaluatePolicy:localizedReason:reply:], which is answered by the
// system authentication UI (coreauthd / Touch ID sensor / password sheet). No
// environment variable, file, flag, stdin line or socket message is read by
// this package when deciding; the only inputs to Ask are the ApprovalRequest
// (displayed, never interpreted as an answer) and the options fixed at
// construction. If authentication is unavailable (no passcode set, not an
// interactive GUI session) Ask returns a typed error and NEVER allows.
//
// # Choices offered
//
// LocalAuthentication only reports success or failure, so the three-way choice
// is a separate native step. By default (WithChooser(true)) Ask first runs
// /usr/bin/osascript (absolute path, minimal environment, killed on ctx
// cancellation) with a constant AppleScript `display dialog` offering
//
//	{"Deny", "Allow once", "Allow for <SuggestedTTL>"}
//
// default and cancel button "Deny", caution icon, giving up (= Deny) after
// 120s. The dialog text and the third button label are passed as run-handler
// arguments after `--`; untrusted caller/argv/cwd text is sanitised and never
// interpolated into AppleScript source. Only the exact `button returned:` label
// with `gave up:false` counts; any other output is Deny. Deny short-circuits
// before LocalAuthentication. For either Allow button the LocalAuthentication
// prompt follows, and only chosen button AND authentication success yield
// Decision{Allow:true, TTL: 0 (once) or SuggestedTTL (Allow for N)}. With
// SuggestedTTL == 0 the third button is not offered.
//
// WithChooser(false) skips the dialog: LocalAuthentication alone, allow-once,
// or the WithDefaultTTL duration (capped by SuggestedTTL, stated in the prompt).
//
// Residual risk: the osascript dialog is ordinary UI. A process running as the
// same account that holds Accessibility permission could script it and click
// "Allow". That is exactly why LocalAuthentication always follows an Allow
// button: the sensor or password is not scriptable the same way. If the dialog
// cannot be shown (osascript fails for a reason other than the user cancelling)
// Ask returns ErrChooserFailed; it never degrades to an allow.
//
// # Prompt text
//
// The reason string is built from the untrusted request: control characters are
// replaced, backticks in argv are neutralised, and long argv is truncated in the
// middle with an ellipsis. Secret names are never dropped.
package darwin
