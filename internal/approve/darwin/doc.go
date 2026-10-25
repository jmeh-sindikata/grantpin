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
// LocalAuthentication only reports success or failure, so the choice is a
// separate native step. By default (WithChooser(true)) Ask first runs
// /usr/bin/osascript (absolute path, minimal environment, killed on ctx
// cancellation) with a constant AppleScript `display dialog`, caution icon,
// giving up (= the safe button) after 120s. The dialog depends on
// ApprovalRequest.Kind:
//
//	KindRelease        {"Deny", "Allow once", "Allow for <SuggestedTTL>"}   default and cancel: Deny
//	KindShow           {"Deny", "Reveal once"}                              default and cancel: Deny
//	KindStandingGrant  {"Cancel", "Create standing grant"}                  default and cancel: Cancel
//	KindLowerTier      {"Cancel", "Lower"}                                  default and cancel: Cancel
//
// Only a release offers "Allow for N" (and only with SuggestedTTL > 0); a show
// never offers a duration. A standing grant has one allow button and its TTL is
// not a choice: the dialog states RequestedTTL ("for the next 30 days"), and
// success yields Decision{Allow: true, TTL: RequestedTTL}. Anything else is a
// deny. The standing text is
//
//	Create a standing grant?
//
//	<caller> may run `<cmd prefix> …` with <secrets> in <cwd> and subfolders for the next 30 days, without further prompts.
//
//	Only continue if you just asked for this yourself.
//
// and the Touch ID reason repeats it ("Create standing grant for 30 days: …").
// A display dialog cannot set a font size, so the duration cannot be shown in
// large print; it is in the first sentence of the body and of the Touch ID
// reason instead (a native alert in the planned app can do better).
//
// The dialog text and the button labels are passed as run-handler arguments
// after `--`; untrusted caller/argv/cwd text is sanitised and never
// interpolated into AppleScript source. Only the exact `button returned:` label
// of the kind's allow button (or "Allow for N" for a release) with
// `gave up:false` counts; any other output, including another kind's button
// label, is a deny. A deny short-circuits before LocalAuthentication. For an
// allow button the LocalAuthentication prompt follows, and only the chosen
// button AND authentication success yield Allow.
//
// WithChooser(false) skips the dialog: LocalAuthentication alone, allow-once,
// or the WithDefaultTTL duration (capped by SuggestedTTL, stated in the prompt).
// A standing grant is then decided by Touch ID alone, whose reason states the
// grant and its duration; a show never carries a duration.
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
