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
// LocalAuthentication only reports success or failure, so v0.1 is allow-once
// only: success yields Decision{Allow: true, TTL: 0}; cancel, failed
// authentication, or "Deny" yield Decision{Allow: false}. The daemon may opt in
// to "Allow for N" semantics with WithDefaultTTL; when it does, the prompt text
// states the duration so the human knows what they are approving, and the TTL is
// capped by ApprovalRequest.SuggestedTTL. A native three-button (Allow once /
// Allow for N / Deny) chooser would need an AppKit NSAlert on the main thread of
// a process running NSApplication; a Go daemon does not own the main thread
// safely, so this is deliberately NOT implemented (see docs/MANUAL-TEST-MACOS.md
// and the step-7 report).
//
// # Prompt text
//
// The reason string is built from the untrusted request: control characters are
// replaced, backticks in argv are neutralised, and long argv is truncated in the
// middle with an ellipsis. Secret names are never dropped.
package darwin
