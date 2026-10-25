// Package approve defines the Approver seam: the component that asks the human
// for approval at secret-release time.
//
// Platform implementations live in subpackages (darwin today; windows and linux
// slot in later without touching core). The dev subpackage is a TierNone test
// backend compiled only under the grantd_dev build tag.
//
// # Kinds of request
//
// ApprovalRequest.Kind says what is being asked, and each kind has its own
// prompt so one cannot be mistaken for another:
//
//   - KindRelease (the zero value): an agent-triggered run. Allow once, and
//     "Allow for N" when SuggestedTTL > 0 (the repo policy's max_grant_ttl
//     capped at 24 hours, or 1 hour with no policy).
//   - KindShow: reveal one value in the human's terminal. Reveal once; never a
//     duration.
//   - KindStandingGrant: a long-lived grant the human requested with
//     `grantd grants add`. A single button that creates exactly the grant
//     shown, for exactly RequestedTTL. Never offered as a choice by a release
//     prompt.
//
// # Standing grants and the socket
//
// Any process that can reach the daemon socket, an agent included, can send the
// request that produces a KindStandingGrant prompt; the daemon cannot tell who
// typed it. The defence is the prompt itself: it says "standing grant", states
// the duration, the command prefix, the secrets (globs expanded) and the
// directory, and tells the human to continue only if they ran `grants add`
// themselves; Touch ID (or the account password) follows the button. The
// caller label in it is whatever the requester claimed. A standing grant
// that the human did not ask for must be answered with Cancel.
package approve
