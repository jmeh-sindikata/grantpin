package approve

import (
	"context"
	"time"

	"grantd/internal/presence"
)

// Approver asks the human whether a secret release may proceed.
//
// Implementations MUST be impossible to satisfy from the agent's shell: no
// stdin prompt, no env var or file the agent could write, no socket the agent
// could answer on. Platform backends: darwin (LocalAuthentication, TierHardware)
// now; windows (Hello) and linux (dialog) slot in later as sibling subpackages.
type Approver interface {
	// Ask blocks until the human decides or ctx is done. A cancelled or timed
	// out ctx must yield an error (and never an implicit Allow).
	Ask(ctx context.Context, req ApprovalRequest) (Decision, error)
	// Tier reports the presence strength this approver provides.
	Tier() presence.PresenceTier
}

// ApprovalRequest is everything the prompt shows the human. The daemon fills it
// from the (untrusted) request after policy has already been applied.
type ApprovalRequest struct {
	// Caller is the informational caller label (e.g. "claude-code"). Untrusted.
	Caller string
	// Cwd is the absolute working directory of the requested command.
	Cwd string
	// Argv is the exact command that will run.
	Argv []string
	// Secrets are the secrets as requested, names or globs exactly as the
	// caller sent them. A grant created from this request is scoped to this
	// list, so it must stay textual.
	Secrets []string
	// Expanded are the concrete secret names Secrets resolves to (globs
	// expanded, sorted, de-duplicated). It equals Secrets when no entry is a
	// glob. Approvers should show both when they differ, so the human sees
	// which secrets "aws/*" really covers.
	Expanded []string
	// PolicyPresent is false when no .grantd.yml was found; the prompt must then
	// say "no policy".
	PolicyPresent bool
	// SuggestedTTL is the default duration offered for "Allow for N" (1h by
	// default, already capped by policy max_grant_ttl).
	SuggestedTTL time.Duration
}

// Decision is the human's answer.
//
// If Allow is true and TTL is zero, the release is allow-once: no grant is
// stored.
//
// If Allow is true and TTL > 0 ("Allow for N"), the daemon creates a grant
// scoped to EXACTLY (caller, cwd, secret set, argv prefix) of the request that
// was shown. Approvers must not widen scope, and the daemon must not derive a
// broader grant than the request displayed.
//
// If Allow is false, Reason explains the denial (e.g. "user denied"); it is
// recorded in the audit log and surfaced to the caller as reason user_denied.
type Decision struct {
	Allow  bool
	TTL    time.Duration
	Reason string
}
