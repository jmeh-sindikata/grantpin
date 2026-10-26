package approve

import (
	"context"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/presence"
)

// Approver asks the human whether a secret release may proceed.
//
// Implementations MUST be impossible to satisfy from the agent's shell: no
// stdin prompt, no env var or file the agent could write, no socket the agent
// could answer on. Platform backends: darwin (LocalAuthentication, TierHardware)
// now; windows (Hello) and linux (dialog) slot in later as sibling subpackages.
type Approver interface {
	// Ask blocks until the human decides or ctx is done. A cancelled or timed
	// out ctx must yield an error (and never an implicit Allow). The daemon
	// (the broker) serialises calls: at most one Ask is in flight at a time, so
	// implementations need no locking or queue of their own.
	Ask(ctx context.Context, req ApprovalRequest) (Decision, error)
	// Tier reports the presence strength this approver provides.
	Tier() presence.PresenceTier
}

// Kind says what the human is being asked, which decides the prompt's wording,
// its buttons and whether a duration can be offered at all.
type Kind int

const (
	// KindRelease is a run: release secrets to a command. This is the zero
	// value, so a request that sets no Kind behaves as it always did: the
	// prompt offers Allow once and, when SuggestedTTL > 0, "Allow for N".
	KindRelease Kind = iota
	// KindShow reveals one secret value in the human's terminal. The prompt
	// offers Reveal once and never a duration; any TTL in the answer is ignored.
	KindShow
	// KindStandingGrant asks the human to create a long-lived grant the human
	// themselves requested (`grantpin grants add`). The prompt says "standing
	// grant" and states RequestedTTL; the only way to allow is the single
	// button that creates exactly that grant.
	KindStandingGrant
	// KindLowerTier asks the human to lower a secret's minimum protection
	// level (`update` with a min_tier below the stored one), for example from
	// hardware to dialog. FromTier and ToTier say what changes and
	// Secrets/Expanded name the secret. The prompt is "Lower the protection of
	// X from hardware to dialog?" with the buttons Cancel and Lower; there is
	// no duration. Raising a level never asks.
	KindLowerTier
)

// String names the kind for logs and test failures.
func (k Kind) String() string {
	switch k {
	case KindRelease:
		return "release"
	case KindShow:
		return "show"
	case KindStandingGrant:
		return "standing_grant"
	case KindLowerTier:
		return "lower_tier"
	}
	return "unknown"
}

// ApprovalRequest is everything the prompt shows the human. The daemon fills it
// from the (untrusted) request after policy has already been applied.
type ApprovalRequest struct {
	// Kind selects the prompt (see Kind). The zero value is KindRelease.
	Kind Kind
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
	// PolicyPresent is false when no .grantpin.yml was found; the prompt must then
	// say "no policy".
	PolicyPresent bool
	// GrantCmdPrefix and GrantCwdPrefix are exactly what an "Allow for N"
	// answer will store: the grant covers any later request from the same
	// caller whose argv starts with GrantCmdPrefix, whose cwd is
	// GrantCwdPrefix or below it, and that asks only for secrets covered by
	// Secrets. Approvers that offer "Allow for N" must show this scope. Both
	// are empty when no grant can result (e.g. show).
	GrantCmdPrefix []string
	GrantCwdPrefix string
	// SuggestedTTL is the default duration offered for "Allow for N" (1h by
	// default when no policy applies; with a policy, its max_grant_ttl capped
	// at 24h). Only KindRelease offers it; other kinds leave it zero.
	SuggestedTTL time.Duration
	// RequestedTTL is, for KindStandingGrant, the lifetime of the grant the
	// human asked for. The prompt must state it. It is zero for other kinds.
	RequestedTTL time.Duration
	// RequestedUses is, for KindStandingGrant, the use limit of that grant
	// (0 = unlimited within RequestedTTL). The prompt must state it when set.
	RequestedUses int
	// FromTier and ToTier are, for KindLowerTier, the secret's current minimum
	// protection level and the lower one it would get (ToTier < FromTier). The
	// prompt must state both. They are zero for other kinds.
	FromTier presence.PresenceTier
	ToTier   presence.PresenceTier
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
// For KindStandingGrant an allow must carry TTL == RequestedTTL; the daemon
// treats any other answer as a denial. For KindShow and KindLowerTier the TTL is
// ignored.
//
// If Allow is false, Reason explains the denial (e.g. "user denied"); it is
// recorded in the audit log and surfaced to the caller as reason user_denied.
type Decision struct {
	Allow  bool
	TTL    time.Duration
	Reason string
}
