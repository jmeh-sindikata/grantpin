//go:build grantd_dev

package dev

import (
	"context"
	"sync"
	"time"

	"grantd/internal/approve"
	"grantd/internal/presence"
)

// Enabled reports whether the dev backend is compiled in. True in this build.
const Enabled = true

// Approver is a TierNone test approver. It never involves a human: it answers
// every request according to its fields and records every request it saw so
// tests can assert on them.
//
// Configure Allow/TTL/DenyReason before use; do not mutate them concurrently
// with Ask (use SetAllow for that).
type Approver struct {
	// Allow is the auto-answer: true = allow, false = deny.
	Allow bool
	// TTL is returned on allow. Zero means allow-once (no grant).
	TTL time.Duration
	// DenyReason is returned on deny. Defaults to "dev approver: auto-deny".
	DenyReason string
	// DenyStanding denies KindStandingGrant requests (and only those) while
	// everything else follows Allow. It lets tests cover both answers.
	DenyStanding bool
	// Err, if non-nil, is returned from Ask instead of a Decision (simulates a
	// prompt that failed, e.g. dialog could not be shown).
	Err error

	mu   sync.Mutex
	seen []approve.ApprovalRequest
}

var _ approve.Approver = (*Approver)(nil)

// New returns a dev approver that auto-allows (allow=true) or auto-denies, as
// allow-once. It exists only under the grantd_dev build tag, so calling it from
// a normal build fails to compile.
func New(allow bool) *Approver { return &Approver{Allow: allow} }

// Open is the build-agnostic constructor for backend selection code; under
// grantd_dev it returns an auto-DENY approver (the conservative default).
func Open() (approve.Approver, error) { return New(false), nil }

// SetAllow changes the auto-answer safely while other goroutines call Ask.
func (a *Approver) SetAllow(allow bool) {
	a.mu.Lock()
	a.Allow = allow
	a.mu.Unlock()
}

// SetDenyStanding changes DenyStanding safely while other goroutines call Ask.
func (a *Approver) SetDenyStanding(deny bool) {
	a.mu.Lock()
	a.DenyStanding = deny
	a.mu.Unlock()
}

// Ask records req (deep-copied, Kind included) and answers per configuration.
// Like the real approvers it answers a KindStandingGrant allow with
// TTL == RequestedTTL and a KindShow or KindLowerTier allow with no TTL; TTL applies to
// KindRelease only.
func (a *Approver) Ask(ctx context.Context, req approve.ApprovalRequest) (approve.Decision, error) {
	if err := ctx.Err(); err != nil {
		return approve.Decision{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := req
	cp.Argv = append([]string(nil), req.Argv...)
	cp.Secrets = append([]string(nil), req.Secrets...)
	cp.Expanded = append([]string(nil), req.Expanded...)
	cp.GrantCmdPrefix = append([]string(nil), req.GrantCmdPrefix...)
	a.seen = append(a.seen, cp)
	if a.Err != nil {
		return approve.Decision{}, a.Err
	}
	if a.Allow && !(a.DenyStanding && req.Kind == approve.KindStandingGrant) {
		switch req.Kind {
		case approve.KindStandingGrant:
			return approve.Decision{Allow: true, TTL: req.RequestedTTL}, nil
		case approve.KindShow, approve.KindLowerTier:
			return approve.Decision{Allow: true}, nil
		}
		return approve.Decision{Allow: true, TTL: a.TTL}, nil
	}
	reason := a.DenyReason
	if reason == "" {
		reason = "dev approver: auto-deny"
	}
	return approve.Decision{Allow: false, Reason: reason}, nil
}

// Tier is always TierNone.
func (a *Approver) Tier() presence.PresenceTier { return presence.TierNone }

// Requests returns a copy of every request seen so far, in order.
func (a *Approver) Requests() []approve.ApprovalRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approve.ApprovalRequest(nil), a.seen...)
}

// Reset forgets recorded requests.
func (a *Approver) Reset() {
	a.mu.Lock()
	a.seen = nil
	a.mu.Unlock()
}
