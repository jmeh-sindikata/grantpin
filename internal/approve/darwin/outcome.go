package darwin

import (
	"errors"
	"fmt"
	"time"

	"grantd/internal/approve"
)

// Option configures New.
type Option func(*config)

type config struct {
	defaultTTL time.Duration
	chooser    bool
}

// WithChooser enables (default) or disables the three-way Allow once / Allow
// for N / Deny dialog shown via /usr/bin/osascript before the
// LocalAuthentication prompt. false falls back to LA-only: allow-once, or the
// WithDefaultTTL duration.
func WithChooser(on bool) Option {
	return func(c *config) { c.chooser = on }
}

// WithDefaultTTL makes a successful authentication an "Allow for N" decision
// (Decision.TTL = d, capped by ApprovalRequest.SuggestedTTL when that is set)
// instead of allow-once, and discloses the duration in the prompt. d <= 0
// keeps allow-once, the default.
func WithDefaultTTL(d time.Duration) Option {
	return func(c *config) {
		if d < 0 {
			d = 0
		}
		c.defaultTTL = d
	}
}

func newConfig(opts []Option) config {
	c := config{chooser: true}
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

// ttlFor returns the grant TTL to disclose and return for a release when no
// chooser dialog is shown.
func (c config) ttlFor(suggested time.Duration) time.Duration {
	ttl := c.defaultTTL
	if ttl > 0 && suggested > 0 && suggested < ttl {
		ttl = suggested
	}
	return ttl
}

// ttlNoChooser is the TTL an authentication success grants when the chooser
// is off. A standing grant is exactly the requested duration (the Touch ID
// reason states it); a show never has one; only a release uses the default.
func (c config) ttlNoChooser(req approve.ApprovalRequest) time.Duration {
	switch req.Kind {
	case approve.KindStandingGrant:
		return req.RequestedTTL
	case approve.KindShow:
		return 0
	}
	return c.ttlFor(req.SuggestedTTL)
}

// ttlForChoice maps the dialog answer to what authentication success grants.
// allow is false for a deny. A standing grant is always exactly RequestedTTL,
// a show never carries a TTL, and only a release can answer "Allow for N".
func ttlForChoice(req approve.ApprovalRequest, ch choice, offered time.Duration) (ttl time.Duration, allow bool) {
	switch ch {
	case choiceOnce:
		if req.Kind == approve.KindStandingGrant {
			return req.RequestedTTL, true
		}
		return 0, true
	case choiceFor:
		if req.Kind == approve.KindRelease && offered > 0 {
			return offered, true
		}
	}
	return 0, false
}

// cancelTitleFor is the label of the cancel button on the system prompt.
func cancelTitleFor(kind approve.Kind) string { return safeButton(kind) }

// Typed errors. None of them is ever turned into an allow by callers.
var (
	// ErrUnavailable: authentication cannot be performed at all (no device
	// passcode set, non-interactive context, ...). Use errors.As to get the
	// *LAError with the code.
	ErrUnavailable = errors.New("darwin approver: device-owner authentication unavailable")
	// ErrNoGUISession: there is no window-server login session to show the
	// prompt in (e.g. the daemon was started over SSH).
	ErrNoGUISession = errors.New("darwin approver: no interactive GUI session; cannot prompt")
	// ErrInterrupted: the system cancelled the prompt (screen locked, another
	// app took over, ...). No human decision was made.
	ErrInterrupted = errors.New("darwin approver: prompt interrupted by the system")
)

// LAError is a LocalAuthentication failure (LAErrorDomain).
type LAError struct {
	Code int
	Msg  string
	kind error
}

func (e *LAError) Error() string {
	return fmt.Sprintf("%v: %s (LAError %d)", e.kind, e.Msg, e.Code)
}

func (e *LAError) Unwrap() error { return e.kind }

// LAError codes from LocalAuthentication/LAPublicDefines.h.
const (
	laAuthenticationFailed = -1
	laUserCancel           = -2
	laUserFallback         = -3
	laSystemCancel         = -4
	laAppCancel            = -9
	laInvalidContext       = -10
	laNotInteractive       = -1004
)

type verdict int

const (
	verdictDeny        verdict = iota // a human decision (or auth failure): Decision{Allow:false}
	verdictInterrupted                // system cancel: error, not a decision
	verdictCancelled                  // we invalidated the context (ctx done)
	verdictUnavailable                // cannot authenticate: error
)

// classifyFailure maps a failed evaluatePolicy LAError code to what Ask does.
// Anything unknown is treated as a deny-with-reason: failing closed.
func classifyFailure(code int) (verdict, string) {
	switch code {
	case laUserCancel:
		return verdictDeny, "user denied"
	case laUserFallback:
		return verdictDeny, "user declined authentication"
	case laAuthenticationFailed:
		return verdictDeny, "authentication failed"
	case laSystemCancel:
		return verdictInterrupted, "prompt interrupted by the system"
	case laAppCancel, laInvalidContext:
		return verdictCancelled, "prompt cancelled"
	case laNotInteractive:
		return verdictUnavailable, "interaction not allowed"
	}
	return verdictDeny, fmt.Sprintf("authentication failed (LAError %d)", code)
}
