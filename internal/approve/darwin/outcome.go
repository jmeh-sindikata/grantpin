package darwin

import (
	"errors"
	"fmt"
	"time"
)

// Option configures New.
type Option func(*config)

type config struct {
	defaultTTL time.Duration
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
	var c config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

// ttlFor returns the grant TTL to disclose and return for req.
func (c config) ttlFor(suggested time.Duration) time.Duration {
	ttl := c.defaultTTL
	if ttl > 0 && suggested > 0 && suggested < ttl {
		ttl = suggested
	}
	return ttl
}

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
