//go:build darwin && cgo

package darwin

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework CoreGraphics -framework CoreFoundation
#include <stdlib.h>
#include "la_darwin.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"grantd/internal/approve"
	"grantd/internal/presence"
)

// cancelTitle is the label of the cancel button on the system prompt.
const cancelTitle = "Deny"

// invalidateGrace bounds how long Ask waits for LocalAuthentication to unwind
// after invalidating the context on ctx cancellation.
const invalidateGrace = 5 * time.Second

// Approver is the LocalAuthentication-backed approve.Approver.
type Approver struct {
	cfg config
	// one prompt at a time; a second Ask queues (honouring its ctx).
	slot chan struct{}
}

var _ approve.Approver = (*Approver)(nil)

// New returns an Approver. It performs no authentication and shows no UI.
func New(opts ...Option) (approve.Approver, error) {
	return &Approver{cfg: newConfig(opts), slot: make(chan struct{}, 1)}, nil
}

// Tier is TierHardware (Touch ID, with account-password fallback).
func (a *Approver) Tier() presence.PresenceTier { return presence.TierHardware }

type laResult struct {
	rc   int
	code int
	msg  string
}

// Ask shows the system authentication prompt and blocks until the human
// answers or ctx is done. Only a successful authentication yields Allow.
func (a *Approver) Ask(ctx context.Context, req approve.ApprovalRequest) (approve.Decision, error) {
	if err := ctx.Err(); err != nil {
		return approve.Decision{}, err
	}
	select {
	case a.slot <- struct{}{}:
		defer func() { <-a.slot }()
	case <-ctx.Done():
		return approve.Decision{}, ctx.Err()
	}

	if C.gd_has_gui_session() == 0 {
		return approve.Decision{}, ErrNoGUISession
	}

	ttl := a.cfg.ttlFor(req.SuggestedTTL)
	reason := BuildReason(req, ttl)
	creason := C.CString(reason)
	ctitle := C.CString(cancelTitle)
	defer C.free(unsafe.Pointer(creason))
	defer C.free(unsafe.Pointer(ctitle))

	h := C.gd_la_new()
	if h == nil {
		return approve.Decision{}, fmt.Errorf("%w: cannot create LAContext", ErrUnavailable)
	}

	done := make(chan laResult, 1)
	go func() {
		var code C.int
		var msg [256]C.char
		rc := C.gd_la_evaluate(h, creason, ctitle, &code, &msg[0], C.size_t(len(msg)))
		done <- laResult{rc: int(rc), code: int(code), msg: C.GoString(&msg[0])}
	}()

	var res laResult
	select {
	case res = <-done:
	case <-ctx.Done():
		C.gd_la_invalidate(h)
		select {
		case <-done:
			C.gd_la_free(h)
		case <-time.After(invalidateGrace):
			// Evaluate is still running and holds h (and the C strings'
			// lifetime is no longer guaranteed by this frame). Leak rather
			// than free memory in use; the context is already invalidated.
			return approve.Decision{}, errors.Join(ctx.Err(), ErrInterrupted)
		}
		return approve.Decision{}, ctx.Err()
	}
	C.gd_la_free(h)

	// A decision that arrives after the caller gave up is discarded.
	if err := ctx.Err(); err != nil {
		return approve.Decision{}, err
	}
	return a.decide(res, ttl)
}

// decide turns a LocalAuthentication result into a Decision. Everything that
// is not a clean success is a deny or an error, never an allow.
func (a *Approver) decide(res laResult, ttl time.Duration) (approve.Decision, error) {
	switch res.rc {
	case C.GD_LA_OK:
		return approve.Decision{Allow: true, TTL: ttl}, nil
	case C.GD_LA_UNAVAILABLE:
		return approve.Decision{}, &LAError{Code: res.code, Msg: res.msg, kind: ErrUnavailable}
	case C.GD_LA_BAD_INPUT:
		return approve.Decision{}, fmt.Errorf("%w: invalid prompt text", ErrUnavailable)
	case C.GD_LA_FAILED:
		v, reason := classifyFailure(res.code)
		switch v {
		case verdictDeny:
			return approve.Decision{Allow: false, Reason: reason}, nil
		case verdictUnavailable:
			return approve.Decision{}, &LAError{Code: res.code, Msg: res.msg, kind: ErrUnavailable}
		default:
			return approve.Decision{}, &LAError{Code: res.code, Msg: res.msg, kind: ErrInterrupted}
		}
	}
	// GD_LA_FOREIGN or anything unexpected: an error, never an allow.
	return approve.Decision{}, &LAError{Code: res.code, Msg: res.msg, kind: ErrUnavailable}
}
