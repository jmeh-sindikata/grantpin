//go:build darwin && cgo

package darwin

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/presence"
)

// LA result codes mirrored from la_darwin.h (cgo cannot be used in _test files).
const (
	rcOK, rcFailed, rcUnavailable, rcBadInput, rcForeign = 0, 1, 2, 3, 4
)

func TestTierAndConstructor(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if a.Tier() != presence.TierHardware {
		t.Errorf("tier %v", a.Tier())
	}
}

func TestAskCancelledContextNeverPrompts(t *testing.T) {
	a, _ := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := a.Ask(ctx, approve.ApprovalRequest{Caller: "x"})
	if !errors.Is(err, context.Canceled) || d.Allow {
		t.Errorf("got %+v, %v", d, err)
	}
}

func TestDecideOnlyOKAllows(t *testing.T) {
	a := &Approver{cfg: newConfig(nil)}
	d, err := a.decide(laResult{rc: rcOK}, 0)
	if err != nil || !d.Allow || d.TTL != 0 {
		t.Errorf("ok: %+v %v", d, err)
	}
	d, err = a.decide(laResult{rc: rcOK}, time.Hour)
	if err != nil || !d.Allow || d.TTL != time.Hour {
		t.Errorf("ok+ttl: %+v %v", d, err)
	}

	cases := []struct {
		res     laResult
		wantErr error // nil => a Deny decision
	}{
		{laResult{rc: rcFailed, code: laUserCancel}, nil},
		{laResult{rc: rcFailed, code: laAuthenticationFailed}, nil},
		{laResult{rc: rcFailed, code: laSystemCancel}, ErrInterrupted},
		{laResult{rc: rcFailed, code: laNotInteractive}, ErrUnavailable},
		{laResult{rc: rcUnavailable, code: -5}, ErrUnavailable},
		{laResult{rc: rcBadInput}, ErrUnavailable},
		{laResult{rc: rcForeign, code: 7}, ErrUnavailable},
		{laResult{rc: 99}, ErrUnavailable},
	}
	for _, c := range cases {
		d, err := a.decide(c.res, time.Hour)
		if d.Allow {
			t.Errorf("%+v: allowed!", c.res)
		}
		if c.wantErr == nil {
			if err != nil || d.Reason == "" {
				t.Errorf("%+v: want deny decision, got %+v %v", c.res, d, err)
			}
		} else if !errors.Is(err, c.wantErr) {
			t.Errorf("%+v: err %v, want %v", c.res, err, c.wantErr)
		}
	}
}

// TestManualPromptsOnce runs the full chain: the osascript chooser, then (for
// either Allow button) one Touch ID / password prompt.
// Skipped unless GRANTD_MANUAL_TEST=1. See docs/MANUAL-TEST-MACOS.md.
func TestManualPromptsOnce(t *testing.T) {
	if os.Getenv("GRANTD_MANUAL_TEST") != "1" {
		t.Skip("set GRANTD_MANUAL_TEST=1 to run (shows a Touch ID / password prompt)")
	}
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d, err := a.Ask(ctx, approve.ApprovalRequest{
		Caller:        "grantd-manual-test",
		Cwd:           "/tmp/grantd-manual-test",
		Argv:          []string{"echo", "hello"},
		Secrets:       []string{"MANUAL_TEST_SECRET"},
		PolicyPresent: false,
		SuggestedTTL:  time.Hour,
	})
	t.Logf("decision=%+v err=%v", d, err)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if os.Getenv("GRANTD_MANUAL_EXPECT") == "deny" && d.Allow {
		t.Fatal("expected deny, got allow")
	}
	if os.Getenv("GRANTD_MANUAL_EXPECT") == "allow" && !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
}

// TestManualCancelViaContext shows one prompt and cancels it from Go after 3s;
// the prompt must disappear and Ask must return context.DeadlineExceeded.
func TestManualCancelViaContext(t *testing.T) {
	if os.Getenv("GRANTD_MANUAL_TEST") != "1" {
		t.Skip("set GRANTD_MANUAL_TEST=1 to run (shows a Touch ID / password prompt)")
	}
	a, _ := New(WithChooser(false))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	d, err := a.Ask(ctx, approve.ApprovalRequest{Caller: "grantd-manual-test", Cwd: "/tmp", Argv: []string{"true"}, Secrets: []string{"X"}})
	if d.Allow {
		t.Fatal("allowed after cancel")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	t.Logf("returned after %v", time.Since(start))
}

func TestChooserDefaultsAndOptOut(t *testing.T) {
	a, _ := New()
	if a.(*Approver).choose == nil {
		t.Error("chooser should be on by default")
	}
	b, _ := New(WithChooser(false))
	if b.(*Approver).choose != nil {
		t.Error("WithChooser(false) must disable it")
	}
}

// Deny from the chooser must short-circuit before LocalAuthentication, so this
// never shows an LA prompt (and the fake means no dialog either).
func TestAskChooserDenyShortCircuits(t *testing.T) {
	f := &fakeExec{stdout: "button returned:Deny, gave up:false\n"}
	a := &Approver{cfg: newConfig(nil), choose: newFake(f)}
	d, err := a.Ask(context.Background(), req())
	if errors.Is(err, ErrNoGUISession) {
		t.Skip("no GUI session")
	}
	if err != nil || d.Allow || d.Reason != "user denied" || f.calls != 1 {
		t.Fatalf("got %+v %v calls=%d", d, err, f.calls)
	}
}

// The standing-grant paths below only exercise answers that deny BEFORE
// LocalAuthentication; an allow answer would reach the Touch ID prompt, so no
// test feeds one to Ask.
func TestAskStandingGrantDeniedWithoutAPositiveAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		mut    func(*approve.ApprovalRequest)
		calls  int
	}{
		{"cancel", "button returned:Cancel, gave up:false\n", nil, 1},
		{"gave up", "button returned:Create standing grant, gave up:true\n", nil, 1},
		{"a release button does not answer it", "button returned:Allow once, gave up:false\n", nil, 1},
		{"no duration is never asked", "button returned:Create standing grant, gave up:false\n", func(r *approve.ApprovalRequest) { r.RequestedTTL = 0 }, 0},
	} {
		f := &fakeExec{stdout: tc.stdout}
		a := &Approver{cfg: newConfig(nil), choose: newFake(f)}
		r := standingReq()
		if tc.mut != nil {
			tc.mut(&r)
		}
		d, err := a.Ask(context.Background(), r)
		if errors.Is(err, ErrNoGUISession) {
			t.Skip("no GUI session")
		}
		if err != nil || d.Allow || f.calls != tc.calls {
			t.Errorf("%s: got %+v %v calls=%d", tc.name, d, err, f.calls)
		}
	}
}

func TestAskShowDeniedByDeny(t *testing.T) {
	f := &fakeExec{stdout: "button returned:Allow once, gave up:false\n"} // not the Show button
	a := &Approver{cfg: newConfig(nil), choose: newFake(f)}
	r := req()
	r.Kind = approve.KindShow
	d, err := a.Ask(context.Background(), r)
	if errors.Is(err, ErrNoGUISession) {
		t.Skip("no GUI session")
	}
	if err != nil || d.Allow {
		t.Fatalf("got %+v %v", d, err)
	}
}

func TestAskChooserFailureIsNotAllow(t *testing.T) {
	f := &fakeExec{code: 1, stderr: "boom"}
	a := &Approver{cfg: newConfig(nil), choose: newFake(f)}
	d, err := a.Ask(context.Background(), req())
	if errors.Is(err, ErrNoGUISession) {
		t.Skip("no GUI session")
	}
	if d.Allow || !errors.Is(err, ErrChooserFailed) {
		t.Fatalf("got %+v %v", d, err)
	}
}

// TestManualChooserOnly shows ONLY the osascript dialog (no Touch ID).
func TestManualChooserOnly(t *testing.T) {
	if os.Getenv("GRANTD_MANUAL_TEST") != "1" {
		t.Skip("set GRANTD_MANUAL_TEST=1 to run (shows an osascript dialog)")
	}
	r := approve.ApprovalRequest{Caller: "grantd-manual-test", Cwd: "/tmp/grantd-manual-test",
		Argv: []string{"echo", "hello"}, Secrets: []string{"MANUAL_TEST_SECRET"}, SuggestedTTL: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := newChooser().ask(ctx, r, time.Hour)
	t.Logf("choice=%d (0 deny, 1 once, 2 for-1h) err=%v", c, err)
	if err != nil {
		t.Fatal(err)
	}
}

// TestManualLAOnly is the original single-prompt test with the chooser off.
func TestManualLAOnly(t *testing.T) {
	if os.Getenv("GRANTD_MANUAL_TEST") != "1" {
		t.Skip("set GRANTD_MANUAL_TEST=1 to run (shows a Touch ID / password prompt)")
	}
	a, _ := New(WithChooser(false))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d, err := a.Ask(ctx, approve.ApprovalRequest{Caller: "grantd-manual-test", Cwd: "/tmp/grantd-manual-test",
		Argv: []string{"echo", "hello"}, Secrets: []string{"MANUAL_TEST_SECRET"}})
	t.Logf("decision=%+v err=%v", d, err)
	if err != nil {
		t.Fatal(err)
	}
}
