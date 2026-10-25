//go:build darwin && cgo

package darwin

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"grantd/internal/approve"
	"grantd/internal/presence"
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

// TestManualPromptsOnce shows ONE real Touch ID / password prompt.
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
	a, _ := New()
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
