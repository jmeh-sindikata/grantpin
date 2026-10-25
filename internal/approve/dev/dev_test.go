//go:build grantd_dev

package dev

import (
	"context"
	"errors"
	"testing"
	"time"

	"grantd/internal/approve"
	"grantd/internal/presence"
)

func TestSatisfiesApprover(t *testing.T) {
	var ap approve.Approver = New(true)
	if ap.Tier() != presence.TierNone {
		t.Fatalf("tier = %v", ap.Tier())
	}
	d, err := ap.Ask(context.Background(), approve.ApprovalRequest{Caller: "c"})
	if err != nil || !d.Allow || d.TTL != 0 {
		t.Fatalf("decision = %+v, %v", d, err)
	}
}

func TestRecordsAndDecides(t *testing.T) {
	a := New(false)
	req := approve.ApprovalRequest{
		Caller: "claude-code", Cwd: "/w", Argv: []string{"php", "artisan"},
		Secrets: []string{"A", "b/*"}, PolicyPresent: true, SuggestedTTL: time.Hour,
	}
	d, err := a.Ask(context.Background(), req)
	if err != nil || d.Allow || d.Reason == "" {
		t.Fatalf("deny decision = %+v, %v", d, err)
	}
	req.Argv[0] = "mutated" // recorded copy must be independent
	a.SetAllow(true)
	a.TTL = time.Hour
	d, _ = a.Ask(context.Background(), approve.ApprovalRequest{Caller: "x"})
	if !d.Allow || d.TTL != time.Hour {
		t.Fatalf("allow decision = %+v", d)
	}
	seen := a.Requests()
	if len(seen) != 2 || seen[0].Argv[0] != "php" || seen[0].Caller != "claude-code" || !seen[0].PolicyPresent {
		t.Fatalf("seen = %+v", seen)
	}
	a.Reset()
	if len(a.Requests()) != 0 {
		t.Fatal("Reset did not clear")
	}
}

func TestErrAndCancelledContext(t *testing.T) {
	boom := errors.New("boom")
	a := &Approver{Allow: true, Err: boom}
	if _, err := a.Ask(context.Background(), approve.ApprovalRequest{}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := New(true)
	if d, err := b.Ask(ctx, approve.ApprovalRequest{}); err == nil || d.Allow {
		t.Fatalf("cancelled ctx must not allow: %+v, %v", d, err)
	}
	if len(b.Requests()) != 0 {
		t.Fatal("cancelled ask should not record")
	}
}

func TestOpenAndEnabled(t *testing.T) {
	if !Enabled {
		t.Fatal("Enabled must be true")
	}
	a, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	d, _ := a.Ask(context.Background(), approve.ApprovalRequest{})
	if d.Allow {
		t.Fatal("Open() default must deny")
	}
}
