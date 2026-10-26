//go:build grantd_dev

package dev

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/presence"
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
		Secrets: []string{"A", "b/*"}, Expanded: []string{"A", "b/x"}, GrantCmdPrefix: []string{"php", "artisan"}, GrantCwdPrefix: "/w", PolicyPresent: true, SuggestedTTL: time.Hour,
	}
	d, err := a.Ask(context.Background(), req)
	if err != nil || d.Allow || d.Reason == "" {
		t.Fatalf("deny decision = %+v, %v", d, err)
	}
	req.Argv[0] = "mutated" // recorded copy must be independent
	req.Expanded[1] = "mutated"
	req.GrantCmdPrefix[0] = "mutated"
	a.SetAllow(true)
	a.TTL = time.Hour
	d, _ = a.Ask(context.Background(), approve.ApprovalRequest{Caller: "x"})
	if !d.Allow || d.TTL != time.Hour {
		t.Fatalf("allow decision = %+v", d)
	}
	seen := a.Requests()
	if len(seen) != 2 || seen[0].Argv[0] != "php" || seen[0].Caller != "claude-code" || len(seen[0].Expanded) != 2 || seen[0].Expanded[1] != "b/x" || strings.Join(seen[0].GrantCmdPrefix, " ") != "php artisan" || seen[0].GrantCwdPrefix != "/w" || !seen[0].PolicyPresent {
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

func TestKindIsRecordedAndStandingGrantsFollowDenyStanding(t *testing.T) {
	a := New(true)
	a.TTL = time.Hour
	ctx := context.Background()

	// Release: TTL applies. Show: never a TTL.
	if d, _ := a.Ask(ctx, approve.ApprovalRequest{Kind: approve.KindRelease}); !d.Allow || d.TTL != time.Hour {
		t.Errorf("release = %+v", d)
	}
	if d, _ := a.Ask(ctx, approve.ApprovalRequest{Kind: approve.KindShow}); !d.Allow || d.TTL != 0 {
		t.Errorf("show = %+v", d)
	}
	// Standing: allowed with exactly the requested TTL, whatever a.TTL says.
	st := approve.ApprovalRequest{Kind: approve.KindStandingGrant, RequestedTTL: 30 * 24 * time.Hour, RequestedUses: 2}
	if d, _ := a.Ask(ctx, st); !d.Allow || d.TTL != 30*24*time.Hour {
		t.Errorf("standing = %+v", d)
	}

	// DenyStanding denies standing requests only.
	a.SetDenyStanding(true)
	if d, _ := a.Ask(ctx, st); d.Allow || d.Reason == "" {
		t.Errorf("standing with DenyStanding = %+v", d)
	}
	if d, _ := a.Ask(ctx, approve.ApprovalRequest{Kind: approve.KindRelease}); !d.Allow {
		t.Errorf("release with DenyStanding = %+v", d)
	}
	if d, _ := a.Ask(ctx, approve.ApprovalRequest{Kind: approve.KindShow}); !d.Allow {
		t.Errorf("show with DenyStanding = %+v", d)
	}

	seen := a.Requests()
	if len(seen) != 6 || seen[0].Kind != approve.KindRelease || seen[1].Kind != approve.KindShow ||
		seen[2].Kind != approve.KindStandingGrant || seen[2].RequestedTTL != 30*24*time.Hour || seen[2].RequestedUses != 2 {
		t.Fatalf("seen = %+v", seen)
	}
}

func TestLowerTierIsRecordedAndHasNoTTL(t *testing.T) {
	a := New(true)
	a.TTL = time.Hour
	a.SetDenyStanding(true) // only standing requests are affected
	req := approve.ApprovalRequest{
		Kind: approve.KindLowerTier, Secrets: []string{"k"},
		FromTier: presence.TierHardware, ToTier: presence.TierDialog,
	}
	if d, err := a.Ask(context.Background(), req); err != nil || !d.Allow || d.TTL != 0 {
		t.Errorf("lower = %+v %v", d, err)
	}
	seen := a.Requests()
	if len(seen) != 1 || seen[0].Kind != approve.KindLowerTier || seen[0].FromTier != presence.TierHardware || seen[0].ToTier != presence.TierDialog {
		t.Fatalf("seen = %+v", seen)
	}
	if d, _ := New(false).Ask(context.Background(), req); d.Allow {
		t.Error("auto-deny dev approver allowed a lower-tier request")
	}
}
