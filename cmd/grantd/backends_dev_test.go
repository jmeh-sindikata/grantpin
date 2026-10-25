//go:build grantd_dev

package main

import (
	"context"
	"testing"

	"grantd/internal/approve"
	"grantd/internal/presence"
)

func TestDevApproverDefaultsToDeny(t *testing.T) {
	t.Setenv(devApproveEnv, "")
	ap, err := openApprover()
	if err != nil {
		t.Fatal(err)
	}
	if ap.Tier() != presence.TierNone {
		t.Errorf("tier = %v", ap.Tier())
	}
	d, err := ap.Ask(context.Background(), approve.ApprovalRequest{})
	if err != nil || d.Allow {
		t.Errorf("default decision = %+v, %v", d, err)
	}
	for _, v := range []string{"yes", "ALLOW", "1", "deny"} {
		t.Setenv(devApproveEnv, v)
		ap, _ = openApprover()
		if d, _ := ap.Ask(context.Background(), approve.ApprovalRequest{}); d.Allow {
			t.Errorf("%s=%q allowed", devApproveEnv, v)
		}
	}
	t.Setenv(devApproveEnv, "allow")
	ap, _ = openApprover()
	if d, _ := ap.Ask(context.Background(), approve.ApprovalRequest{}); !d.Allow || d.TTL != 0 {
		t.Errorf("allow decision = %+v", d)
	}
}
