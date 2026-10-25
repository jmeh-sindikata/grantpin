package darwin

import (
	"testing"
	"time"
)

func TestOptionsAndTTL(t *testing.T) {
	if got := newConfig(nil).ttlFor(time.Hour); got != 0 {
		t.Errorf("default must be allow-once, got %v", got)
	}
	c := newConfig([]Option{WithDefaultTTL(time.Hour)})
	if got := c.ttlFor(0); got != time.Hour {
		t.Errorf("got %v", got)
	}
	if got := c.ttlFor(10 * time.Minute); got != 10*time.Minute {
		t.Errorf("must cap at SuggestedTTL, got %v", got)
	}
	if got := c.ttlFor(4 * time.Hour); got != time.Hour {
		t.Errorf("got %v", got)
	}
	if got := newConfig([]Option{WithDefaultTTL(-time.Hour), nil}).defaultTTL; got != 0 {
		t.Errorf("negative TTL must clamp to 0, got %v", got)
	}
}

func TestClassifyFailure(t *testing.T) {
	cases := []struct {
		code int
		want verdict
	}{
		{laUserCancel, verdictDeny},
		{laUserFallback, verdictDeny},
		{laAuthenticationFailed, verdictDeny},
		{laSystemCancel, verdictInterrupted},
		{laAppCancel, verdictCancelled},
		{laInvalidContext, verdictCancelled},
		{laNotInteractive, verdictUnavailable},
		{12345, verdictDeny}, // unknown fails closed
	}
	for _, c := range cases {
		if got, reason := classifyFailure(c.code); got != c.want || reason == "" {
			t.Errorf("code %d: %v %q, want %v", c.code, got, reason, c.want)
		}
	}
}
