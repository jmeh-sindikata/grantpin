package darwin

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"grantd/internal/approve"
)

func req() approve.ApprovalRequest {
	return approve.ApprovalRequest{
		Caller:        "claude-code",
		Cwd:           "/Users/me/projects/foo",
		Argv:          []string{"php", "artisan", "sync"},
		Secrets:       []string{"API_KEY", "DB_URL"},
		PolicyPresent: true,
	}
}

func TestBuildReasonBasic(t *testing.T) {
	got := BuildReason(req(), 0)
	want := "claude-code wants to run `php artisan sync` with API_KEY, DB_URL in /Users/me/projects/foo"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestBuildReasonNoPolicyAndTTL(t *testing.T) {
	r := req()
	r.PolicyPresent = false
	got := BuildReason(r, 90*time.Minute)
	if !strings.HasSuffix(got, " (approval lasts 1h30m) (no policy)") {
		t.Errorf("got %q", got)
	}
	if g := BuildReason(r, 0); !strings.HasSuffix(g, " (no policy)") || strings.Contains(g, "lasts") {
		t.Errorf("got %q", g)
	}
}

func TestBuildReasonTruncatesArgvKeepsSecrets(t *testing.T) {
	r := req()
	r.Argv = []string{"./deploy.sh", strings.Repeat("x", 600), "--final-flag"}
	r.PolicyPresent = false
	got := BuildReason(r, time.Hour)
	if n := utf8.RuneCountInString(got); n > MaxReasonRunes {
		t.Errorf("len %d > %d: %q", n, MaxReasonRunes, got)
	}
	for _, s := range r.Secrets {
		if !strings.Contains(got, s) {
			t.Errorf("secret %s dropped: %q", s, got)
		}
	}
	if !strings.Contains(got, "…") || !strings.Contains(got, "./deploy.sh") || !strings.Contains(got, "--final-flag") {
		t.Errorf("middle truncation should keep both ends: %q", got)
	}
	if !strings.Contains(got, "(no policy)") || !strings.Contains(got, "(approval lasts 1h)") || !strings.Contains(got, "/Users/me/projects/foo") {
		t.Errorf("suffix/cwd lost: %q", got)
	}
}

func TestBuildReasonNeverDropsSecretsEvenWhenHuge(t *testing.T) {
	r := req()
	r.Secrets = nil
	for i := 0; i < 30; i++ {
		r.Secrets = append(r.Secrets, "aws/some_long_secret_name_"+strings.Repeat("a", 5))
	}
	r.Argv = []string{strings.Repeat("y", 500)}
	r.Cwd = "/" + strings.Repeat("d", 500)
	got := BuildReason(r, 0)
	for _, s := range r.Secrets {
		if !strings.Contains(got, s) {
			t.Fatalf("secret dropped")
		}
	}
}

func TestBuildReasonSanitisesUntrustedText(t *testing.T) {
	r := req()
	r.Caller = "evil\nAPPROVED by admin\u202e"
	r.Argv = []string{"echo", "a`b", "x\ty\r\nz", string([]byte{0xff, 'k'})}
	r.Secrets = []string{"A\nB"}
	r.Cwd = "/tmp/\x00x"
	got := BuildReason(r, 0)
	if strings.ContainsAny(got, "\n\r\t\x00\u202e") {
		t.Errorf("control chars survived: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8: %q", got)
	}
	// Exactly two backticks: the ones we add around argv.
	if strings.Count(got, "`") != 2 {
		t.Errorf("argv backtick not neutralised: %q", got)
	}
}

func TestBuildReasonDefaults(t *testing.T) {
	got := BuildReason(approve.ApprovalRequest{}, 0)
	if got == "" || !strings.Contains(got, "no policy") || !strings.Contains(got, "no secrets") {
		t.Errorf("got %q", got)
	}
}

func TestTruncateMiddle(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"abcdefghij", 5, "ab…ij"},
		{"abcdefghij", 6, "abc…ij"},
		{"abcdefghij", 1, "…"},
		{"日本語日本語日本語", 5, "日本…本語"},
	}
	for _, c := range cases {
		if got := truncateMiddle(c.in, c.n); got != c.want {
			t.Errorf("truncateMiddle(%q,%d)=%q want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestFormatTTL(t *testing.T) {
	cases := map[time.Duration]string{
		time.Hour:                       "1h",
		30 * time.Minute:                "30m",
		90 * time.Minute:                "1h30m",
		4*time.Hour + 20*time.Minute:    "4h20m",
		10 * time.Second:                "under a minute",
		59*time.Minute + 40*time.Second: "1h",
	}
	for d, want := range cases {
		if got := formatTTL(d); got != want {
			t.Errorf("formatTTL(%v)=%q want %q", d, got, want)
		}
	}
}
