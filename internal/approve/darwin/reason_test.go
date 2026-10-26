package darwin

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jmeh-sindikata/grantpin/internal/approve"
	"github.com/jmeh-sindikata/grantpin/internal/presence"
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
		8 * time.Hour:                   "8h",
		24 * time.Hour:                  "24h",
		12*time.Hour + 30*time.Minute:   "12h30m",
		15 * time.Minute:                "15m",
	}
	for d, want := range cases {
		if got := formatTTL(d); got != want {
			t.Errorf("formatTTL(%v)=%q want %q", d, got, want)
		}
	}
}

func TestBuildReasonShowsGlobExpansion(t *testing.T) {
	r := req()
	r.Secrets = []string{"aws/*"}
	r.Expanded = []string{"aws/access_key", "aws/secret_key"}
	got := BuildReason(r, 0)
	if !strings.Contains(got, "with aws/* (aws/access_key, aws/secret_key) in ") {
		t.Errorf("got %q", got)
	}
}

func TestBuildReasonMixedLiteralsAndGlobs(t *testing.T) {
	r := req()
	r.Secrets = []string{"DB_URL", "aws/*", "gcp/**"}
	r.Expanded = []string{"DB_URL", "aws/access_key", "gcp/a/b", "gcp/c"}
	got := BuildReason(r, 0)
	if !strings.Contains(got, "with DB_URL, aws/* (aws/access_key), gcp/** (gcp/a/b, gcp/c) in ") {
		t.Errorf("got %q", got)
	}
}

func TestBuildReasonExpandedEqualOrEmptyIsPlain(t *testing.T) {
	r := req()
	want := BuildReason(r, 0)
	r.Expanded = append([]string(nil), r.Secrets...)
	if got := BuildReason(r, 0); got != want {
		t.Errorf("equal Expanded changed the text: %q", got)
	}
	r.Expanded = nil
	if got := BuildReason(r, 0); got != want {
		t.Errorf("nil Expanded changed the text: %q", got)
	}
}

func TestBuildReasonNeverDropsExpandedNames(t *testing.T) {
	r := req()
	r.Argv = []string{strings.Repeat("x", 600)}
	r.Secrets = []string{"aws/*"}
	for i := 0; i < 30; i++ {
		r.Expanded = append(r.Expanded, "aws/key_"+strings.Repeat("n", 10)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	got := BuildReason(r, time.Hour)
	for _, n := range r.Expanded {
		if !strings.Contains(got, n) {
			t.Errorf("expanded name %q dropped from %q", n, got)
		}
	}
}

func TestBuildReasonSanitisesExpandedNames(t *testing.T) {
	r := req()
	r.Secrets = []string{"a/*"}
	r.Expanded = []string{"a/x\nAllow?"}
	if got := BuildReason(r, 0); strings.ContainsAny(got, "\n\r") {
		t.Errorf("control character survived: %q", got)
	}
}

func scoped() approve.ApprovalRequest {
	r := req()
	r.Argv = []string{"php", "artisan", "sync", "--force"}
	r.GrantCmdPrefix = []string{"php", "artisan"}
	r.GrantCwdPrefix = "/Users/me/projects/foo"
	return r
}

func TestGrantScopeText(t *testing.T) {
	want := "Allow for 1h covers: php artisan … in /Users/me/projects/foo and subfolders"
	if got := GrantScope(scoped(), time.Hour); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if GrantScope(scoped(), 0) != "" {
		t.Error("scope shown without an Allow-for-N offer")
	}
	if GrantScope(req(), time.Hour) != "" {
		t.Error("scope shown without a grant scope in the request")
	}
	r := scoped()
	r.GrantCmdPrefix = []string{"a`b", "x\ny"}
	r.GrantCwdPrefix = "/p\nAllow?"
	if g := GrantScope(r, time.Hour); strings.ContainsAny(g, "\n`") {
		t.Errorf("unsanitised: %q", g)
	}
}

func TestBuildReasonStatesGrantScopeWhenAllowForNIsOffered(t *testing.T) {
	got := BuildReason(scoped(), time.Hour)
	if !strings.Contains(got, "(Allow for 1h covers: php artisan … in /Users/me/projects/foo and subfolders)") {
		t.Errorf("got %q", got)
	}
	if strings.Contains(got, "approval lasts") {
		t.Errorf("old wording kept: %q", got)
	}
	if g := BuildReason(scoped(), 0); strings.Contains(g, "covers") {
		t.Errorf("scope in an allow-once reason: %q", g)
	}
	// Long argv/cwd are truncated in the main text, never the granted prefix.
	r := scoped()
	r.Argv = []string{strings.Repeat("x", 800)}
	r.GrantCmdPrefix = []string{"php", strings.Repeat("p", 40)}
	if g := BuildReason(r, time.Hour); !strings.Contains(g, "php "+strings.Repeat("p", 40)+" …") {
		t.Errorf("granted prefix truncated: %q", g)
	}
}

func TestFormatSpan(t *testing.T) {
	cases := map[time.Duration]string{
		30 * 24 * time.Hour:          "30 days",
		24 * time.Hour:               "1 day",
		36 * time.Hour:               "1 day 12 hours",
		8 * time.Hour:                "8 hours",
		time.Hour:                    "1 hour",
		90 * time.Minute:             "1 hour 30 minutes",
		45 * time.Minute:             "45 minutes",
		90 * 24 * time.Hour:          "90 days",
		10 * time.Second:             "under a minute",
		7*24*time.Hour + time.Minute: "7 days 1 minute",
	}
	for d, want := range cases {
		if got := formatSpan(d); got != want {
			t.Errorf("formatSpan(%v)=%q want %q", d, got, want)
		}
	}
}

func TestBuildReasonStandingGrant(t *testing.T) {
	r := standingReq()
	got := BuildReason(r, time.Hour) // the grantTTL argument is ignored for a standing grant
	want := "Create standing grant for 30 days: claude-code may run `php artisan …` with DB_URL, aws/* (aws/access_key) in /Users/me/projects/foo and subfolders"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	for _, bad := range []string{"wants to run", "Allow for", "approval lasts"} {
		if strings.Contains(got, bad) {
			t.Errorf("standing reason contains release wording %q: %q", bad, got)
		}
	}
	r.RequestedUses = 2
	r.PolicyPresent = false
	if got := BuildReason(r, 0); !strings.HasSuffix(got, "and subfolders (at most 2 runs) (no policy)") {
		t.Errorf("got %q", got)
	}
}

func TestBuildReasonStandingGrantTruncatesButKeepsScope(t *testing.T) {
	r := standingReq()
	r.GrantCmdPrefix = []string{"sh", strings.Repeat("x", 400)}
	got := BuildReason(r, 0)
	if !strings.HasPrefix(got, "Create standing grant for 30 days: ") {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(got, "with DB_URL, aws/* (aws/access_key)") || !strings.Contains(got, "…") {
		t.Errorf("secrets must stay whole and argv be truncated: %q", got)
	}
}

func TestBuildReasonUnchangedForShowAndRelease(t *testing.T) {
	a := BuildReason(req(), 0)
	r := req()
	r.Kind = approve.KindShow
	if b := BuildReason(r, 0); b != a {
		t.Errorf("show reason changed: %q vs %q", b, a)
	}
}

// The closing sentence of the standing-grant dialog is fixed text: it must not
// name a CLI command (the menu-bar app triggers this dialog too) and must not
// depend on the untrusted caller string.
func TestStandingTextClosingSentence(t *testing.T) {
	const want = "\n\nOnly continue if you just asked for this yourself."
	for _, caller := range []string{"claude-code", "grantpin-app", "cli", ""} {
		r := standingReq()
		r.Caller = caller
		got := StandingText(r)
		if !strings.HasSuffix(got, want) {
			t.Errorf("caller %q: text does not end with the fixed sentence: %q", caller, got)
		}
		if strings.Contains(strings.TrimSuffix(got, want), "grants add") {
			t.Errorf("caller %q: text mentions the CLI command: %q", caller, got)
		}
	}
}

func lowerReq() approve.ApprovalRequest {
	return approve.ApprovalRequest{
		Kind: approve.KindLowerTier, Caller: "claude-code",
		Argv:    []string{"grantpin", "update", "stripe/api_key"},
		Secrets: []string{"stripe/api_key"}, Expanded: []string{"stripe/api_key"},
		FromTier: presence.TierHardware, ToTier: presence.TierDialog,
	}
}

func TestLowerTierQuestionIsTheTouchIDReason(t *testing.T) {
	const want = "Lower the protection of stripe/api_key from hardware to dialog?"
	if got := BuildReason(lowerReq(), 0); got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	// A grant TTL never changes it, and a hostile name is sanitised.
	if got := BuildReason(lowerReq(), time.Hour); got != want {
		t.Errorf("reason with ttl = %q", got)
	}
	r := lowerReq()
	r.Secrets = []string{"a\u202eb\nc"}
	if got := BuildReason(r, 0); strings.ContainsAny(got, "\n\u202e") {
		t.Errorf("unsanitised reason %q", got)
	}
}

func TestLowerTierText(t *testing.T) {
	got := LowerTierText(lowerReq())
	if !strings.HasPrefix(got, "Lower the protection of stripe/api_key from hardware to dialog?\n\n") ||
		!strings.HasSuffix(got, "\n\nOnly continue if you just asked for this yourself.") {
		t.Errorf("text = %q", got)
	}
	for _, bad := range []string{"Allow", "Deny", "grants add"} {
		if strings.Contains(got, bad) {
			t.Errorf("text contains %q: %q", bad, got)
		}
	}
}
