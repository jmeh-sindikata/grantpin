package broker

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/grant"
	"grantd/internal/presence"
	"grantd/internal/proto"
	"grantd/internal/vault"
)

const day = 24 * time.Hour

// add builds a `grants add` request for the env's cwd.
func (e *env) add(secrets []string, ttl time.Duration, argv ...string) *proto.Request {
	return &proto.Request{
		Op: proto.OpGrants, Action: proto.ActionAdd, Caller: "cli", GrantCaller: "claude-code",
		Cwd: e.cwd, Secrets: secrets, Argv: argv, TTLS: int64(ttl / time.Second),
	}
}

func (e *env) grantCount() int {
	e.t.Helper()
	gs, err := e.g.List(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return len(gs)
}

func TestGrantAddCreatesAStandingGrant(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.add([]string{"API_KEY"}, 30*day, "php", "artisan"))
	wantOK(t, w)
	info := decode[proto.GrantInfo](t, w)
	if info.ID == "" || info.ID != w.final.GrantID || !info.Standing || info.Caller != "claude-code" ||
		info.CwdPrefix != e.cwd || strings.Join(info.Secrets, ",") != "API_KEY" || strings.Join(info.CmdPrefix, " ") != "php artisan" ||
		info.UsesRemaining != nil || info.ExpiresAt.Sub(info.CreatedAt) != 30*day {
		t.Fatalf("info = %+v", info)
	}
	// The human was shown exactly this.
	r := e.ap.last()
	if r.Kind != approve.KindStandingGrant || r.Caller != "claude-code" || r.Cwd != e.cwd || r.GrantCwdPrefix != e.cwd ||
		strings.Join(r.GrantCmdPrefix, " ") != "php artisan" || strings.Join(r.Secrets, ",") != "API_KEY" ||
		strings.Join(r.Expanded, ",") != "API_KEY" || r.RequestedTTL != 30*day || r.RequestedUses != 0 ||
		r.SuggestedTTL != 0 || r.PolicyPresent {
		t.Fatalf("approval request = %+v", r)
	}
	// Stored, authenticated, and marked.
	g, err := e.g.Get(context.Background(), info.ID)
	if err != nil || g.Tampered || !g.Standing {
		t.Fatalf("stored grant = %+v, %v", g, err)
	}
	// Audited.
	a := e.lastAudit()
	if a.Decision != audit.DecisionAllowedNewGrant || a.Reason != ReasonStanding || a.GrantID != info.ID ||
		a.Caller != "claude-code" || a.Cwd != e.cwd || strings.Join(a.Argv, " ") != "php artisan" || a.ID != w.final.AuditID {
		t.Fatalf("audit = %+v", a)
	}
	if v, err := e.a.Verify(context.Background()); err != nil || !v.OK {
		t.Fatalf("audit verify = %+v %v", v, err)
	}
	// Listed as standing.
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 1 || !gs[0].Standing {
		t.Fatalf("grants = %+v", gs)
	}
}

func TestGrantAddThenRunMatchesWithoutPrompt(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(e.add([]string{"API_KEY"}, 30*day, "sh", "-c")))
	if e.ap.calls() != 1 {
		t.Fatalf("calls = %d", e.ap.calls())
	}
	req := e.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	req.Caller = "claude-code"
	w := e.do(req)
	wantOK(t, w)
	if e.ap.calls() != 1 {
		t.Fatalf("standing grant did not satisfy the run (approver asked %d times)", e.ap.calls())
	}
	if rel, _ := e.lastPair(); rel.Decision != audit.DecisionAllowedGrant {
		t.Errorf("release decision = %q, want allowed_grant", rel.Decision)
	}
	// Valid weeks later, gone after its lifetime.
	e.advance(29 * day)
	wantOK(t, e.do(req))
	if e.ap.calls() != 1 {
		t.Errorf("grant expired early (asked %d times)", e.ap.calls())
	}
	e.advance(2 * day)
	wantOK(t, e.do(req))
	if e.ap.calls() != 2 {
		t.Errorf("expired standing grant still matched (asked %d times)", e.ap.calls())
	}
	// A different caller is not covered.
	req.Caller = "someone-else"
	wantOK(t, e.do(req))
	if e.ap.calls() != 3 {
		t.Errorf("grant matched another caller (asked %d times)", e.ap.calls())
	}
}

func TestGrantAddUsesLimit(t *testing.T) {
	e := newEnv(t)
	req := e.add([]string{"API_KEY"}, day, "true")
	req.Uses = 2
	w := e.do(req)
	wantOK(t, w)
	if info := decode[proto.GrantInfo](t, w); info.UsesRemaining == nil || *info.UsesRemaining != 2 {
		t.Fatalf("info = %+v", info)
	}
	if e.ap.last().RequestedUses != 2 {
		t.Errorf("approver not told about the use limit: %+v", e.ap.last())
	}
	run := e.run([]string{"API_KEY"}, "true")
	run.Caller = "claude-code"
	wantOK(t, e.do(run))
	wantOK(t, e.do(run))
	if e.ap.calls() != 1 {
		t.Fatalf("asked %d times within the use limit", e.ap.calls())
	}
	wantOK(t, e.do(run)) // third use: asks again
	if e.ap.calls() != 2 {
		t.Errorf("use limit not enforced (asked %d times)", e.ap.calls())
	}
}

func TestGrantAddExpandsGlobsForTheDialogButStoresTheGlob(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"aws/b", "aws/a"} {
		if err := e.v.Set(context.Background(), vault.Meta{Name: n}, []byte("value-"+n+"-xx"), false); err != nil {
			t.Fatal(err)
		}
	}
	w := e.do(e.add([]string{"aws/*", "API_KEY"}, day, "aws"))
	wantOK(t, w)
	r := e.ap.last()
	if strings.Join(r.Secrets, ",") != "aws/*,API_KEY" || strings.Join(r.Expanded, ",") != "API_KEY,aws/a,aws/b" {
		t.Errorf("request = %+v", r)
	}
	if g, _ := e.g.Get(context.Background(), w.final.GrantID); strings.Join(g.Secrets, ",") != "aws/*,API_KEY" {
		t.Errorf("stored secrets = %v", g.Secrets)
	}
}

func TestKindIsSetByEveryOp(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	if k := e.ap.last().Kind; k != approve.KindRelease {
		t.Errorf("run kind = %v", k)
	}
	wantOK(t, e.do(showReq(e)))
	if k := e.ap.last().Kind; k != approve.KindShow {
		t.Errorf("show kind = %v", k)
	}
	if r := e.ap.last(); r.SuggestedTTL != 0 || r.RequestedTTL != 0 || len(r.GrantCmdPrefix) != 0 {
		t.Errorf("show offers a duration or scope: %+v", r)
	}
	wantOK(t, e.do(e.add([]string{"API_KEY"}, day, "true")))
	if k := e.ap.last().Kind; k != approve.KindStandingGrant {
		t.Errorf("grants add kind = %v", k)
	}
}

func TestGrantAddDeniedCreatesNothing(t *testing.T) {
	e := newEnv(t)
	e.ap.allow, e.ap.reason = false, "user denied"
	w := e.do(e.add([]string{"API_KEY"}, 30*day, "true"))
	wantFail(t, w, proto.ErrDenied, proto.ReasonUserDenied)
	if e.grantCount() != 0 {
		t.Fatal("a grant exists after Cancel")
	}
	a := e.lastAudit()
	if a.Decision != audit.DecisionDeniedUser || !strings.HasPrefix(a.Reason, "standing grant: ") || a.ID != w.final.AuditID {
		t.Errorf("audit = %+v", a)
	}
	// And nothing satisfies a later run.
	e.ap.allow = true
	run := e.run([]string{"API_KEY"}, "true")
	run.Caller = "claude-code"
	wantOK(t, e.do(run))
	if e.ap.calls() != 2 {
		t.Errorf("run was not asked (calls=%d)", e.ap.calls())
	}
}

func TestGrantAddApproverErrors(t *testing.T) {
	e := newEnv(t)
	e.ap.err = errors.New("no gui")
	wantFail(t, e.do(e.add([]string{"API_KEY"}, day, "true")), proto.ErrDenied, proto.ReasonApproverUnavailable)
	if e.grantCount() != 0 {
		t.Fatal("grant created although the prompt failed")
	}
}

// An approver must answer with exactly the requested duration; anything else
// is not a confirmation of the grant that was shown.
func TestGrantAddRequiresTheExactDurationBack(t *testing.T) {
	for name, ttl := range map[string]time.Duration{"zero (allow once)": 0, "longer": 60 * day, "shorter": time.Hour} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.ap.standingTTL = &ttl
			wantFail(t, e.do(e.add([]string{"API_KEY"}, 30*day, "true")), proto.ErrDenied, proto.ReasonUserDenied)
			if e.grantCount() != 0 {
				t.Fatal("grant created from a mismatched answer")
			}
		})
	}
}

func TestGrantAddCallerIsRequiredAndChecked(t *testing.T) {
	e := newEnv(t)
	req := e.add([]string{"API_KEY"}, day, "true")
	req.GrantCaller = ""
	w := e.do(req)
	wantFail(t, w, proto.ErrBadRequest, proto.ReasonBadRequest)
	if !strings.Contains(w.final.Message, "grant_caller") {
		t.Errorf("message = %q", w.final.Message)
	}
	// The requester's own caller label is not a default for it.
	req = e.add([]string{"API_KEY"}, day, "true")
	req.GrantCaller, req.Caller = "  ", "claude-code"
	wantFail(t, e.do(req), proto.ErrBadRequest, proto.ReasonBadRequest)
	for _, bad := range []string{"line\nbreak", strings.Repeat("x", 65), "esc\x1b[2J"} {
		req = e.add([]string{"API_KEY"}, day, "true")
		req.GrantCaller = bad
		wantFail(t, e.do(req), proto.ErrBadRequest, proto.ReasonBadRequest)
	}
	if e.ap.calls() != 0 || e.grantCount() != 0 {
		t.Fatalf("invalid requests reached the approver (%d) or created grants (%d)", e.ap.calls(), e.grantCount())
	}
}

func TestGrantAddValidation(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.cwd, "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*proto.Request){
		"relative cwd":       func(r *proto.Request) { r.Cwd = "relative/dir" },
		"missing cwd":        func(r *proto.Request) { r.Cwd = filepath.Join(e.cwd, "nope") },
		"cwd is a file":      func(r *proto.Request) { r.Cwd = file },
		"no secrets":         func(r *proto.Request) { r.Secrets = nil },
		"empty secret":       func(r *proto.Request) { r.Secrets = []string{""} },
		"no argv":            func(r *proto.Request) { r.Argv = nil },
		"empty argv0":        func(r *proto.Request) { r.Argv = []string{""} },
		"empty argv element": func(r *proto.Request) { r.Argv = []string{"php", "", "x"} },
		"no ttl":             func(r *proto.Request) { r.TTLS = 0 },
		"negative ttl":       func(r *proto.Request) { r.TTLS = -5 },
		"negative uses":      func(r *proto.Request) { r.Uses = -1 },
		"bad glob":           func(r *proto.Request) { r.Secrets = []string{"[a"} },
	} {
		req := e.add([]string{"API_KEY"}, day, "true")
		mut(req)
		w := e.doCtx(context.Background(), req)
		if w.final.OK || w.final.Error != proto.ErrBadRequest {
			t.Errorf("%s: response = %+v", name, w.final)
		}
	}
	if e.ap.calls() != 0 || e.grantCount() != 0 {
		t.Fatalf("invalid requests reached the approver (%d) or created grants (%d)", e.ap.calls(), e.grantCount())
	}
	// Refusals are audited.
	if e.auditCount() == 0 {
		t.Error("refused requests left no audit rows")
	}
}

func TestGrantAddUnknownAndExpiredSecrets(t *testing.T) {
	e := newEnv(t)
	wantFail(t, e.do(e.add([]string{"MISSING"}, day, "true")), proto.ErrNotFound, proto.ReasonSecretNotFound)
	past := e.now.Add(-time.Hour)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "OLD", ExpiresAt: &past}, []byte("old-secret-value-1"), false); err != nil {
		t.Fatal(err)
	}
	wantFail(t, e.do(e.add([]string{"OLD"}, day, "true")), proto.ErrRefused, proto.ReasonSecretExpired)
	wantFail(t, e.do(e.add([]string{"nothing/*"}, day, "true")), proto.ErrNotFound, proto.ReasonSecretNotFound)
	if e.ap.calls() != 0 || e.grantCount() != 0 {
		t.Fatal("approver asked or grant created")
	}
}

func TestGrantAddTierUnmet(t *testing.T) {
	e := newEnv(t)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "HW", MinTier: presence.TierHardware}, []byte("hardware-only-value"), false); err != nil {
		t.Fatal(err)
	}
	wantFail(t, e.do(e.add([]string{"HW"}, day, "true")), proto.ErrRefused, proto.ReasonTierUnmet)
	if e.ap.calls() != 0 || e.grantCount() != 0 {
		t.Fatal("approver asked or grant created")
	}
}

func TestGrantAddCeilings(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		ttl    time.Duration
		ok     bool
		msg    string // substring of the bad_request message
	}{
		{"no policy, 90d", "", 90 * day, true, ""},
		{"no policy, one second over 90d", "", 90*day + time.Second, false, "90d"},
		{"no policy, 120d", "", 120 * day, false, "exceeds the maximum standing grant lifetime of 90d"},
		{"no policy, 1 minute", "", time.Minute, true, ""},
		{"policy without a standing key: 30d", "max_grant_ttl: 1h\n", 30 * day, true, ""},
		{"max_grant_ttl does not cap standing grants (7d)", "max_grant_ttl: 8h\n", 7 * day, true, ""},
		{"max_grant_ttl does not cap standing grants (90d)", "max_grant_ttl: 10m\n", 90 * day, true, ""},
		{"policy ceiling 30d, at it", "max_standing_grant_ttl: 30d\n", 30 * day, true, ""},
		{"policy ceiling 30d, over it", "max_standing_grant_ttl: 30d\n", 31 * day, false, "max_standing_grant_ttl"},
		{"policy ceiling 12h, 1d", "max_standing_grant_ttl: 12h\n", day, false, "12h"},
		{"policy ceiling cannot raise the global one", "max_standing_grant_ttl: 365d\n", 91 * day, false, "daemon maximum"},
		{"policy ceiling above ttl", "max_standing_grant_ttl: 365d\n", 60 * day, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.policy != "" {
				writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [true]\n"+c.policy, 0o600)
			}
			w := e.do(e.add([]string{"API_KEY"}, c.ttl, "true"))
			if c.ok {
				wantOK(t, w)
				if g := decode[proto.GrantInfo](t, w); g.ExpiresAt.Sub(g.CreatedAt) != c.ttl {
					t.Errorf("lifetime = %v, want exactly %v", g.ExpiresAt.Sub(g.CreatedAt), c.ttl)
				}
				return
			}
			wantFail(t, w, proto.ErrBadRequest, proto.ReasonBadRequest)
			if !strings.Contains(w.final.Message, c.msg) {
				t.Errorf("message = %q, want it to contain %q", w.final.Message, c.msg)
			}
			if e.ap.calls() != 0 || e.grantCount() != 0 {
				t.Fatal("an over-ceiling request reached the approver or was clamped into a grant")
			}
		})
	}
}

func TestGrantAddHugeTTLDoesNotOverflow(t *testing.T) {
	e := newEnv(t)
	req := e.add([]string{"API_KEY"}, day, "true")
	req.TTLS = 1<<62 + 5
	wantFail(t, e.do(req), proto.ErrBadRequest, proto.ReasonBadRequest)
	if e.grantCount() != 0 {
		t.Fatal("grant created")
	}
}

func TestGrantAddPolicy(t *testing.T) {
	e := newEnv(t)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "OTHER"}, []byte("other-secret-value"), false); err != nil {
		t.Fatal(err)
	}
	writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [php, artisan]\n", 0o600)

	w := e.do(e.add([]string{"OTHER"}, day, "php", "artisan"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonPolicyRefused)
	if !strings.Contains(w.final.Message, "OTHER") {
		t.Errorf("message = %q", w.final.Message)
	}
	w = e.do(e.add([]string{"API_KEY"}, day, "sh", "-c"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonPolicyRefused)
	if a := e.lastAudit(); a.Decision != audit.DecisionRefusedPolicy {
		t.Errorf("audit = %+v", a)
	}
	// A prefix shorter than the policy's is not covered either.
	wantFail(t, e.do(e.add([]string{"API_KEY"}, day, "php")), proto.ErrRefused, proto.ReasonPolicyRefused)
	if e.ap.calls() != 0 || e.grantCount() != 0 {
		t.Fatal("approver asked or grant created for a policy-refused request")
	}

	// Allowed: the dialog is told a policy applies.
	wantOK(t, e.do(e.add([]string{"API_KEY"}, 30*day, "php", "artisan", "sync")))
	if r := e.ap.last(); !r.PolicyPresent || r.Kind != approve.KindStandingGrant {
		t.Errorf("request = %+v", r)
	}
	// An insecure policy file refuses, as for a run.
	writePolicy(t, e.cwd, "version: 1\n", 0o666)
	wantFail(t, e.do(e.add([]string{"API_KEY"}, day, "true")), proto.ErrRefused, proto.ReasonPolicyRefused)
}

// The dialog's Allow for N can never produce a standing grant: a release
// answer with a TTL gives a plain dialog grant, whatever the TTL.
func TestDialogGrantsAreNotStanding(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = 100 * day
	w := e.do(e.run([]string{"API_KEY"}, "true"))
	wantOK(t, w)
	g, _ := e.g.Get(context.Background(), w.final.GrantID)
	if g.Standing || g.ExpiresAt.Sub(g.CreatedAt) > grant.MaxDialogGrantTTL {
		t.Errorf("dialog grant = %+v", g)
	}
}

func TestGrantAddAuditFailureLeavesNoGrant(t *testing.T) {
	e := newEnv(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	broken, err := audit.New(context.Background(), db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close() // every Append now fails
	b, err := New(Deps{Vault: e.v, Grants: e.g, Audit: broken, Approver: e.ap})
	if err != nil {
		t.Fatal(err)
	}
	e.b = b
	wantFail(t, e.do(e.add([]string{"API_KEY"}, day, "true")), proto.ErrFailed, proto.ReasonInternal)
	if e.grantCount() != 0 {
		t.Fatal("a standing grant exists without an audit row")
	}
}

func TestGrantAddUnknownActionStillRejected(t *testing.T) {
	e := newEnv(t)
	wantFail(t, e.do(&proto.Request{Op: proto.OpGrants, Action: "addd"}), proto.ErrBadRequest, proto.ReasonBadRequest)
}

func TestSpanText(t *testing.T) {
	for secs, want := range map[int64]string{
		90 * 86400: "90d", 86400 + 12*3600: "1d12h", 45 * 60: "45m", 30: "30s", 0: "0s", 3661: "1h1m1s",
	} {
		if got := spanText(secs); got != want {
			t.Errorf("spanText(%d) = %q, want %q", secs, got, want)
		}
	}
}
