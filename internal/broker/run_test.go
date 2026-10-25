package broker

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/grant"
	"grantd/internal/presence"
	"grantd/internal/proto"
	"grantd/internal/vault"
)

const echoBoth = `echo "out=$API_KEY"; echo "err=$API_KEY" >&2`

func TestRunAllowOnceRedactsAndAudits(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", echoBoth))
	wantOK(t, w)
	if w.final.ExitCode == nil || *w.final.ExitCode != 0 {
		t.Fatalf("exit = %v", w.final.ExitCode)
	}
	if got := w.out("stdout"); got != "out=[REDACTED:API_KEY]\n" {
		t.Errorf("stdout = %q", got)
	}
	if got := w.out("stderr"); got != "err=[REDACTED:API_KEY]\n" {
		t.Errorf("stderr = %q", got)
	}
	if b, _ := marshalAll(w); strings.Contains(b, e.secret) {
		t.Error("value present in frames/response")
	}
	rel, a := e.lastPair()
	if rel.Decision != audit.DecisionAllowedOnce || a.ExitCode == nil || *a.ExitCode != 0 || a.GrantID != "" || a.Duration <= 0 {
		t.Errorf("audit = %+v / %+v", rel, a)
	}
	if w.final.AuditID != a.ID {
		t.Errorf("audit id %q != %q", w.final.AuditID, a.ID)
	}
	if a.Caller != "tester" || a.Cwd != e.cwd {
		t.Errorf("audit identity = %+v", a)
	}
}

func marshalAll(w *recWriter) (string, error) {
	var sb strings.Builder
	for _, f := range w.frames {
		sb.WriteString(f.Data)
	}
	if w.final != nil {
		sb.WriteString(w.final.Message + w.final.Reason + w.final.Error + string(w.final.Result))
	}
	return sb.String(), nil
}

func TestRunExitCodePropagates(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 7"))
	wantOK(t, w)
	if *w.final.ExitCode != 7 {
		t.Fatalf("exit = %d", *w.final.ExitCode)
	}
}

func TestRunDefaultCaller(t *testing.T) {
	e := newEnv(t)
	req := e.run([]string{"API_KEY"}, "true")
	req.Caller = ""
	wantOK(t, e.do(req))
	if got := e.ap.last().Caller; got != "cli" {
		t.Errorf("caller = %q", got)
	}
}

func TestRunApprovalRequestContents(t *testing.T) {
	e := newEnv(t)
	e.do(e.run([]string{"API_*"}, "true"))
	r := e.ap.last()
	if r.Cwd != e.cwd || r.PolicyPresent || r.SuggestedTTL != time.Hour ||
		strings.Join(r.Secrets, ",") != "API_*" || strings.Join(r.Argv, ",") != "true" {
		t.Errorf("approval request = %+v", r)
	}
}

func TestRunNewGrantThenGrantMatch(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = time.Hour
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0"))
	wantOK(t, w)
	if w.final.GrantID == "" {
		t.Fatal("no grant id")
	}
	if rel, a := e.lastPair(); rel.Decision != audit.DecisionAllowedNewGrant || rel.GrantID != w.final.GrantID || a.GrantID != w.final.GrantID {
		t.Errorf("audit = %+v / %+v", rel, a)
	}
	w2 := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0"))
	wantOK(t, w2)
	if e.ap.calls() != 1 {
		t.Errorf("approver asked %d times, want 1", e.ap.calls())
	}
	if rel, a := e.lastPair(); rel.Decision != audit.DecisionAllowedGrant || a.GrantID != w.final.GrantID {
		t.Errorf("audit = %+v / %+v", rel, a)
	}
	// Different cwd: asked again.
	other, _ := filepath.EvalSymlinks(t.TempDir())
	req := e.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	req.Cwd = other
	wantOK(t, e.do(req))
	if e.ap.calls() != 2 {
		t.Errorf("approver asked %d times, want 2", e.ap.calls())
	}
	// Different argv: asked again.
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 1")))
	if e.ap.calls() != 3 {
		t.Errorf("approver asked %d times, want 3", e.ap.calls())
	}
	// Grant expiry.
	e.advance(2 * time.Hour)
	e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0"))
	if e.ap.calls() != 4 {
		t.Errorf("approver asked %d times after expiry, want 4", e.ap.calls())
	}
}

func TestRunGrantTTLClampedByDefault(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = 48 * time.Hour
	w := e.do(e.run([]string{"API_KEY"}, "true"))
	wantOK(t, w)
	g, err := e.g.Get(context.Background(), w.final.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if d := g.ExpiresAt.Sub(g.CreatedAt); d > time.Hour {
		t.Errorf("grant lasts %s, want <= 1h", d)
	}
}

func TestRunDenied(t *testing.T) {
	e := newEnv(t)
	e.ap.allow, e.ap.reason = false, "nope"
	w := e.do(e.run([]string{"API_KEY"}, "true"))
	wantFail(t, w, proto.ErrDenied, proto.ReasonUserDenied)
	a := e.lastAudit()
	if a.Decision != audit.DecisionDeniedUser || a.Reason != "nope" || a.ExitCode != nil {
		t.Errorf("audit = %+v", a)
	}
	if w.final.AuditID != a.ID {
		t.Error("response lacks audit id")
	}
}

func TestRunApproverError(t *testing.T) {
	e := newEnv(t)
	e.ap.err = os.ErrPermission
	w := e.do(e.run([]string{"API_KEY"}, "true"))
	wantFail(t, w, proto.ErrDenied, proto.ReasonApproverUnavailable)
	if a := e.lastAudit(); a.Decision != audit.DecisionError {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunPolicy(t *testing.T) {
	e := newEnv(t)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "OTHER"}, []byte("other-secret-value"), false); err != nil {
		t.Fatal(err)
	}
	writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [sh]\nmax_grant_ttl: 30m\n", 0o600)

	// secret not allowed
	w := e.do(e.run([]string{"OTHER"}, "sh", "-c", "true"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonPolicyRefused)
	if !strings.Contains(w.final.Message, "OTHER") || strings.Contains(w.final.Message, "other-secret-value") {
		t.Errorf("message = %q", w.final.Message)
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionRefusedPolicy {
		t.Errorf("audit = %+v", a)
	}
	// command not allowed
	w = e.do(e.run([]string{"API_KEY"}, "echo", "hi"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonPolicyRefused)
	if !strings.Contains(w.final.Message, "echo") {
		t.Errorf("message = %q", w.final.Message)
	}
	if e.ap.calls() != 0 {
		t.Fatal("approver was asked for a policy-refused request")
	}

	// allowed: PolicyPresent, suggested TTL capped, grant prefix = policy prefix.
	e.ap.ttl = 4 * time.Hour
	w = e.do(e.run([]string{"API_KEY"}, "sh", "-c", "true"))
	wantOK(t, w)
	r := e.ap.last()
	if !r.PolicyPresent || r.SuggestedTTL != 30*time.Minute {
		t.Errorf("approval request = %+v", r)
	}
	g, err := e.g.Get(context.Background(), w.final.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(g.CmdPrefix, " ") != "sh" || g.ExpiresAt.Sub(g.CreatedAt) > 30*time.Minute {
		t.Errorf("grant = %+v", g)
	}
	// A different sh command is covered by the policy-prefix grant.
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0")))
	if e.ap.calls() != 1 {
		t.Errorf("approver calls = %d", e.ap.calls())
	}
}

func TestRunInsecurePolicy(t *testing.T) {
	e := newEnv(t)
	writePolicy(t, e.cwd, "version: 1\nsecrets: ['*']\ncommands:\n  - [sh]\n", 0o666)
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "true"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonPolicyRefused)
	if e.ap.calls() != 0 {
		t.Fatal("approver asked")
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionRefusedPolicy {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunTierUnmet(t *testing.T) {
	e := newEnv(t)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "HW", MinTier: presence.TierHardware}, []byte("hardware-secret-1"), false); err != nil {
		t.Fatal(err)
	}
	w := e.do(e.run([]string{"API_KEY", "HW"}, "true"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonTierUnmet)
	if e.ap.calls() != 0 {
		t.Fatal("approver asked")
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionRefusedTier {
		t.Errorf("audit = %+v", a)
	}
	// Approver strong enough but keystore weak: still refused.
	e.ap.tier = presence.TierHardware
	wantFail(t, e.do(e.run([]string{"HW"}, "true")), proto.ErrRefused, proto.ReasonTierUnmet)
	// Both strong: allowed.
	e.rebuild(presence.TierHardware)
	wantOK(t, e.do(e.run([]string{"HW"}, "true")))
	// Approver weak but keystore strong: refused.
	e.ap.tier = presence.TierDialog
	wantFail(t, e.do(e.run([]string{"HW"}, "true")), proto.ErrRefused, proto.ReasonTierUnmet)
}

func TestRunNotFound(t *testing.T) {
	e := newEnv(t)
	for _, s := range []string{"MISSING", "nope/*"} {
		w := e.do(e.run([]string{"API_KEY", s}, "true"))
		wantFail(t, w, proto.ErrNotFound, proto.ReasonSecretNotFound)
	}
	if e.ap.calls() != 0 {
		t.Fatal("approver asked")
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionError {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunExpiredSecret(t *testing.T) {
	e := newEnv(t)
	exp := e.now.Add(time.Hour)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "OLD", ExpiresAt: &exp}, []byte("old-secret-value"), false); err != nil {
		t.Fatal(err)
	}
	e.advance(2 * time.Hour)
	w := e.do(e.run([]string{"OLD"}, "true"))
	wantFail(t, w, proto.ErrRefused, proto.ReasonSecretExpired)
	if w.final.Message != "OLD" {
		t.Errorf("message = %q, want the secret's name", w.final.Message)
	}
	if e.ap.calls() != 0 {
		t.Fatal("approver asked")
	}
}

func TestRunBadRequests(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.cwd, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(r *proto.Request)) *proto.Request {
		r := e.run([]string{"API_KEY"}, "true")
		f(r)
		return r
	}
	for name, r := range map[string]*proto.Request{
		"relative cwd":      mut(func(r *proto.Request) { r.Cwd = "rel/dir" }),
		"missing cwd":       mut(func(r *proto.Request) { r.Cwd = filepath.Join(e.cwd, "nope") }),
		"cwd is file":       mut(func(r *proto.Request) { r.Cwd = file }),
		"no argv":           mut(func(r *proto.Request) { r.Argv = nil }),
		"empty argv0":       mut(func(r *proto.Request) { r.Argv = []string{""} }),
		"no secrets":        mut(func(r *proto.Request) { r.Secrets = nil }),
		"empty secret":      mut(func(r *proto.Request) { r.Secrets = []string{""} }),
		"bad caller":        mut(func(r *proto.Request) { r.Caller = "evil\nAllow?" }),
		"long caller":       mut(func(r *proto.Request) { r.Caller = strings.Repeat("a", 100) }),
		"bad env prefix":    mut(func(r *proto.Request) { r.EnvPrefix = "bad-prefix" }),
		"newline in argv":   mut(func(r *proto.Request) { r.Argv = []string{"sh", "-c", "a\nb"} }),
		"escape in argv":    mut(func(r *proto.Request) { r.Argv = []string{"echo", "\x1b[2J"} }),
		"nul in argv":       mut(func(r *proto.Request) { r.Argv = []string{"echo", "a\x00b"} }),
		"control in cwd":    mut(func(r *proto.Request) { r.Cwd = e.cwd + "/x\ry" }),
		"control in caller": mut(func(r *proto.Request) { r.Caller = "a\x01b" }),
		"huge argv":         mut(func(r *proto.Request) { r.Argv = []string{"echo", strings.Repeat("a", maxArgvBytes)} }),
	} {
		before := e.auditCount()
		w := &recWriter{}
		e.b.Handle(context.Background(), r, w)
		if w.final == nil || w.final.OK || w.final.Error != proto.ErrBadRequest {
			t.Errorf("%s: response = %+v", name, w.final)
		}
		if e.auditCount() != before+1 {
			t.Errorf("%s: not audited", name)
		}
	}
	if e.ap.calls() != 0 {
		t.Fatal("approver asked")
	}
}

// A tab is the one control character argv may carry.
func TestRunArgvMayContainTabs(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "sh", "-c", "true\t# comment")))
}

func TestRunEnvCollision(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, n := range []string{"a/token", "b/token"} {
		if err := e.v.Set(ctx, vault.Meta{Name: n}, []byte("v-"+n+"-value"), false); err != nil {
			t.Fatal(err)
		}
	}
	// Collisions resolve to full names; the run works and both are injected.
	w := e.do(e.run([]string{"a/*", "b/*"}, "sh", "-c", `echo "$A_TOKEN $B_TOKEN"`))
	wantOK(t, w)
	if got := w.out("stdout"); got != "[REDACTED:a/token] [REDACTED:b/token]\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunGlobGrantMatchesTextually(t *testing.T) {
	e := newEnv(t)
	if err := e.v.Set(context.Background(), vault.Meta{Name: "aws/key"}, []byte("aws-key-value-1"), false); err != nil {
		t.Fatal(err)
	}
	e.ap.ttl = time.Hour
	wantOK(t, e.do(e.run([]string{"aws/*"}, "true")))
	wantOK(t, e.do(e.run([]string{"aws/*"}, "true")))
	if e.ap.calls() != 1 {
		t.Errorf("calls = %d", e.ap.calls())
	}
	// Literal name is covered by the glob grant.
	wantOK(t, e.do(e.run([]string{"aws/key"}, "true")))
	if e.ap.calls() != 1 {
		t.Errorf("calls = %d", e.ap.calls())
	}
}

func TestRunTimeoutByContext(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	w := e.doCtx(ctx, e.run([]string{"API_KEY"}, "sleep", "5"))
	wantOK(t, w)
	if *w.final.ExitCode != 124 || w.final.Reason != proto.ReasonTimeout {
		t.Fatalf("response = %+v", w.final)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	if a := e.lastAudit(); a.ExitCode == nil || *a.ExitCode != 124 || a.Reason != "timeout" {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunTimeoutBySpec(t *testing.T) {
	e := newEnv(t)
	req := e.run([]string{"API_KEY"}, "sleep", "5")
	req.TimeoutS = 1
	w := e.do(req)
	wantOK(t, w)
	if *w.final.ExitCode != 124 {
		t.Fatalf("response = %+v", w.final)
	}
}

func TestRunCanceled(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	w := e.doCtx(ctx, e.run([]string{"API_KEY"}, "sleep", "5"))
	wantFail(t, w, proto.ErrFailed, proto.ReasonCanceled)
	if a := e.lastAudit(); a.Reason != "canceled" || a.ExitCode == nil {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunClientGoneCancelsChild(t *testing.T) {
	e := newEnv(t)
	req := e.run([]string{"API_KEY"}, "sh", "-c", "while true; do echo tick; sleep 0.05; done")
	w := &recWriter{failAt: 2}
	done := make(chan struct{})
	go func() { e.b.Handle(context.Background(), req, w); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop after the stream broke")
	}
}

func TestRunCommandNotFound(t *testing.T) {
	e := newEnv(t)
	w := e.do(e.run([]string{"API_KEY"}, "definitely-not-a-command-xyz"))
	wantOK(t, w)
	if *w.final.ExitCode != 127 || !strings.Contains(w.final.Message, "command not found") {
		t.Fatalf("response = %+v", w.final)
	}
	if a := e.lastAudit(); a.ExitCode == nil || *a.ExitCode != 127 {
		t.Errorf("audit = %+v", a)
	}
}

func TestRunCannotExecute(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.cwd, "noexec")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := e.do(e.run([]string{"API_KEY"}, "./noexec"))
	wantOK(t, w)
	if *w.final.ExitCode != 126 {
		t.Fatalf("response = %+v", w.final)
	}
}

func TestRunSplitSecretAcrossWrites(t *testing.T) {
	e := newEnv(t)
	// printf in two halves with a delay: the value straddles two reads.
	half := len(e.secret) / 2
	script := `printf '%s' "$(printf %s "$API_KEY" | cut -c1-` + itoa(half) + `)"; sleep 0.2; printf '%s\n' "$(printf %s "$API_KEY" | cut -c` + itoa(half+1) + `-)"`
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", script))
	wantOK(t, w)
	if got := w.out("stdout"); got != "[REDACTED:API_KEY]\n" {
		t.Errorf("stdout = %q", got)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestRunUTF8SplitAcrossWrites(t *testing.T) {
	e := newEnv(t)
	// "é" is 0xC3 0xA9; emit the two bytes with a pause in between.
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", `printf '\303'; sleep 0.2; printf '\251\n'`))
	wantOK(t, w)
	if got := w.out("stdout"); got != "é\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunSerialisesApprover(t *testing.T) {
	e := newEnv(t)
	e.ap.block = make(chan struct{})
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); e.do(e.run([]string{"API_KEY"}, "true")) }()
	}
	time.Sleep(300 * time.Millisecond)
	if e.ap.calls() != 1 {
		t.Fatalf("approver calls while blocked = %d, want 1", e.ap.calls())
	}
	close(e.ap.block)
	wg.Wait()
	if e.ap.calls() != 3 || e.ap.maxSeen != 1 {
		t.Errorf("calls=%d maxConcurrent=%d", e.ap.calls(), e.ap.maxSeen)
	}
}

func TestRunWaitingForApproverHonoursCancel(t *testing.T) {
	e := newEnv(t)
	e.ap.block = make(chan struct{})
	defer close(e.ap.block)
	go e.do(e.run([]string{"API_KEY"}, "true")) // holds the lock
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *recWriter, 1)
	go func() { done <- e.doCtx(ctx, e.run([]string{"API_KEY"}, "true")) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case w := <-done:
		wantFail(t, w, proto.ErrFailed, proto.ReasonCanceled)
	case <-time.After(5 * time.Second):
		t.Fatal("queued request ignored cancel")
	}
	if e.ap.calls() != 1 {
		t.Errorf("calls = %d", e.ap.calls())
	}
}

func TestRunApprovalDeadline(t *testing.T) {
	e := newEnv(t)
	e.ap.block = make(chan struct{})
	defer close(e.ap.block)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w := e.doCtx(ctx, e.run([]string{"API_KEY"}, "true"))
	wantFail(t, w, proto.ErrFailed, proto.ReasonTimeout)
}

func TestRunMessagesAreScrubbed(t *testing.T) {
	e := newEnv(t)
	rc := &runCtx{b: e.b, w: &recWriter{}}
	rc.redact = nil
	if rc.scrub("x") != "x" {
		t.Fatal("scrub without redactor must be identity")
	}
	// An argv that contains the value (the test knows it; an agent would not)
	// must not leak through the response, the command-not-found message or any
	// audit row, the released row included.
	req := e.run([]string{"API_KEY"}, e.secret)
	w := e.do(req)
	wantOK(t, w)
	if b, _ := marshalAll(w); strings.Contains(b, e.secret) {
		t.Errorf("value leaked: %q", b)
	}
	rel, done := e.lastPair()
	if rel.Reason != ReasonReleased || done.Decision != audit.DecisionCompleted {
		t.Fatalf("rows = %+v / %+v", rel, done)
	}
	es, _ := e.a.List(context.Background(), 10, 0)
	if len(es) != 2 {
		t.Fatalf("%d rows", len(es))
	}
	for _, en := range es {
		if strings.Contains(strings.Join(en.Argv, " ")+en.Reason+en.Cwd+en.Caller+strings.Join(en.Secrets, " "), e.secret) {
			t.Errorf("audit row leaked value: %+v", en)
		}
		if got := strings.Join(en.Argv, " "); got != "[REDACTED:API_KEY]" {
			t.Errorf("argv in row %s = %q", en.ID, got)
		}
	}
	if out := e.logs.String(); strings.Contains(out, e.secret) {
		t.Errorf("value in the broker log:\n%s", out)
	}
}

func TestRunResolveFailureLeavesSingleErrorRow(t *testing.T) {
	e := newEnv(t)
	// The secret disappears between approval and release.
	e.ap.onAsk = func() { _ = e.v.Delete(context.Background(), "API_KEY") }
	before := e.auditCount()
	w := e.do(e.run([]string{"API_KEY"}, "true"))
	wantFail(t, w, proto.ErrNotFound, proto.ReasonSecretNotFound)
	if e.auditCount() != before+1 {
		t.Fatalf("want exactly one new audit row, got %d", e.auditCount()-before)
	}
	a := e.lastAudit()
	if a.Decision != audit.DecisionError || !strings.HasPrefix(a.Reason, proto.ReasonSecretNotFound) || a.Reason == ReasonReleased {
		t.Errorf("audit = %+v", a)
	}
	if w.final.AuditID != a.ID {
		t.Errorf("audit id %q != %q", w.final.AuditID, a.ID)
	}
}

func TestRunNothingReleasedWhenPreReleaseAuditFails(t *testing.T) {
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
	marker := filepath.Join(e.cwd, "ran")
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "touch "+marker))
	wantFail(t, w, proto.ErrFailed, proto.ReasonInternal)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran although the released audit row could not be written")
	}
}

func TestRunApprovalRequestCarriesExpandedNames(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"aws/b", "aws/a"} {
		if err := e.v.Set(context.Background(), vault.Meta{Name: n}, []byte("value-"+n+"-xx"), false); err != nil {
			t.Fatal(err)
		}
	}
	wantOK(t, e.do(e.run([]string{"aws/*"}, "true")))
	r := e.ap.last()
	if strings.Join(r.Secrets, ",") != "aws/*" || strings.Join(r.Expanded, ",") != "aws/a,aws/b" {
		t.Errorf("approval request = %+v", r)
	}
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	if r := e.ap.last(); strings.Join(r.Expanded, ",") != "API_KEY" {
		t.Errorf("literal request Expanded = %v", r.Expanded)
	}
}

func TestRunApprovalRequestStatesGrantScope(t *testing.T) {
	e := newEnv(t)
	// No policy: the grant would be scoped to the full argv in the resolved cwd.
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0")))
	r := e.ap.last()
	if strings.Join(r.GrantCmdPrefix, "|") != "sh|-c|exit 0" || r.GrantCwdPrefix != e.cwd {
		t.Errorf("scope = %q in %q", r.GrantCmdPrefix, r.GrantCwdPrefix)
	}
	// With a policy prefix: the policy prefix, and what is stored is identical.
	writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [sh]\n", 0o600)
	e.ap.ttl = time.Hour
	w := e.do(e.run([]string{"API_KEY"}, "sh", "-c", "exit 0"))
	wantOK(t, w)
	r = e.ap.last()
	g, err := e.g.Get(context.Background(), w.final.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.GrantCmdPrefix, "|") != "sh" || strings.Join(g.CmdPrefix, "|") != strings.Join(r.GrantCmdPrefix, "|") || g.CwdPrefix != r.GrantCwdPrefix {
		t.Errorf("shown scope %q in %q != stored %q in %q", r.GrantCmdPrefix, r.GrantCwdPrefix, g.CmdPrefix, g.CwdPrefix)
	}
}

// ---- dialog TTL follows the repo policy, capped ---------------------------

func TestRunDialogTTLFollowsPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		policy      string // max_grant_ttl line, "" for none
		wantOffered time.Duration
	}{
		{"no max_grant_ttl key", "", time.Hour}, // the policy default
		{"8h", "max_grant_ttl: 8h\n", 8 * time.Hour},
		{"90m", "max_grant_ttl: 90m\n", 90 * time.Minute},
		{"exactly the cap", "max_grant_ttl: 24h\n", 24 * time.Hour},
		{"7d is capped to 24h", "max_grant_ttl: 7d\n", 24 * time.Hour},
		{"10m", "max_grant_ttl: 10m\n", 10 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [true]\n"+tc.policy, 0o600)
			e.ap.ttl = tc.wantOffered // the human takes the offer
			w := e.do(e.run([]string{"API_KEY"}, "true"))
			wantOK(t, w)
			r := e.ap.last()
			if r.Kind != approve.KindRelease || r.SuggestedTTL != tc.wantOffered {
				t.Fatalf("offered %v (kind %v), want %v", r.SuggestedTTL, r.Kind, tc.wantOffered)
			}
			g, err := e.g.Get(context.Background(), w.final.GrantID)
			if err != nil {
				t.Fatal(err)
			}
			if d := g.ExpiresAt.Sub(g.CreatedAt); d != tc.wantOffered || g.Standing {
				t.Errorf("grant lasts %v (standing=%v), want %v", d, g.Standing, tc.wantOffered)
			}
		})
	}
}

func TestRunDialogGrantNeverExceedsTheOffer(t *testing.T) {
	// An approver answering for longer than it was offered is clamped: to the
	// policy's max_grant_ttl, and to 24h whatever the policy says.
	for _, tc := range []struct {
		policy string
		want   time.Duration
	}{
		{"max_grant_ttl: 8h\n", 8 * time.Hour},
		{"max_grant_ttl: 7d\n", 24 * time.Hour},
		{"", time.Hour},
	} {
		e := newEnv(t)
		writePolicy(t, e.cwd, "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [true]\n"+tc.policy, 0o600)
		e.ap.ttl = 30 * 24 * time.Hour
		w := e.do(e.run([]string{"API_KEY"}, "true"))
		wantOK(t, w)
		g, _ := e.g.Get(context.Background(), w.final.GrantID)
		if d := g.ExpiresAt.Sub(g.CreatedAt); d != tc.want {
			t.Errorf("policy %q: grant lasts %v, want %v", tc.policy, d, tc.want)
		}
	}
}

func TestRunNoPolicyOffersTheDaemonDefault(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	if r := e.ap.last(); r.SuggestedTTL != time.Hour || r.Kind != approve.KindRelease || r.PolicyPresent {
		t.Errorf("request = %+v", r)
	}
	if grant.MaxDialogGrantTTL != 24*time.Hour {
		t.Errorf("MaxDialogGrantTTL = %v", grant.MaxDialogGrantTTL)
	}
}

// A request that matches a finite-use grant but then fails before anything is
// released must not burn one of the grant's uses.
func TestRunFailedResolveAfterGrantMatchKeepsTheUse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// The broker's clock runs 3h behind the vault's (real) one: a secret that
	// expired 1h ago still looks valid to the broker's checks and the grant
	// matches, but Resolve refuses it.
	e.advance(-3 * time.Hour)
	past := time.Now().Add(-time.Hour)
	if err := e.v.Set(ctx, vault.Meta{Name: "STALE", ExpiresAt: &past}, []byte("stale-secret-value"), false); err != nil {
		t.Fatal(err)
	}
	req := e.add([]string{"STALE"}, day, "true")
	req.Uses = 2
	wantOK(t, e.do(req))
	asked := e.ap.calls()

	run := e.run([]string{"STALE"}, "true")
	run.Caller = "claude-code"
	for range 3 {
		wantFail(t, e.do(run), proto.ErrRefused, proto.ReasonSecretExpired)
	}
	if e.ap.calls() != asked {
		t.Fatal("the grant did not match: the human was asked")
	}
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 1 || gs[0].UsesRemaining == nil || *gs[0].UsesRemaining != 2 {
		t.Fatalf("uses were consumed by failed runs: %+v", gs)
	}
}

// A successful grant-matched run costs exactly one use.
func TestRunGrantMatchedReleaseConsumesOneUse(t *testing.T) {
	e := newEnv(t)
	req := e.add([]string{"API_KEY"}, day, "true")
	req.Uses = 2
	wantOK(t, e.do(req))
	run := e.run([]string{"API_KEY"}, "true")
	run.Caller = "claude-code"
	wantOK(t, e.do(run))
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 1 || *gs[0].UsesRemaining != 1 {
		t.Fatalf("grants = %+v", gs)
	}
}

// Many concurrent runs against a 3-use grant release exactly 3 times, even
// though Match no longer takes the use itself.
func TestRunConcurrentRunsCannotOverConsumeAGrant(t *testing.T) {
	e := newEnv(t)
	const uses, workers = 3, 8
	req := e.add([]string{"API_KEY"}, day, "sh", "-c", "echo x >> ran")
	req.Uses = uses
	wantOK(t, e.do(req))
	e.ap.allow = false // anything that does not match a grant is denied

	var wg sync.WaitGroup
	var okRuns atomic.Int32
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run := e.run([]string{"API_KEY"}, "sh", "-c", "echo x >> ran")
			run.Caller, run.V = "claude-code", proto.Version
			w := &recWriter{}
			e.b.Handle(context.Background(), run, w)
			if w.final.OK {
				okRuns.Add(1)
			}
		}()
	}
	wg.Wait()
	b, err := os.ReadFile(filepath.Join(e.cwd, "ran"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "x"); n != uses || okRuns.Load() != uses {
		t.Fatalf("command ran %d times, %d ok responses, want %d", n, okRuns.Load(), uses)
	}
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 1 || *gs[0].UsesRemaining != 0 {
		t.Fatalf("grants = %+v", gs)
	}
}

// lastPair2 is lastPair without requiring the completed row to carry an exit code.
func (e *env) lastPair2() (released, completed audit.Entry) {
	e.t.Helper()
	es, err := e.a.List(context.Background(), 2, 0)
	if err != nil || len(es) < 2 {
		e.t.Fatalf("audit list: %v %v", es, err)
	}
	return es[1], es[0]
}

// If the grant is revoked after Match, the release is not started and the
// audit bracket is closed.
func TestRunGrantRevokedAfterMatchDoesNotRelease(t *testing.T) {
	e := newEnv(t)
	req := e.add([]string{"API_KEY"}, day, "sh", "-c", "echo x >> ran")
	req.Uses = 2
	wantOK(t, e.do(req))
	// Revoke from inside the released-row append, i.e. after Match and Resolve.
	run := e.run([]string{"API_KEY"}, "sh", "-c", "echo x >> ran")
	run.Caller = "claude-code"
	gs, _ := e.g.List(context.Background())
	e.b.afterReleased = func() { _ = e.g.Revoke(context.Background(), gs[0].ID) }
	w := e.do(run)
	wantFail(t, w, proto.ErrDenied, proto.ReasonNoGrant)
	if rel, done := e.lastPair2(); rel.Reason != ReasonReleased || done.Decision != audit.DecisionCompleted ||
		!strings.HasPrefix(done.Reason, "not started: "+proto.ReasonNoGrant) {
		t.Errorf("audit bracket = %+v / %+v", rel, done)
	}
	if _, err := os.Stat(filepath.Join(e.cwd, "ran")); err == nil {
		t.Fatal("command ran although the grant was revoked")
	}
}

// The context ending before the command could start is reported as the
// caller's cancel/timeout, not as an internal failure.
func TestRunNotStartedBecauseContextEnded(t *testing.T) {
	marker := func(e *env) string { return filepath.Join(e.cwd, "ran") }
	cases := []struct {
		name   string
		ctx    func() (context.Context, context.CancelFunc)
		hook   func(cancel context.CancelFunc)
		reason string
	}{
		{"canceled", func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			func(cancel context.CancelFunc) { cancel() }, proto.ReasonCanceled},
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 30*time.Millisecond)
		}, func(context.CancelFunc) { time.Sleep(80 * time.Millisecond) }, proto.ReasonTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			ctx, cancel := c.ctx()
			defer cancel()
			e.b.afterReleased = func() { c.hook(cancel) }
			w := e.doCtx(ctx, e.run([]string{"API_KEY"}, "sh", "-c", "touch "+marker(e)))
			wantFail(t, w, proto.ErrFailed, c.reason)
			rel, done := e.lastPair2()
			if rel.Reason != ReasonReleased || done.Decision != audit.DecisionCompleted || done.Reason != c.reason || done.ExitCode != nil {
				t.Errorf("audit = %+v / %+v", rel, done)
			}
			if w.final.AuditID != done.ID {
				t.Errorf("audit id %q != %q", w.final.AuditID, done.ID)
			}
			if _, err := os.Stat(marker(e)); err == nil {
				t.Error("command ran")
			}
		})
	}
}

// Audit rows record the concrete names a glob released, not just the glob.
func TestRunAuditRowsRecordExpandedNames(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"aws/b", "aws/a"} {
		if err := e.v.Set(context.Background(), vault.Meta{Name: n}, []byte("value-"+n+"-xx"), false); err != nil {
			t.Fatal(err)
		}
	}
	wantOK(t, e.do(e.run([]string{"aws/*", "API_KEY"}, "true")))
	rel, done := e.lastPair()
	want := []string{"API_KEY", "aws/a", "aws/b"}
	for _, row := range []audit.Entry{rel, done} {
		if strings.Join(row.Secrets, ",") != "aws/*,API_KEY" || !slices.Equal(row.Expanded, want) {
			t.Errorf("row %s: secrets=%v expanded=%v", row.ID, row.Secrets, row.Expanded)
		}
	}
	// Without globs the expansion is the same names.
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	if _, done := e.lastPair(); !slices.Equal(done.Expanded, []string{"API_KEY"}) {
		t.Errorf("literal run: expanded = %v", done.Expanded)
	}
	// An error after expansion (here: a denial) carries it too; a refusal before
	// expansion (bad request) has none.
	e.ap.allow = false
	e.do(e.run([]string{"aws/*"}, "true"))
	if a := e.lastAudit(); a.Decision != audit.DecisionDeniedUser || !slices.Equal(a.Expanded, []string{"aws/a", "aws/b"}) {
		t.Errorf("denied row = %+v", a)
	}
	// It reaches `audit list` and the CSV export.
	list := decode[proto.AuditListResult](t, e.do(&proto.Request{Op: proto.OpAudit, Limit: 1})).Entries
	if !slices.Equal(list[0].Expanded, []string{"aws/a", "aws/b"}) {
		t.Errorf("list = %+v", list[0])
	}
	csv := decode[proto.AuditExportResult](t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport})).CSV
	if !strings.HasPrefix(csv, "id,ts,caller,cwd,argv,secrets,expanded,") || !strings.Contains(csv, `"[""aws/a"",""aws/b""]"`) {
		t.Errorf("csv = %q", csv)
	}
}
