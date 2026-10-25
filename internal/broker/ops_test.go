package broker

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"grantd/internal/audit"
	"grantd/internal/daemon"
	"grantd/internal/presence"
	"grantd/internal/proto"
)

func TestNewValidates(t *testing.T) {
	e := newEnv(t)
	for name, d := range map[string]Deps{
		"vault":    {Grants: e.g, Audit: e.a, Approver: e.ap},
		"grants":   {Vault: e.v, Audit: e.a, Approver: e.ap},
		"audit":    {Vault: e.v, Grants: e.g, Approver: e.ap},
		"approver": {Vault: e.v, Grants: e.g, Audit: e.a},
	} {
		if _, err := New(d); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	b, err := New(Deps{Vault: e.v, Grants: e.g, Audit: e.a, Approver: e.ap, Logger: slog.Default()})
	if err != nil || b.d.DefaultGrantTTL != time.Hour {
		t.Fatalf("%v %v", b, err)
	}
}

func TestRegister(t *testing.T) {
	e := newEnv(t)
	r := daemon.NewRouter()
	e.b.Register(r)
	got := strings.Join(r.Ops(), ",")
	want := "audit,delete,exists,grants,list,masked,run,set,show"
	if got != want {
		t.Errorf("ops = %s, want %s", got, want)
	}
	w := &recWriter{}
	e.b.Handle(context.Background(), &proto.Request{V: 1, Op: proto.OpStatus}, w)
	wantFail(t, w, proto.ErrBadRequest, proto.ReasonUnknownOp)
}

func TestSetListExistsMaskedDelete(t *testing.T) {
	e := newEnv(t)
	hw := presence.TierDialog
	exp := time.Now().Add(48 * time.Hour)
	w := e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "AKIA-0123456789-WXYZ",
		Tags: []string{"prod"}, URL: "https://x", Notes: "n", Expires: &exp, MinTier: &hw})
	wantOK(t, w)
	if a := e.lastAudit(); a.Decision != audit.DecisionAllowedOnce || a.Reason != "set" || strings.Join(a.Argv, " ") != "grantd set aws/key" {
		t.Errorf("audit = %+v", a)
	}
	if b, _ := marshalAll(w); strings.Contains(b, "AKIA") {
		t.Error("set response leaked value")
	}

	// duplicate without overwrite
	dup := e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "other-value-1234"})
	wantFail(t, dup, proto.ErrBadRequest, proto.ReasonSecretExists)
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "AKIA-0123456789-WXYZ", Overwrite: true, Tags: []string{"prod"}, MinTier: &hw}))

	l := decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList}))
	if len(l) != 2 || l[0].Name != "API_KEY" || l[1].Name != "aws/key" || l[1].MinTier != presence.TierDialog {
		t.Fatalf("list = %+v", l)
	}
	l = decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList, Tag: "prod"}))
	if len(l) != 1 || l[0].Name != "aws/key" {
		t.Fatalf("tag list = %+v", l)
	}
	if got := decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList, Tag: "nothing"})); got == nil || len(got) != 0 {
		t.Fatalf("empty list = %#v", got)
	}

	if !decode[proto.ExistsResult](t, e.do(&proto.Request{Op: proto.OpExists, Name: "aws/key"})).Exists {
		t.Error("exists = false")
	}
	if decode[proto.ExistsResult](t, e.do(&proto.Request{Op: proto.OpExists, Name: "nope"})).Exists {
		t.Error("exists = true")
	}
	if m := decode[proto.MaskedResult](t, e.do(&proto.Request{Op: proto.OpMasked, Name: "aws/key"})).Masked; m != "****WXYZ" {
		t.Errorf("masked = %q", m)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpMasked, Name: "nope"}), proto.ErrNotFound, proto.ReasonSecretNotFound)

	wantOK(t, e.do(&proto.Request{Op: proto.OpDelete, Name: "aws/key"}))
	if a := e.lastAudit(); a.Reason != "delete" {
		t.Errorf("audit = %+v", a)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpDelete, Name: "aws/key"}), proto.ErrNotFound, proto.ReasonSecretNotFound)
}

func TestListExpiring(t *testing.T) {
	e := newEnv(t)
	soon := time.Now().Add(24 * time.Hour)
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "SOON", Value: "soon-value-1234", Expires: &soon}))
	l := decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList, ExpiringWithinS: 7 * 24 * 3600}))
	if len(l) != 1 || l[0].Name != "SOON" {
		t.Fatalf("list = %+v", l)
	}
}

func TestSetValidation(t *testing.T) {
	e := newEnv(t)
	past := time.Now().Add(-time.Hour)
	bad := presence.PresenceTier(9)
	for name, r := range map[string]*proto.Request{
		"bad name":     {Op: proto.OpSet, Name: "a//b", Value: "value-1234"},
		"empty name":   {Op: proto.OpSet, Name: "", Value: "value-1234"},
		"empty value":  {Op: proto.OpSet, Name: "X"},
		"huge value":   {Op: proto.OpSet, Name: "X", Value: strings.Repeat("a", maxValueBytes+1)},
		"bad tier":     {Op: proto.OpSet, Name: "X", Value: "value-1234", MinTier: &bad},
		"past expires": {Op: proto.OpSet, Name: "X", Value: "value-1234", Expires: &past},
		"exists name":  {Op: proto.OpExists, Name: "../x"},
		"masked name":  {Op: proto.OpMasked, Name: ""},
		"delete name":  {Op: proto.OpDelete, Name: "a b"},
		"show name":    {Op: proto.OpShow, Name: ""},
	} {
		wantFail(t, e.do(r), proto.ErrBadRequest, proto.ReasonBadRequest)
		_ = name
	}
}

func showReq(e *env) *proto.Request {
	return &proto.Request{Op: proto.OpShow, Name: "API_KEY", Caller: "cli", Cwd: e.cwd}
}

func TestShow(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = time.Hour // must be ignored
	w := e.do(showReq(e))
	wantOK(t, w)
	if v := decode[proto.ShowResult](t, w).Value; v != e.secret {
		t.Errorf("value = %q", v)
	}
	r := e.ap.last()
	if strings.Join(r.Argv, " ") != "grantd show API_KEY" || strings.Join(r.Secrets, ",") != "API_KEY" || r.PolicyPresent {
		t.Errorf("approval request = %+v", r)
	}
	a := e.lastAudit()
	if a.Decision != audit.DecisionAllowedOnce || a.Reason != "show" || a.GrantID != "" {
		t.Errorf("audit = %+v", a)
	}
	// No grant was created and a second show asks again.
	if gs, _ := e.g.List(context.Background()); len(gs) != 0 {
		t.Errorf("show created grants: %+v", gs)
	}
	wantOK(t, e.do(showReq(e)))
	if e.ap.calls() != 2 {
		t.Errorf("calls = %d", e.ap.calls())
	}
	// A run grant for the same secret does not satisfy show.
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	wantOK(t, e.do(showReq(e)))
	if e.ap.calls() != 4 {
		t.Errorf("calls = %d", e.ap.calls())
	}
}

func TestShowRefusals(t *testing.T) {
	e := newEnv(t)
	e.ap.allow = false
	w := e.do(showReq(e))
	wantFail(t, w, proto.ErrDenied, proto.ReasonUserDenied)
	if len(w.final.Result) != 0 {
		t.Error("denied show carries a result")
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionDeniedUser {
		t.Errorf("audit = %+v", a)
	}
	e.ap.allow, e.ap.err = true, context.DeadlineExceeded
	wantFail(t, e.do(showReq(e)), proto.ErrDenied, proto.ReasonApproverUnavailable)
	e.ap.err = nil

	r := showReq(e)
	r.Name = "MISSING"
	wantFail(t, e.do(r), proto.ErrNotFound, proto.ReasonSecretNotFound)
	r = showReq(e)
	r.Caller = "bad\x00caller"
	wantFail(t, e.do(r), proto.ErrBadRequest, proto.ReasonBadRequest)

	// tier
	n := e.calls()
	if err := e.v.Set(context.Background(), vaultMeta("HW", presence.TierHardware), []byte("hw-secret-12345"), false); err != nil {
		t.Fatal(err)
	}
	r = showReq(e)
	r.Name = "HW"
	wantFail(t, e.do(r), proto.ErrRefused, proto.ReasonTierUnmet)
	if e.calls() != n {
		t.Error("approver asked for tier-refused show")
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionRefusedTier {
		t.Errorf("audit = %+v", a)
	}

	// expired
	exp := e.now.Add(time.Minute)
	m := vaultMeta("EXP", presence.TierNone)
	m.ExpiresAt = &exp
	if err := e.v.Set(context.Background(), m, []byte("exp-secret-12345"), false); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	r = showReq(e)
	r.Name = "EXP"
	wantFail(t, e.do(r), proto.ErrRefused, proto.ReasonSecretExpired)
}

func (e *env) calls() int { return e.ap.calls() }

func TestShowCtxWhileWaiting(t *testing.T) {
	e := newEnv(t)
	e.ap.block = make(chan struct{})
	defer close(e.ap.block)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	wantFail(t, e.doCtx(ctx, showReq(e)), proto.ErrFailed, proto.ReasonTimeout)
}

func TestGrantsOps(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = time.Hour
	w1 := e.do(e.run([]string{"API_KEY"}, "true"))
	e.do(e.run([]string{"API_KEY"}, "false"))
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 2 {
		t.Fatalf("grants = %+v", gs)
	}
	if gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants})); len(gs) != 2 {
		t.Fatalf("bare grants = %+v", gs)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke}), proto.ErrBadRequest, proto.ReasonBadRequest)
	wantFail(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: "nope"}), proto.ErrNotFound, proto.ReasonGrantNotFound)
	wantOK(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: w1.final.GrantID}))
	if gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList})); len(gs) != 1 {
		t.Fatalf("grants after revoke = %+v", gs)
	}
	var st proto.StatusResult
	e.b.StatusFunc()(context.Background(), &st)
	if st.ActiveGrants != 1 {
		t.Errorf("status = %+v", st)
	}
	wantOK(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevokeAll}))
	if gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList})); len(gs) != 0 {
		t.Fatalf("grants after revoke all = %+v", gs)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpGrants, Action: "bogus"}), proto.ErrBadRequest, proto.ReasonBadRequest)

	// expired grants are not listed
	e.do(e.run([]string{"API_KEY"}, "true"))
	e.advance(2 * time.Hour)
	if gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList})); len(gs) != 0 {
		t.Fatalf("expired grant listed: %+v", gs)
	}
}

func TestAuditOps(t *testing.T) {
	e := newEnv(t)
	for range 3 {
		e.do(e.run([]string{"API_KEY"}, "true"))
	}
	l := decode[[]proto.AuditInfo](t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 2}))
	if len(l) != 2 || l[0].Decision != audit.DecisionCompleted || l[0].ExitCode == nil ||
		l[1].Decision != audit.DecisionAllowedOnce || l[1].Reason != ReasonReleased || l[1].ExitCode != nil {
		t.Fatalf("audit list = %+v", l)
	}
	if l := decode[[]proto.AuditInfo](t, e.do(&proto.Request{Op: proto.OpAudit})); len(l) != 6 {
		t.Fatalf("bare list = %d", len(l))
	}
	v := decode[proto.AuditVerifyResult](t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionVerify}))
	if !v.OK || v.Entries != 6 {
		t.Fatalf("verify = %+v", v)
	}
	csv := decode[proto.AuditExportResult](t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport})).CSV
	if !strings.Contains(csv, "allowed_once") || !strings.Contains(csv, "completed") || strings.Count(csv, "\n") != 7 {
		t.Fatalf("csv = %q", csv)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpAudit, Action: "bogus"}), proto.ErrBadRequest, proto.ReasonBadRequest)
}

func TestStatusFunc(t *testing.T) {
	e := newEnv(t)
	e.rebuild(presence.TierDialog)
	e.ap.tier = presence.TierHardware
	var st proto.StatusResult
	e.b.StatusFunc()(context.Background(), &st)
	if !st.VaultInitialized || st.KeyStoreTier != presence.TierDialog || st.ApproverTier != presence.TierHardware || st.Secrets != 1 || st.ActiveGrants != 0 {
		t.Errorf("status = %+v", st)
	}
}

func TestIncompleteTail(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want int
	}{
		{nil, 0}, {[]byte("abc"), 0}, {[]byte("é"), 0}, {[]byte("é")[:1], 1},
		{[]byte("€")[:1], 1}, {[]byte("€")[:2], 2}, {[]byte("€"), 0},
		{[]byte("😀")[:3], 3}, {[]byte{0xff}, 0}, {[]byte("a\xc3"), 1},
	} {
		if got := incompleteTail(c.in); got != c.want {
			t.Errorf("incompleteTail(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFrameWriterFlushOnClose(t *testing.T) {
	w := &recWriter{}
	f := &frameWriter{w: w, stream: proto.StreamStdout, onErr: func() {}}
	_, _ = f.Write([]byte("a\xc3"))
	_ = f.Close()
	if got := w.out("stdout"); got != "a\xc3" {
		t.Errorf("out = %q", got)
	}
	w = &recWriter{failAt: 1}
	f = &frameWriter{w: w, stream: proto.StreamStdout, onErr: func() {}}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("write error not propagated")
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("error not sticky")
	}
}

func TestInternalErrorsAreGeneric(t *testing.T) {
	e := newEnv(t)
	_ = e.v.Close()
	for _, r := range []*proto.Request{
		{Op: proto.OpList},
		{Op: proto.OpExists, Name: "API_KEY"},
		{Op: proto.OpMasked, Name: "API_KEY"},
		{Op: proto.OpSet, Name: "X", Value: "value-1234"},
		{Op: proto.OpDelete, Name: "API_KEY"},
		showReq(e),
		{Op: proto.OpGrants, Action: proto.ActionList},
		{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: "x"},
		{Op: proto.OpGrants, Action: proto.ActionRevokeAll},
		{Op: proto.OpAudit, Action: proto.ActionList},
		{Op: proto.OpAudit, Action: proto.ActionVerify},
		{Op: proto.OpAudit, Action: proto.ActionExport},
		e.run([]string{"API_KEY"}, "true"),
	} {
		w := e.do(r)
		if w.final.OK || w.final.Error != proto.ErrFailed || w.final.Reason != proto.ReasonInternal {
			t.Errorf("%s/%s: response = %+v", r.Op, r.Action, w.final)
		}
		if strings.Contains(w.final.Message, "sql") || strings.Contains(w.final.Message, "/") {
			t.Errorf("%s: message leaks internals: %q", r.Op, w.final.Message)
		}
	}
	var st proto.StatusResult
	e.b.StatusFunc()(context.Background(), &st)
	if st.Secrets != 0 {
		t.Errorf("status = %+v", st)
	}
}
