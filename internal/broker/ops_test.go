package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
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
	want := "audit,delete,exists,grants,list,masked,run,set,show,update"
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
		"NUL in value": {Op: proto.OpSet, Name: "X", Value: "abc\x00def"},
		"long url":     {Op: proto.OpSet, Name: "X", Value: "value-1234", URL: strings.Repeat("u", maxURLBytes+1)},
		"long notes":   {Op: proto.OpSet, Name: "X", Value: "value-1234", Notes: strings.Repeat("n", maxNotesBytes+1)},
		"bad tier":     {Op: proto.OpSet, Name: "X", Value: "value-1234", MinTier: &bad},
		"bad tag":      {Op: proto.OpSet, Name: "X", Value: "value-1234", Tags: []string{"no spaces"}},
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

func TestSetURLAndNotesAtTheLimitAreAccepted(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "X", Value: "value-1234",
		URL: strings.Repeat("u", maxURLBytes), Notes: strings.Repeat("n", maxNotesBytes)}))
	l := decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList}))
	for _, s := range l {
		if s.Name == "X" && (len(s.URL) != maxURLBytes || len(s.Notes) != maxNotesBytes) {
			t.Fatalf("stored %d/%d", len(s.URL), len(s.Notes))
		}
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
	l := decode[proto.AuditListResult](t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 2})).Entries
	if len(l) != 2 || l[0].Decision != audit.DecisionCompleted || l[0].ExitCode == nil ||
		l[1].Decision != audit.DecisionAllowedOnce || l[1].Reason != ReasonReleased || l[1].ExitCode != nil {
		t.Fatalf("audit list = %+v", l)
	}
	if l := decode[proto.AuditListResult](t, e.do(&proto.Request{Op: proto.OpAudit})).Entries; len(l) != 6 {
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
		{Op: proto.OpUpdate, Name: "API_KEY", Notes: "x"},
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

func TestForgedGrantRowIsIgnoredFlaggedAndCounted(t *testing.T) {
	e := newEnv(t)
	_, err := e.v.DB().Exec(`INSERT INTO grants (id, caller, cwd_prefix, secrets, cmd_prefix, created_at, expires_at, uses_remaining, mac) VALUES ('forged', 'tester', ?, '["API_KEY"]', '["true"]', ?, ?, NULL, x'00')`,
		e.cwd, e.now.UnixNano(), e.now.Add(time.Hour).UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	wantOK(t, e.do(e.run([]string{"API_KEY"}, "true")))
	if e.ap.calls() != 1 {
		t.Fatalf("forged grant skipped the approver (calls=%d)", e.ap.calls())
	}
	gs := decode[[]proto.GrantInfo](t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gs) != 1 || gs[0].ID != "forged" || !gs[0].Tampered {
		t.Fatalf("grants = %+v", gs)
	}
	var st proto.StatusResult
	e.b.StatusFunc()(context.Background(), &st)
	if st.TamperedGrants != 1 || st.ActiveGrants != 0 {
		t.Errorf("status = %+v", st)
	}
	wantOK(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: "forged"}))
}

// bigRow appends audit rows with a large reason so a listing or export has to
// give up rows to fit one protocol line.
func (e *env) bigRows(n int, reason string) {
	e.t.Helper()
	for range n {
		if _, err := e.a.Append(context.Background(), audit.Entry{Decision: audit.DecisionError, Reason: reason}); err != nil {
			e.t.Fatal(err)
		}
	}
}

func TestOkRefusesAResultThatCannotFitOneLine(t *testing.T) {
	w := &recWriter{}
	ok(w, strings.Repeat("x", maxResultBytes))
	wantFail(t, w, proto.ErrFailed, proto.ReasonResponseTooLarge)
	w = &recWriter{}
	ok(w, strings.Repeat("x", maxResultBytes-1024))
	wantOK(t, w)
}

// legacyRows writes audit rows straight into the table, as a build that did not
// bound its fields wrote them. The MACs are placeholders: nothing here verifies.
func (e *env) legacyRows(n int, argv []string, reason string) {
	e.t.Helper()
	av, _ := json.Marshal(argv)
	for range n {
		if _, err := e.v.DB().Exec(`INSERT INTO audit (ts, caller, cwd, argv, secrets, decision, reason, prev_hmac, hmac, enc)
VALUES ('2026-01-01T00:00:00Z','cli','/',?,'[]','error',?,x'00',x'00',2)`, string(av), reason); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) auditList(limit int, before string) proto.AuditListResult {
	e.t.Helper()
	w := e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: limit, BeforeID: before})
	wantOK(e.t, w)
	if len(w.final.Result) > maxResultBytes {
		e.t.Errorf("result is %d bytes", len(w.final.Result))
	}
	return decode[proto.AuditListResult](e.t, w)
}

func TestAuditListTruncatesInsteadOfOverflowingAndPages(t *testing.T) {
	e := newEnv(t)
	// A thousand rows at the reason cap are more than one protocol line.
	e.bigRows(1000, strings.Repeat("r", audit.MaxReason))
	res := e.auditList(1000, "")
	if !res.Truncated || len(res.Entries) == 0 || len(res.Entries) >= 1000 {
		t.Fatalf("entries=%d truncated=%v", len(res.Entries), res.Truncated)
	}
	if res.Entries[0].ID != "1000" { // newest first
		t.Errorf("first = %s", res.Entries[0].ID)
	}
	if last := res.Entries[len(res.Entries)-1].ID; res.NextBeforeID != last {
		t.Errorf("next_before_id = %q, last entry %q", res.NextBeforeID, last)
	}
	// A page that fits is not flagged.
	small := e.auditList(2, "")
	if small.Truncated || len(small.Entries) != 2 || small.NextBeforeID != "999" {
		t.Fatalf("small page: %+v", small)
	}
	// Walking back with next_before_id reaches every row exactly once.
	seen := map[string]bool{}
	before, pages := "", 0
	for {
		page := e.auditList(1000, before)
		pages++
		for _, en := range page.Entries {
			if seen[en.ID] {
				t.Fatalf("row %s returned twice", en.ID)
			}
			seen[en.ID] = true
		}
		if page.NextBeforeID == "" {
			break
		}
		before = page.NextBeforeID
	}
	if len(seen) != 1000 || pages < 2 {
		t.Fatalf("walked %d rows in %d pages", len(seen), pages)
	}
}

func TestAuditListBeforeID(t *testing.T) {
	e := newEnv(t)
	e.bigRows(5, "x")
	ids := func(r proto.AuditListResult) string {
		var s []string
		for _, en := range r.Entries {
			s = append(s, en.ID)
		}
		return strings.Join(s, ",")
	}
	if got := ids(e.auditList(10, "4")); got != "3,2,1" {
		t.Errorf("before 4 = %s", got)
	}
	if got := ids(e.auditList(2, "5")); got != "4,3" {
		t.Errorf("before 5 limit 2 = %s", got)
	}
	if r := e.auditList(10, "1"); len(r.Entries) != 0 || r.NextBeforeID != "" || r.Truncated {
		t.Errorf("before 1 = %+v", r)
	}
	for _, bad := range []string{"abc", "0", "-3", "1.5", "99999999999999999999"} {
		wantFail(t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, BeforeID: bad}), proto.ErrBadRequest, proto.ReasonBadRequest)
	}
}

func TestAuditListWalksPastOversizeLegacyRows(t *testing.T) {
	e := newEnv(t)
	e.bigRows(1, "old")
	e.legacyRows(3, []string{"true", strings.Repeat("a", 1<<20)}, strings.Repeat("r", 1<<20))
	e.bigRows(1, "new")
	res := e.auditList(10, "")
	if res.Truncated || res.Skipped != 0 || len(res.Entries) != 5 {
		t.Fatalf("truncated=%v skipped=%d entries=%d", res.Truncated, res.Skipped, len(res.Entries))
	}
	for _, en := range res.Entries[1:4] {
		if en.Argv[len(en.Argv)-1] != audit.TruncatedMarker || !strings.HasSuffix(en.Reason, audit.TruncatedMarker) {
			t.Errorf("row %s was not shortened and marked: %d argv, reason %d bytes", en.ID, len(en.Argv), len(en.Reason))
		}
	}
	if res.Entries[0].Reason != "new" || res.Entries[4].Reason != "old" {
		t.Errorf("ordinary rows altered: %q %q", res.Entries[0].Reason, res.Entries[4].Reason)
	}
}

func TestAuditListSkipsARowThatCannotBeShortenedEnough(t *testing.T) {
	e := newEnv(t)
	e.bigRows(3, "r")
	old := maxAuditRowBytes
	maxAuditRowBytes = 100 // every row is too large, even shortened
	defer func() { maxAuditRowBytes = old }()
	res := e.auditList(10, "")
	if res.Skipped != 3 || len(res.Entries) != 0 || res.NextBeforeID != "1" {
		t.Fatalf("result = %+v", res)
	}
	// With a limit the client still moves on: the walk is not stuck on the row.
	res = e.auditList(2, "")
	if res.Skipped != 2 || res.NextBeforeID != "2" {
		t.Fatalf("result = %+v", res)
	}
	if next := e.auditList(2, res.NextBeforeID); next.Skipped != 1 || next.NextBeforeID != "1" {
		t.Fatalf("next page = %+v", next)
	}
}

func TestAuditExportLimitIsOnTheEncodedLength(t *testing.T) {
	// Raw CSV well under the limit, but every quote becomes "" in CSV and \"\"
	// in the JSON string: only the encoded length is too big.
	e := newEnv(t)
	e.bigRows(300, strings.Repeat(`"`, 4000))
	var raw bytes.Buffer
	if err := e.a.ExportCSV(context.Background(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Len() > maxResultBytes {
		t.Fatalf("setup: raw CSV is already %d bytes", raw.Len())
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport}), proto.ErrFailed, proto.ReasonResponseTooLarge)

	// A raw CSV beyond the limit is refused without being collected whole.
	e2 := newEnv(t)
	e2.bigRows(1100, strings.Repeat("r", audit.MaxReason))
	wantFail(t, e2.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport}), proto.ErrFailed, proto.ReasonResponseTooLarge)
}

func TestAuditExportSurvivesOversizeLegacyRows(t *testing.T) {
	e := newEnv(t)
	e.legacyRows(4, []string{"true", strings.Repeat("a", 1<<20)}, strings.Repeat("r", 1<<20))
	w := e.do(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport})
	wantOK(t, w)
	if csv := decode[proto.AuditExportResult](t, w).CSV; !strings.Contains(csv, audit.TruncatedMarker) {
		t.Errorf("export does not mark the shortened rows")
	}
}

func listInfo(t *testing.T, e *env, name string) proto.SecretInfo {
	t.Helper()
	for _, s := range decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList})) {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("%s not listed", name)
	return proto.SecretInfo{}
}

func TestUpdateChangesMetadataNotTheValue(t *testing.T) {
	e := newEnv(t)
	exp := time.Now().Add(48 * time.Hour)
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "AKIA-0123456789-WXYZ",
		Tags: []string{"prod"}, URL: "https://x", Notes: "n", Expires: &exp}))
	before := listInfo(t, e, "aws/key")

	// any subset: only tags
	w := e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", Tags: []string{"b", "a", "b"}})
	wantOK(t, w)
	if a := e.lastAudit(); a.Decision != audit.DecisionAllowedOnce || a.Reason != "update" || strings.Join(a.Argv, " ") != "grantd update aws/key" || a.ID != w.final.AuditID {
		t.Errorf("audit = %+v (audit_id %q)", a, w.final.AuditID)
	}
	got := listInfo(t, e, "aws/key")
	if strings.Join(got.Tags, ",") != "a,b" || got.URL != "https://x" || got.Notes != "n" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(*before.ExpiresAt) {
		t.Errorf("after tags update: %+v", got)
	}
	if !got.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("created_at changed")
	}
	// the value is untouched
	if m := decode[proto.MaskedResult](t, e.do(&proto.Request{Op: proto.OpMasked, Name: "aws/key"})).Masked; m != "****WXYZ" {
		t.Errorf("masked = %q", m)
	}

	// several fields at once, a new expiry
	later := time.Now().Add(96 * time.Hour)
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", URL: "https://y", Notes: "m", Expires: &later}))
	got = listInfo(t, e, "aws/key")
	if got.URL != "https://y" || got.Notes != "m" || got.ExpiresAt == nil || got.ExpiresAt.Sub(later).Abs() > time.Second || strings.Join(got.Tags, ",") != "a,b" {
		t.Errorf("after multi update: %+v", got)
	}

	// clear fields
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", Clear: []string{"expires", "url", "notes", "tags"}}))
	got = listInfo(t, e, "aws/key")
	if got.ExpiresAt != nil || got.URL != "" || got.Notes != "" || len(got.Tags) != 0 {
		t.Errorf("after clear: %+v", got)
	}
	if n := len(decode[[]proto.SecretInfo](t, e.do(&proto.Request{Op: proto.OpList, Tag: "a"}))); n != 0 {
		t.Errorf("tag filter still matches: %d", n)
	}
}

func TestUpdateMinTierReencryptsAndKeepsValue(t *testing.T) {
	e := newEnv(t)
	hw, dialog := presence.TierHardware, presence.TierDialog
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "k", Value: "value-0123456789-ABCD", MinTier: &hw}))
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &dialog}))
	if got := listInfo(t, e, "k"); got.MinTier != presence.TierDialog {
		t.Errorf("min_tier = %v", got.MinTier)
	}
	if m := decode[proto.MaskedResult](t, e.do(&proto.Request{Op: proto.OpMasked, Name: "k"})).Masked; m != "****ABCD" {
		t.Errorf("masked after tier change = %q", m)
	}
	// the keystore here is tier none, so a hardware secret is refused on use;
	// lowering it to the vault default (none) re-encrypts and a run releases it
	// (the tier is bound into the ciphertext, so a stale seal could not decrypt).
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &hw}))
	wantFail(t, e.do(e.run([]string{"k"}, "true")), proto.ErrRefused, proto.ReasonTierUnmet)
	none := presence.TierNone
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &none}))
	if w := e.do(e.run([]string{"k"}, "true")); w.final == nil || !w.final.OK {
		t.Errorf("run after lowering the tier: %+v", w.final)
	}
}

func TestUpdateValidation(t *testing.T) {
	e := newEnv(t)
	past := time.Now().Add(-time.Hour)
	soon := time.Now().Add(time.Hour)
	bad := presence.PresenceTier(9)
	for name, r := range map[string]*proto.Request{
		"bad name":        {Op: proto.OpUpdate, Name: "a//b", Notes: "x"},
		"empty name":      {Op: proto.OpUpdate, Name: "", Notes: "x"},
		"nothing":         {Op: proto.OpUpdate, Name: "API_KEY"},
		"value":           {Op: proto.OpUpdate, Name: "API_KEY", Value: "new-value-1234"},
		"overwrite":       {Op: proto.OpUpdate, Name: "API_KEY", Overwrite: true, Notes: "x"},
		"long url":        {Op: proto.OpUpdate, Name: "API_KEY", URL: strings.Repeat("u", maxURLBytes+1)},
		"long notes":      {Op: proto.OpUpdate, Name: "API_KEY", Notes: strings.Repeat("n", maxNotesBytes+1)},
		"bad tier":        {Op: proto.OpUpdate, Name: "API_KEY", MinTier: &bad},
		"past expires":    {Op: proto.OpUpdate, Name: "API_KEY", Expires: &past},
		"bad tag":         {Op: proto.OpUpdate, Name: "API_KEY", Tags: []string{"no spaces"}},
		"unknown clear":   {Op: proto.OpUpdate, Name: "API_KEY", Clear: []string{"value"}},
		"set and clear":   {Op: proto.OpUpdate, Name: "API_KEY", Expires: &soon, Clear: []string{"expires"}},
		"tags set+clear":  {Op: proto.OpUpdate, Name: "API_KEY", Tags: []string{"a"}, Clear: []string{"tags"}},
		"notes set+clear": {Op: proto.OpUpdate, Name: "API_KEY", Notes: "a", Clear: []string{"notes"}},
		"url set+clear":   {Op: proto.OpUpdate, Name: "API_KEY", URL: "a", Clear: []string{"url"}},
		"too many tags":   {Op: proto.OpUpdate, Name: "API_KEY", Tags: manyTags(33)},
	} {
		w := e.do(r)
		if w.final == nil || w.final.OK || w.final.Error != proto.ErrBadRequest {
			t.Errorf("%s: response = %+v", name, w.final)
		}
	}
	// nothing above changed or audited anything
	if info := listInfo(t, e, "API_KEY"); len(info.Tags) != 0 || info.Notes != "" || info.ExpiresAt != nil {
		t.Errorf("rejected updates changed the secret: %+v", info)
	}
	wantFail(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "nope", Notes: "x"}), proto.ErrNotFound, proto.ReasonSecretNotFound)
}

func manyTags(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "t" + strings.Repeat("x", i)
	}
	return out
}

func TestUpdateNeverPromptsOrReturnsTheValue(t *testing.T) {
	e := newEnv(t)
	w := e.do(&proto.Request{Op: proto.OpUpdate, Name: "API_KEY", Notes: "rotated"})
	wantOK(t, w)
	if e.ap.calls() != 0 {
		t.Errorf("approver asked %d times", e.ap.calls())
	}
	if b, _ := marshalAll(w); strings.Contains(b, e.secret) {
		t.Error("update response leaked the value")
	}
}

func TestUpdateLoweringTheTierNeedsApproval(t *testing.T) {
	e := newEnv(t)
	hw, dialog, none := presence.TierHardware, presence.TierDialog, presence.TierNone
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "k", Value: "value-0123456789-ABCD", MinTier: &hw}))
	e.ap.reqs = nil

	// hardware -> dialog asks, with the secret and both levels in the request.
	w := e.do(&proto.Request{Op: proto.OpUpdate, Caller: "grantd-app", Name: "k", MinTier: &dialog, Notes: "n"})
	wantOK(t, w)
	if e.ap.calls() != 1 {
		t.Fatalf("approver asked %d times", e.ap.calls())
	}
	r := e.ap.last()
	if r.Kind != approve.KindLowerTier || r.FromTier != hw || r.ToTier != dialog ||
		strings.Join(r.Secrets, ",") != "k" || r.Caller != "grantd-app" {
		t.Errorf("approval request = %+v", r)
	}
	if a := e.lastAudit(); a.Decision != audit.DecisionAllowedOnce || a.Reason != "update: lower min_tier" || a.ID != w.final.AuditID {
		t.Errorf("audit = %+v", a)
	}
	if got := listInfo(t, e, "k"); got.MinTier != dialog || got.Notes != "n" {
		t.Errorf("after approved lowering: %+v", got)
	}

	// dialog -> none (the vault default in this env) asks again.
	e.ap.reqs = nil
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &none}))
	if e.ap.calls() != 1 || e.ap.last().FromTier != dialog || e.ap.last().ToTier != none {
		t.Errorf("none did not ask as a lowering: %+v", e.ap.reqs)
	}
}

func TestUpdateRaisingOrKeepingTheTierNeverAsks(t *testing.T) {
	e := newEnv(t)
	hw, dialog, none := presence.TierHardware, presence.TierDialog, presence.TierNone
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "k", Value: "value-0123456789-ABCD", MinTier: &dialog}))
	e.ap.reqs = nil
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &hw}))      // raise
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &hw}))      // same
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", Notes: "metadata"})) // no tier
	if e.ap.calls() != 0 {
		t.Errorf("approver asked %d times", e.ap.calls())
	}
	if a := e.lastAudit(); a.Reason != "update" {
		t.Errorf("audit reason = %q, want a plain update", a.Reason)
	}
	// A secret already at the vault default: none is no change.
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "d", Value: "value-0123456789-ABCD"}))
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "d", MinTier: &none}))
	if e.ap.calls() != 0 {
		t.Errorf("approver asked for a no-op tier change")
	}
}

func TestUpdateLoweringRefusedChangesNothing(t *testing.T) {
	hw, dialog := presence.TierHardware, presence.TierDialog
	for name, tc := range map[string]struct {
		setup    func(*fakeApprover)
		category string
		reason   string
		decision string
		suffix   string
	}{
		"denied":      {func(a *fakeApprover) { a.allow, a.reason = false, "user denied" }, proto.ErrDenied, proto.ReasonUserDenied, audit.DecisionDeniedUser, ": user denied"},
		"unavailable": {func(a *fakeApprover) { a.err = errors.New("no gui") }, proto.ErrDenied, proto.ReasonApproverUnavailable, audit.DecisionError, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "k", Value: "value-0123456789-ABCD", MinTier: &hw, Notes: "old"}))
			tc.setup(e.ap)
			w := e.do(&proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &dialog, Notes: "new"})
			wantFail(t, w, tc.category, tc.reason)
			a := e.lastAudit()
			if a.Decision != tc.decision || a.Reason != "update: lower min_tier"+tc.suffix || a.ID != w.final.AuditID {
				t.Errorf("audit = %+v", a)
			}
			// neither the tier nor the other fields of the same request changed
			if got := listInfo(t, e, "k"); got.MinTier != hw || got.Notes != "old" {
				t.Errorf("refused update changed the secret: %+v", got)
			}
		})
	}
}

func TestUpdateLoweringNotFoundAndCancelled(t *testing.T) {
	e := newEnv(t)
	dialog := presence.TierDialog
	wantFail(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "nope", MinTier: &dialog}), proto.ErrNotFound, proto.ReasonSecretNotFound)
	if e.ap.calls() != 0 {
		t.Error("asked about a secret that does not exist")
	}
	// A client that goes away while the dialog is open: failed/canceled, nothing changes.
	hw := presence.TierHardware
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "k", Value: "value-0123456789-ABCD", MinTier: &hw}))
	e.ap.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	e.ap.onAsk = cancel
	w := e.doCtx(ctx, &proto.Request{Op: proto.OpUpdate, Name: "k", MinTier: &dialog})
	if w.final == nil || w.final.OK || w.final.Error != proto.ErrFailed {
		t.Fatalf("response = %+v", w.final)
	}
	if got := listInfo(t, e, "k"); got.MinTier != hw {
		t.Errorf("cancelled update changed the tier: %+v", got)
	}
}

// url, notes and tags are shown on a terminal by `grantd list`: characters that
// drive a terminal or reorder text are refused at the daemon.
func TestSetAndUpdateRejectTerminalControlsInMetadata(t *testing.T) {
	e := newEnv(t)
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "AKIA-0123456789-WXYZ", URL: "https://ok.example", Notes: "fine"}))
	before := listInfo(t, e, "aws/key")
	rows := e.auditCount()

	bad := []string{
		"a\x1b[2Jb", "a\x1b]0;title\x07", "a\nb", "a\rb", "a\tb", "a\x00b", "a\x7fb", "a\u009bb",
		"a\u202eb", "a\u202ab", "a\u202bb", "a\u202cb", "a\u202db", "a\u2066b", "a\u2067b", "a\u2068b", "a\u2069b",
	}
	for _, s := range bad {
		for field, mk := range map[string]func(op string) *proto.Request{
			"url": func(op string) *proto.Request {
				return &proto.Request{Op: op, Name: "aws/key", Value: "v-0123456789-ABCD", URL: s}
			},
			"notes": func(op string) *proto.Request {
				return &proto.Request{Op: op, Name: "aws/key", Value: "v-0123456789-ABCD", Notes: s}
			},
			"tags": func(op string) *proto.Request {
				return &proto.Request{Op: op, Name: "aws/key", Value: "v-0123456789-ABCD", Tags: []string{s}}
			},
		} {
			if field == "notes" && (s == "a\nb" || s == "a\tb") {
				continue // notes may hold line feeds and tabs (see the test below)
			}
			set := mk(proto.OpSet)
			set.Overwrite = true
			wantFail(t, e.do(set), proto.ErrBadRequest, proto.ReasonBadRequest)
			upd := mk(proto.OpUpdate)
			upd.Value = ""
			wantFail(t, e.do(upd), proto.ErrBadRequest, proto.ReasonBadRequest)
		}
	}
	// Nothing changed and nothing was audited.
	after := listInfo(t, e, "aws/key")
	if after.URL != before.URL || after.Notes != before.Notes || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("metadata changed: %+v -> %+v", before, after)
	}
	if e.auditCount() != rows {
		t.Error("rejected requests were audited as successes")
	}
	w := e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", URL: "a\x1bb"})
	if !strings.Contains(w.final.Message, "url") {
		t.Errorf("message does not name the field: %q", w.final.Message)
	}

	// Ordinary text, including non-ASCII and characters next to the banned ranges, is fine.
	for _, s := range []string{"https://例え.jp/path?q=1&r=%1B", "naïve — café ✓ 😀", "a\u202fb\u2065c\u206ad"} {
		wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", URL: s, Notes: s}))
	}
}

// notes is a multi-line field in the app: line feeds and tabs are allowed there
// (and only there); every other control character is still refused.
func TestNotesMayHoldLineBreaks(t *testing.T) {
	e := newEnv(t)
	multi := "first line\n\tindented second line\n\nlast line \u00e9\u20ac"
	wantOK(t, e.do(&proto.Request{Op: proto.OpSet, Name: "aws/key", Value: "AKIA-0123456789-WXYZ", Notes: multi}))
	if got := listInfo(t, e, "aws/key").Notes; got != multi {
		t.Errorf("notes = %q", got)
	}
	multi2 := "a\nb\tc"
	wantOK(t, e.do(&proto.Request{Op: proto.OpUpdate, Name: "aws/key", Notes: multi2}))
	if got := listInfo(t, e, "aws/key").Notes; got != multi2 {
		t.Errorf("notes after update = %q", got)
	}
	// The strict rule still holds for url and tags, and for other controls and CR in notes.
	for _, r := range []*proto.Request{
		{Op: proto.OpUpdate, Name: "aws/key", URL: "https://x\n/y"},
		{Op: proto.OpUpdate, Name: "aws/key", URL: "https://x\t/y"},
		{Op: proto.OpUpdate, Name: "aws/key", Tags: []string{"a\nb"}},
		{Op: proto.OpUpdate, Name: "aws/key", Notes: "a\r\nb"},
		{Op: proto.OpUpdate, Name: "aws/key", Notes: "a\x1b[2Jb"},
		{Op: proto.OpUpdate, Name: "aws/key", Notes: "a\u009bb"},
		{Op: proto.OpUpdate, Name: "aws/key", Notes: "a\x7fb"},
		{Op: proto.OpUpdate, Name: "aws/key", Notes: "line\n\u202eb"},
	} {
		wantFail(t, e.do(r), proto.ErrBadRequest, proto.ReasonBadRequest)
	}
	if got := listInfo(t, e, "aws/key").Notes; got != multi2 {
		t.Errorf("notes changed by a refused update: %q", got)
	}
}

func TestGrantRevocationsAreAudited(t *testing.T) {
	e := newEnv(t)
	e.ap.ttl = time.Hour
	g1 := e.do(e.run([]string{"API_KEY"}, "true")).final.GrantID
	g2 := e.do(e.run([]string{"API_KEY"}, "false")).final.GrantID
	g3 := e.do(e.run([]string{"API_KEY"}, "echo")).final.GrantID

	count := func() int {
		es, err := e.a.List(context.Background(), 1000, 0)
		if err != nil {
			t.Fatal(err)
		}
		return len(es)
	}

	// An unknown ID writes nothing.
	before := count()
	wantFail(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: "nope", Caller: "agent"}), proto.ErrNotFound, proto.ReasonGrantNotFound)
	if count() != before {
		t.Fatal("a failed revoke wrote an audit row")
	}

	w := e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: g1, Caller: "agent"})
	wantOK(t, w)
	a := e.lastAudit()
	if w.final.AuditID != a.ID || a.Decision != audit.DecisionAllowedOnce || a.Reason != "grants revoke" || a.GrantID != g1 ||
		a.Caller != "agent" || strings.Join(a.Argv, " ") != "grantd grants revoke "+g1 {
		t.Errorf("revoke audit = %+v (response %+v)", a, w.final)
	}

	before = count()
	w = e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevokeAll})
	wantOK(t, w)
	es, err := e.a.List(context.Background(), count()-before, 0)
	if err != nil || len(es) != 2 {
		t.Fatalf("rows for revoke_all = %+v %v", es, err)
	}
	ids := map[string]bool{}
	for _, r := range es {
		if r.Decision != audit.DecisionAllowedOnce || r.Reason != "grants revoke_all" || r.Caller != DefaultCaller {
			t.Errorf("revoke_all audit = %+v", r)
		}
		ids[r.GrantID] = true
	}
	if !ids[g2] || !ids[g3] || len(ids) != 2 || w.final.AuditID != es[0].ID {
		t.Errorf("revoked ids = %v (want %s, %s), audit_id = %q", ids, g2, g3, w.final.AuditID)
	}

	// Nothing left to revoke still leaves a trace of the attempt.
	before = count()
	wantOK(t, e.do(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevokeAll}))
	if count() != before+1 {
		t.Fatalf("empty revoke_all rows = %d", count()-before)
	}
	if a := e.lastAudit(); a.Reason != "grants revoke_all" || a.GrantID != "" || strings.Join(a.Argv, " ") != "grantd grants revoke --all" {
		t.Errorf("empty revoke_all audit = %+v", a)
	}
}
