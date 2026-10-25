//go:build grantd_dev

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	devap "grantd/internal/approve/dev"
	"grantd/internal/audit"
	"grantd/internal/broker"
	"grantd/internal/client"
	"grantd/internal/daemon"
	"grantd/internal/grant"
	devks "grantd/internal/keystore/dev"
	"grantd/internal/presence"
	"grantd/internal/proto"
	"grantd/internal/vault"
)

const apiKey = "sk_live_0123456789_SUPERSECRET"

// rig is a running daemon plus handles to its approver.
type rig struct {
	t    *testing.T
	sock string
	ap   *devap.Approver
	cwd  string
}

// reply is everything one exchange put on the wire.
type reply struct {
	raw    []byte // exact bytes the daemon wrote
	stdout string
	stderr string
	resp   *proto.Response
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir, err := os.MkdirTemp("/tmp", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	ks := devks.New()
	v, err := vault.Init(ctx, filepath.Join(dir, "vault", "vault.db"), ks, vault.WithDefaultMinTier(ks.Tier()))
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Migrate(ctx, v.DB()); err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(ctx, v.DB(), v.DeriveKey("audit-hmac"))
	if err != nil {
		t.Fatal(err)
	}
	ap := devap.New(true)
	b, err := broker.New(broker.Deps{Vault: v, Grants: grant.NewStore(v.DB()), Audit: al, Approver: ap, KeyStoreTier: ks.Tier()})
	if err != nil {
		t.Fatal(err)
	}
	r := daemon.NewRouter()
	b.Register(r)
	sock := filepath.Join(dir, "s.sock")
	srv, err := daemon.New(daemon.Config{SocketPath: sock, Router: r, StatusFunc: b.StatusFunc(), Version: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = v.Close()
	})

	cwd, err := filepath.EvalSymlinks(filepath.Join(dir))
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(cwd, "proj")
	if err := os.Mkdir(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, sock: sock, ap: ap, cwd: proj}
}

// call drives the wire protocol directly and records the raw bytes.
func (r *rig) call(req *proto.Request) reply {
	r.t.Helper()
	if req.V == 0 {
		req.V = proto.Version
	}
	conn, err := net.DialTimeout("unix", r.sock, 5*time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.Write(conn, req); err != nil {
		r.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	raw, err := io.ReadAll(conn) // the daemon closes after the final response
	if err != nil {
		r.t.Fatalf("read: %v", err)
	}
	rep := reply{raw: raw}
	rd := proto.NewReader(bytes.NewReader(raw))
	for {
		m, err := rd.ReadMessage()
		if err != nil {
			break
		}
		if m.Frame != nil {
			if m.Frame.Stream == proto.StreamStdout {
				rep.stdout += m.Frame.Data
			} else {
				rep.stderr += m.Frame.Data
			}
		} else {
			rep.resp = m.Response
		}
	}
	if rep.resp == nil {
		r.t.Fatalf("no final response in %q", raw)
	}
	return rep
}

func (r *rig) set(name, value string, mut ...func(*proto.Request)) {
	r.t.Helper()
	req := &proto.Request{Op: proto.OpSet, Name: name, Value: value}
	for _, m := range mut {
		m(req)
	}
	if rep := r.call(req); !rep.resp.OK {
		r.t.Fatalf("set %s: %+v", name, rep.resp)
	}
}

func (r *rig) run(secrets []string, argv ...string) reply {
	return r.call(&proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: r.cwd, Argv: argv, Secrets: secrets})
}

func (r *rig) asked() int { return len(r.ap.Requests()) }

func (r *rig) noLeak(rep reply) {
	r.t.Helper()
	if bytes.Contains(rep.raw, []byte(apiKey)) {
		r.t.Fatalf("raw socket bytes contain the secret value: %q", rep.raw)
	}
}

func result[T any](t *testing.T, rep reply) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rep.resp.Result, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func wantErr(t *testing.T, rep reply, category, reason string) {
	t.Helper()
	if rep.resp.OK || rep.resp.Error != category || rep.resp.Reason != reason {
		t.Fatalf("response = %+v, want %s/%s", rep.resp, category, reason)
	}
}

func lastAudit(t *testing.T, r *rig) proto.AuditInfo {
	t.Helper()
	l := result[[]proto.AuditInfo](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 1}))
	if len(l) != 1 {
		t.Fatalf("audit list = %+v", l)
	}
	return l[0]
}

func TestRunRedactsBothStreamsAndNeverLeaksOnTheWire(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)

	rep := r.run([]string{"API_KEY"}, "sh", "-c", "echo $API_KEY; echo $API_KEY >&2")
	if !rep.resp.OK || *rep.resp.ExitCode != 0 {
		t.Fatalf("response = %+v", rep.resp)
	}
	if rep.stdout != "[REDACTED:API_KEY]\n" || rep.stderr != "[REDACTED:API_KEY]\n" {
		t.Fatalf("stdout=%q stderr=%q", rep.stdout, rep.stderr)
	}
	r.noLeak(rep)

	// Even output that tries to dodge chunking: value emitted byte by byte.
	rep = r.run([]string{"API_KEY"}, "sh", "-c", `v="$API_KEY"; while [ -n "$v" ]; do printf '%s' "${v%"${v#?}"}"; v="${v#?}"; done; echo`)
	if rep.stdout != "[REDACTED:API_KEY]\n" {
		t.Fatalf("byte-by-byte stdout = %q", rep.stdout)
	}
	r.noLeak(rep)

	// Error responses and every non-show op stay value-free too.
	for _, req := range []*proto.Request{
		{Op: proto.OpList},
		{Op: proto.OpExists, Name: "API_KEY"},
		{Op: proto.OpMasked, Name: "API_KEY"},
		{Op: proto.OpGrants, Action: proto.ActionList},
		{Op: proto.OpAudit, Action: proto.ActionList},
		{Op: proto.OpAudit, Action: proto.ActionExport},
		{Op: proto.OpAudit, Action: proto.ActionVerify},
		{Op: proto.OpStatus},
		{Op: proto.OpRun, Cwd: r.cwd, Argv: []string{"definitely-not-a-command"}, Secrets: []string{"API_KEY"}},
		{Op: proto.OpRun, Cwd: r.cwd, Argv: []string{apiKey}, Secrets: []string{"API_KEY"}},
		{Op: proto.OpRun, Cwd: r.cwd, Argv: []string{"true"}, Secrets: []string{"MISSING"}},
		{Op: proto.OpSet, Name: "API_KEY", Value: apiKey}, // duplicate: error must not echo the value
	} {
		r.noLeak(r.call(req))
	}
	// The audit log never holds it either (argv containing the value was scrubbed).
	for _, e := range result[[]proto.AuditInfo](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 100})) {
		if strings.Contains(strings.Join(e.Argv, " ")+e.Reason, apiKey) {
			t.Errorf("audit entry holds the value: %+v", e)
		}
	}
}

func TestDenyIsAuditedAndNothingRuns(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.SetAllow(false)
	marker := filepath.Join(r.cwd, "ran")
	rep := r.run([]string{"API_KEY"}, "sh", "-c", "touch "+marker)
	wantErr(t, rep, proto.ErrDenied, proto.ReasonUserDenied)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran despite denial")
	}
	a := lastAudit(t, r)
	if a.Decision != audit.DecisionDeniedUser || a.Caller != "e2e" || a.Cwd != r.cwd || a.ExitCode != nil {
		t.Fatalf("audit = %+v", a)
	}
	if rep.resp.AuditID != a.ID {
		t.Errorf("audit id %q != %q", rep.resp.AuditID, a.ID)
	}
}

func TestAllowForAnHourCreatesAGrantUsedWithoutAsking(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.TTL = time.Hour

	first := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if !first.resp.OK || first.resp.GrantID == "" {
		t.Fatalf("first = %+v", first.resp)
	}
	if got := lastAudit(t, r); got.Decision != audit.DecisionAllowedNewGrant || got.GrantID != first.resp.GrantID {
		t.Fatalf("audit = %+v", got)
	}
	if r.asked() != 1 {
		t.Fatalf("asked %d", r.asked())
	}

	second := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if !second.resp.OK || second.resp.GrantID != first.resp.GrantID {
		t.Fatalf("second = %+v", second.resp)
	}
	if r.asked() != 1 {
		t.Fatalf("grant not used: approver asked %d times", r.asked())
	}
	if got := lastAudit(t, r); got.Decision != audit.DecisionAllowedGrant {
		t.Fatalf("audit = %+v", got)
	}

	// Different cwd: asked again.
	other := filepath.Join(filepath.Dir(r.cwd), "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	rep := r.call(&proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: other, Argv: []string{"sh", "-c", "exit 0"}, Secrets: []string{"API_KEY"}})
	if !rep.resp.OK || r.asked() != 2 {
		t.Fatalf("other cwd: %+v asked=%d", rep.resp, r.asked())
	}
	// Different caller: asked again.
	rep = r.call(&proto.Request{Op: proto.OpRun, Caller: "someone-else", Cwd: r.cwd, Argv: []string{"sh", "-c", "exit 0"}, Secrets: []string{"API_KEY"}})
	if !rep.resp.OK || r.asked() != 3 {
		t.Fatalf("other caller: %+v asked=%d", rep.resp, r.asked())
	}

	// grants list shows them; revoke --all makes the next run ask again.
	gl := result[[]proto.GrantInfo](t, r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gl) != 3 {
		t.Fatalf("grants = %+v", gl)
	}
	if rep := r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevokeAll}); !rep.resp.OK {
		t.Fatalf("revoke all: %+v", rep.resp)
	}
	before := r.asked()
	if rep := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0"); !rep.resp.OK {
		t.Fatalf("after revoke: %+v", rep.resp)
	}
	if r.asked() != before+1 {
		t.Fatalf("approver not asked after revoke --all (asked %d, before %d)", r.asked(), before)
	}
}

func TestPolicyRefusalNeverReachesTheApprover(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.set("OTHER", "other-secret-value-123")
	policy := "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [sh, -c]\nmax_grant_ttl: 10m\n"
	if err := os.WriteFile(filepath.Join(r.cwd, ".grantd.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	rep := r.run([]string{"OTHER"}, "sh", "-c", "true")
	wantErr(t, rep, proto.ErrRefused, proto.ReasonPolicyRefused)
	if !strings.Contains(rep.resp.Message, "OTHER") {
		t.Errorf("message = %q", rep.resp.Message)
	}
	rep = r.run([]string{"API_KEY"}, "curl", "http://example.invalid")
	wantErr(t, rep, proto.ErrRefused, proto.ReasonPolicyRefused)
	if r.asked() != 0 {
		t.Fatalf("approver asked %d times for policy-refused requests", r.asked())
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionRefusedPolicy {
		t.Fatalf("audit = %+v", a)
	}

	// A permitted request is prompted, with the policy flag and TTL cap.
	if rep := r.run([]string{"API_KEY"}, "sh", "-c", "true"); !rep.resp.OK {
		t.Fatalf("permitted run: %+v", rep.resp)
	}
	req := r.ap.Requests()[0]
	if !req.PolicyPresent || req.SuggestedTTL != 10*time.Minute {
		t.Errorf("approval request = %+v", req)
	}
}

func TestMinTierHardwareIsRefusedOnTierNoneBackends(t *testing.T) {
	r := newRig(t)
	hw := presence.TierHardware
	r.set("HW_KEY", apiKey, func(q *proto.Request) { q.MinTier = &hw })

	rep := r.run([]string{"HW_KEY"}, "true")
	wantErr(t, rep, proto.ErrRefused, proto.ReasonTierUnmet)
	if r.asked() != 0 {
		t.Fatal("approver asked for a tier-refused request")
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionRefusedTier {
		t.Fatalf("audit = %+v", a)
	}
	// show is refused the same way.
	rep = r.call(&proto.Request{Op: proto.OpShow, Name: "HW_KEY", Cwd: r.cwd})
	wantErr(t, rep, proto.ErrRefused, proto.ReasonTierUnmet)
	if r.asked() != 0 {
		t.Fatal("approver asked for a tier-refused show")
	}
	r.noLeak(rep)
}

func TestShowIsPresenceGatedEveryTime(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.TTL = time.Hour // a TTL on a show approval must not create a grant

	rep := r.call(&proto.Request{Op: proto.OpShow, Name: "API_KEY", Caller: "cli", Cwd: r.cwd})
	if !rep.resp.OK || result[proto.ShowResult](t, rep).Value != apiKey {
		t.Fatalf("show = %+v", rep.resp)
	}
	reqs := r.ap.Requests()
	if len(reqs) != 1 || strings.Join(reqs[0].Argv, " ") != "grantd show API_KEY" || strings.Join(reqs[0].Secrets, ",") != "API_KEY" {
		t.Fatalf("approval requests = %+v", reqs)
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionAllowedOnce || a.Reason != "show" {
		t.Fatalf("audit = %+v", a)
	}
	if gl := result[[]proto.GrantInfo](t, r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList})); len(gl) != 0 {
		t.Fatalf("show created grants: %+v", gl)
	}
	r.call(&proto.Request{Op: proto.OpShow, Name: "API_KEY", Cwd: r.cwd})
	if r.asked() != 2 {
		t.Fatalf("second show did not ask: %d", r.asked())
	}

	r.ap.SetAllow(false)
	rep = r.call(&proto.Request{Op: proto.OpShow, Name: "API_KEY", Cwd: r.cwd})
	wantErr(t, rep, proto.ErrDenied, proto.ReasonUserDenied)
	r.noLeak(rep)
}

func TestTimeoutExits124(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	start := time.Now()
	rep := r.call(&proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: r.cwd, Argv: []string{"sleep", "5"}, Secrets: []string{"API_KEY"}, TimeoutS: 1})
	if !rep.resp.OK || *rep.resp.ExitCode != 124 {
		t.Fatalf("response = %+v", rep.resp)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("took %s", d)
	}
	if a := lastAudit(t, r); a.ExitCode == nil || *a.ExitCode != 124 {
		t.Fatalf("audit = %+v", a)
	}
}

func TestClientDisconnectKillsTheChild(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	marker := filepath.Join(r.cwd, "still-running")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.Call(ctx, r.sock, &proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: r.cwd,
			Argv: []string{"sh", "-c", "sleep 2; touch " + marker}, Secrets: []string{"API_KEY"}}, nil)
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child survived the client disconnect")
	}
	// The cancelled run is still in the audit log.
	var found bool
	for _, e := range result[[]proto.AuditInfo](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 10})) {
		if e.Reason == "canceled" {
			found = true
		}
	}
	if !found {
		t.Error("cancelled run not audited")
	}
}

func TestStatusAndAuditVerifyAfterEverything(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.TTL = time.Hour
	r.run([]string{"API_KEY"}, "true")
	r.ap.SetAllow(false)
	r.run([]string{"API_KEY"}, "false")
	r.ap.SetAllow(true)
	r.call(&proto.Request{Op: proto.OpShow, Name: "API_KEY", Cwd: r.cwd})
	r.run([]string{"MISSING"}, "true")
	r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevokeAll})
	r.call(&proto.Request{Op: proto.OpDelete, Name: "API_KEY"})

	v := result[proto.AuditVerifyResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionVerify}))
	if !v.OK || v.Entries != 6 {
		t.Fatalf("verify = %+v", v)
	}
	csv := result[proto.AuditExportResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionExport})).CSV
	for _, want := range []string{"allowed_new_grant", "denied_user", "allowed_once"} {
		if !strings.Contains(csv, want) {
			t.Errorf("export lacks %q", want)
		}
	}
	st := result[proto.StatusResult](t, r.call(&proto.Request{Op: proto.OpStatus}))
	if !st.VaultInitialized || st.KeyStoreTier != presence.TierNone || st.ApproverTier != presence.TierNone || st.Secrets != 0 {
		t.Errorf("status = %+v", st)
	}
}
