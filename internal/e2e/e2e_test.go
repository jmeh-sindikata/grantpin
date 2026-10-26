//go:build grantd_dev

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	devap "github.com/jmeh-sindikata/grantd/internal/approve/dev"
	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/broker"
	"github.com/jmeh-sindikata/grantd/internal/client"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/grant"
	devks "github.com/jmeh-sindikata/grantd/internal/keystore/dev"
	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/vault"
)

const apiKey = "sk_live_0123456789_SUPERSECRET"

// slowApprover delays every answer, standing in for a human who takes a while.
type slowApprover struct {
	*devap.Approver
	delay atomic.Int64 // nanoseconds
}

func (s *slowApprover) Ask(ctx context.Context, req approve.ApprovalRequest) (approve.Decision, error) {
	select {
	case <-time.After(time.Duration(s.delay.Load())):
	case <-ctx.Done():
		return approve.Decision{}, ctx.Err()
	}
	return s.Approver.Ask(ctx, req)
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// rig is a running daemon plus handles to its approver.
type rig struct {
	logs *syncBuf // everything the daemon and broker log, at debug level
	t    *testing.T
	sock string
	ap   *devap.Approver
	slow *slowApprover
	cwd  string
	db   *sql.DB // the vault file, to play the same-UID attacker
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
	slow := &slowApprover{Approver: ap}
	logs := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	b, err := broker.New(broker.Deps{Vault: v, Grants: grant.NewStore(v.DB(), v.DeriveKey("grant-mac")), Audit: al, Approver: slow, KeyStoreTier: ks.Tier(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	r := daemon.NewRouter()
	b.Register(r)
	sock := filepath.Join(dir, "s.sock")
	srv, err := daemon.New(daemon.Config{SocketPath: sock, Router: r, StatusFunc: b.StatusFunc(), Version: "e2e", Logger: logger})
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
		// Serve has drained every connection, so every request line has been
		// logged by now: no test may have put the value in the daemon's or the
		// broker's log, whatever it did (argv, errors, show, grants).
		if out := logs.String(); strings.Contains(out, apiKey) {
			t.Errorf("the secret value is in the daemon/broker log:\n%s", out)
		}
	})

	cwd, err := filepath.EvalSymlinks(filepath.Join(dir))
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(cwd, "proj")
	if err := os.Mkdir(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	return &rig{logs: logs, t: t, sock: sock, ap: ap, slow: slow, cwd: proj, db: v.DB()}
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
	if out := r.logs.String(); strings.Contains(out, apiKey) {
		r.t.Fatalf("the secret value is in the daemon/broker log:\n%s", out)
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
	l := result[proto.AuditListResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 1})).Entries
	if len(l) != 1 {
		t.Fatalf("audit list = %+v", l)
	}
	return l[0]
}

// lastPair returns the released and completed rows of the newest run.
func lastPair(t *testing.T, r *rig) (released, completed proto.AuditInfo) {
	t.Helper()
	l := result[proto.AuditListResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 2})).Entries
	if len(l) != 2 {
		t.Fatalf("audit list = %+v", l)
	}
	released, completed = l[1], l[0]
	if released.Reason != broker.ReasonReleased || released.ExitCode != nil || released.GrantID != completed.GrantID ||
		completed.Decision != audit.DecisionCompleted || completed.ExitCode == nil {
		t.Fatalf("not a released+completed pair: %+v / %+v", released, completed)
	}
	return released, completed
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
		{Op: proto.OpRun, Cwd: r.cwd, Argv: []string{"sh", "-c", "true", apiKey}, Secrets: []string{"API_KEY"}}, // runs; the value rides in argv
		{Op: proto.OpRun, Cwd: r.cwd, Argv: []string{"true"}, Secrets: []string{"MISSING"}},
		{Op: proto.OpSet, Name: "API_KEY", Value: apiKey}, // duplicate: error must not echo the value
	} {
		r.noLeak(r.call(req))
	}
	// The audit log never holds it either (argv containing the value was scrubbed).
	for _, e := range result[proto.AuditListResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 100})).Entries {
		// Every row, the released one included, is written after decryption
		// and scrubbed with the redactor.
		if strings.Contains(strings.Join(e.Argv, " ")+e.Reason+e.Cwd+e.Caller, apiKey) {
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
	rel, done := lastPair(t, r)
	if rel.Decision != audit.DecisionAllowedNewGrant || rel.GrantID != first.resp.GrantID || first.resp.AuditID != done.ID {
		t.Fatalf("audit = %+v / %+v", rel, done)
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
	if rel, _ := lastPair(t, r); rel.Decision != audit.DecisionAllowedGrant {
		t.Fatalf("audit = %+v", rel)
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
	if _, a := lastPair(t, r); *a.ExitCode != 124 || a.Reason != proto.ReasonTimeout {
		t.Fatalf("audit = %+v", a)
	}
}

// timeout_s budgets the command only: a slow human does not eat into it.
func TestSlowApprovalDoesNotConsumeTheCommandTimeout(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.slow.delay.Store(int64(2500 * time.Millisecond))
	start := time.Now()
	rep := r.call(&proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: r.cwd,
		Argv: []string{"sh", "-c", "sleep 1; echo done"}, Secrets: []string{"API_KEY"}, TimeoutS: 2})
	if !rep.resp.OK || *rep.resp.ExitCode != 0 || rep.stdout != "done\n" {
		t.Fatalf("response = %+v stdout=%q (approval time must not count against timeout_s)", rep.resp, rep.stdout)
	}
	if d := time.Since(start); d < 3*time.Second {
		t.Errorf("finished in %s; the approval delay did not happen", d)
	}
	// ... while the command itself is still bounded by it.
	start = time.Now()
	rep = r.call(&proto.Request{Op: proto.OpRun, Caller: "e2e", Cwd: r.cwd,
		Argv: []string{"sleep", "10"}, Secrets: []string{"API_KEY"}, TimeoutS: 1})
	if !rep.resp.OK || *rep.resp.ExitCode != 124 {
		t.Fatalf("response = %+v", rep.resp)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("took %s", d)
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
	for _, e := range result[proto.AuditListResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionList, Limit: 10})).Entries {
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
	if !v.OK || v.Entries != 7 {
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

// Presence bypass attempt: a same-UID process writes a grant straight into the
// vault file. Without a valid MAC it must be ignored and the human asked.
func TestForgedGrantRowDoesNotBypassThePrompt(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	far := time.Now().Add(24 * time.Hour).UnixNano()
	for i, mac := range [][]byte{{}, []byte("forged"), make([]byte, 32)} {
		if _, err := r.db.Exec(`INSERT INTO grants (id, caller, cwd_prefix, secrets, cmd_prefix, created_at, expires_at, uses_remaining, mac) VALUES (?, 'e2e', ?, '["API_KEY"]', '["sh"]', ?, ?, NULL, ?)`,
			"forged"+string(rune('a'+i)), r.cwd, time.Now().UnixNano(), far, mac); err != nil {
			t.Fatal(err)
		}
	}
	rep := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if !rep.resp.OK || rep.resp.GrantID != "" {
		t.Fatalf("response = %+v", rep.resp)
	}
	if r.asked() != 1 {
		t.Fatalf("forged grant skipped the prompt (approver asked %d times)", r.asked())
	}
	if rel, _ := lastPair(t, r); rel.Decision != audit.DecisionAllowedOnce {
		t.Fatalf("decision = %q, want allowed_once (a human decision)", rel.Decision)
	}
	// ... and the forgeries are visible to the user.
	gl := result[[]proto.GrantInfo](t, r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
	if len(gl) != 3 {
		t.Fatalf("grants = %+v", gl)
	}
	for _, g := range gl {
		if !g.Tampered {
			t.Errorf("forged grant %s not flagged", g.ID)
		}
	}
	if st := result[proto.StatusResult](t, r.call(&proto.Request{Op: proto.OpStatus})); st.TamperedGrants != 3 || st.ActiveGrants != 0 {
		t.Errorf("status = %+v", st)
	}
	// A genuine grant still works next to the forgeries.
	r.ap.TTL = time.Hour
	first := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	second := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if first.resp.GrantID == "" || second.resp.GrantID != first.resp.GrantID || r.asked() != 2 {
		t.Fatalf("genuine grant: %+v %+v asked=%d", first.resp, second.resp, r.asked())
	}
	// Editing the genuine row's expiry in place invalidates it.
	if _, err := r.db.Exec(`UPDATE grants SET expires_at = expires_at + 3600000000000 WHERE id = ?`, first.resp.GrantID); err != nil {
		t.Fatal(err)
	}
	r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if r.asked() != 3 {
		t.Fatalf("edited grant still matched (asked %d)", r.asked())
	}
}

// ---- dialog TTL follows the policy; standing grants -----------------------

func (r *rig) addGrant(ttl time.Duration, secrets []string, argv ...string) reply {
	return r.call(&proto.Request{
		Op: proto.OpGrants, Action: proto.ActionAdd, Caller: "cli", GrantCaller: "e2e",
		Cwd: r.cwd, Secrets: secrets, Argv: argv, TTLS: int64(ttl / time.Second),
	})
}

func (r *rig) grants() []proto.GrantInfo {
	return result[[]proto.GrantInfo](r.t, r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionList}))
}

func TestDialogGrantFollowsThePolicyTTLButNeverPastADay(t *testing.T) {
	for _, tc := range []struct {
		policyTTL string
		offered   time.Duration
	}{
		{"8h", 8 * time.Hour},
		{"7d", 24 * time.Hour},
		{"90m", 90 * time.Minute},
	} {
		t.Run(tc.policyTTL, func(t *testing.T) {
			r := newRig(t)
			r.set("API_KEY", apiKey)
			policy := "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [sh, -c]\nmax_grant_ttl: " + tc.policyTTL + "\n"
			if err := os.WriteFile(filepath.Join(r.cwd, ".grantd.yml"), []byte(policy), 0o600); err != nil {
				t.Fatal(err)
			}
			r.ap.TTL = 30 * 24 * time.Hour // a human who clicks "Allow for N" with whatever is on offer
			rep := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
			if !rep.resp.OK || rep.resp.GrantID == "" {
				t.Fatalf("run = %+v", rep.resp)
			}
			reqs := r.ap.Requests()
			if got := reqs[len(reqs)-1]; got.Kind != approve.KindRelease || got.SuggestedTTL != tc.offered {
				t.Fatalf("dialog offered %v (kind %v), want %v", got.SuggestedTTL, got.Kind, tc.offered)
			}
			gl := r.grants()
			if len(gl) != 1 || gl[0].Standing {
				t.Fatalf("grants = %+v", gl)
			}
			if d := gl[0].ExpiresAt.Sub(gl[0].CreatedAt); d != tc.offered {
				t.Errorf("grant lasts %v, want %v", d, tc.offered)
			}
		})
	}
}

func TestStandingGrantIsCreatedByTheHumanAndUsedWithoutAPrompt(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)

	rep := r.addGrant(30*24*time.Hour, []string{"API_KEY"}, "sh", "-c")
	if !rep.resp.OK || rep.resp.GrantID == "" || rep.resp.AuditID == "" {
		t.Fatalf("grants add = %+v", rep.resp)
	}
	r.noLeak(rep)
	info := result[proto.GrantInfo](t, rep)
	if !info.Standing || info.ID != rep.resp.GrantID || info.Caller != "e2e" || info.CwdPrefix != r.cwd ||
		info.ExpiresAt.Sub(info.CreatedAt) != 30*24*time.Hour {
		t.Fatalf("grant = %+v", info)
	}
	// What the human was shown.
	reqs := r.ap.Requests()
	if len(reqs) != 1 || reqs[0].Kind != approve.KindStandingGrant || reqs[0].RequestedTTL != 30*24*time.Hour ||
		reqs[0].Caller != "e2e" || reqs[0].SuggestedTTL != 0 || strings.Join(reqs[0].GrantCmdPrefix, " ") != "sh -c" {
		t.Fatalf("approval request = %+v", reqs)
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionAllowedNewGrant || a.Reason != "standing" || a.GrantID != info.ID || a.ID != rep.resp.AuditID {
		t.Fatalf("audit = %+v", a)
	}

	// A run matching it is released with no prompt, as allowed_grant.
	run := r.run([]string{"API_KEY"}, "sh", "-c", "echo $API_KEY")
	if !run.resp.OK || run.resp.GrantID != info.ID || run.stdout != "[REDACTED:API_KEY]\n" {
		t.Fatalf("run = %+v stdout=%q", run.resp, run.stdout)
	}
	r.noLeak(run)
	if r.asked() != 1 {
		t.Fatalf("the standing grant did not avoid the prompt (asked %d times)", r.asked())
	}
	if rel, _ := lastPair(t, r); rel.Decision != audit.DecisionAllowedGrant || rel.GrantID != info.ID {
		t.Fatalf("release audit = %+v", rel)
	}
	// A different command, caller or directory still asks.
	if rep := r.run([]string{"API_KEY"}, "true"); !rep.resp.OK || r.asked() != 2 {
		t.Fatalf("other command: %+v asked=%d", rep.resp, r.asked())
	}
	if rep := r.call(&proto.Request{Op: proto.OpRun, Caller: "someone-else", Cwd: r.cwd, Argv: []string{"sh", "-c", "exit 0"}, Secrets: []string{"API_KEY"}}); !rep.resp.OK || r.asked() != 3 {
		t.Fatalf("other caller: %+v asked=%d", rep.resp, r.asked())
	}

	// grants lists it as standing; the dialog grants are not.
	var standing int
	for _, g := range r.grants() {
		if g.Standing {
			standing++
			if g.ID != info.ID {
				t.Errorf("unexpected standing grant %+v", g)
			}
		}
	}
	if standing != 1 {
		t.Errorf("standing grants listed: %d", standing)
	}
	// Revoking it makes the same run ask again.
	if rep := r.call(&proto.Request{Op: proto.OpGrants, Action: proto.ActionRevoke, GrantID: info.ID}); !rep.resp.OK {
		t.Fatalf("revoke: %+v", rep.resp)
	}
	before := r.asked()
	r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if r.asked() != before+1 {
		t.Errorf("revoked standing grant still matched")
	}
	// The whole trail verifies.
	if v := result[proto.AuditVerifyResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionVerify})); !v.OK {
		t.Fatalf("verify = %+v", v)
	}
}

func TestStandingGrantDeniedByTheHumanCreatesNothing(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.SetDenyStanding(true) // everything else is still allowed

	rep := r.addGrant(30*24*time.Hour, []string{"API_KEY"}, "sh", "-c")
	wantErr(t, rep, proto.ErrDenied, proto.ReasonUserDenied)
	if gl := r.grants(); len(gl) != 0 {
		t.Fatalf("grants after a denied add: %+v", gl)
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionDeniedUser || !strings.HasPrefix(a.Reason, "standing grant") || a.ID != rep.resp.AuditID {
		t.Fatalf("audit = %+v", a)
	}
	// The run is not satisfied by anything: it asks, and the human allows it once.
	run := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if !run.resp.OK || run.resp.GrantID != "" || r.asked() != 2 {
		t.Fatalf("run = %+v asked=%d", run.resp, r.asked())
	}
	if v := result[proto.AuditVerifyResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionVerify})); !v.OK {
		t.Fatalf("verify = %+v", v)
	}
}

func TestStandingGrantCeilings(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)

	over := r.addGrant(90*24*time.Hour+time.Second, []string{"API_KEY"}, "sh", "-c")
	wantErr(t, over, proto.ErrBadRequest, proto.ReasonBadRequest)
	if !strings.Contains(over.resp.Message, "90d") {
		t.Errorf("message = %q", over.resp.Message)
	}
	if r.asked() != 0 || len(r.grants()) != 0 {
		t.Fatalf("an over-ceiling request reached the human (%d) or was clamped into a grant", r.asked())
	}
	if rep := r.addGrant(90*24*time.Hour, []string{"API_KEY"}, "sh", "-c"); !rep.resp.OK {
		t.Fatalf("90d exactly: %+v", rep.resp)
	}

	// A policy's max_grant_ttl does not apply to standing grants; its
	// max_standing_grant_ttl does.
	policy := "version: 1\nsecrets: [API_KEY]\ncommands:\n  - [sh, -c]\nmax_grant_ttl: 10m\nmax_standing_grant_ttl: 14d\n"
	if err := os.WriteFile(filepath.Join(r.cwd, ".grantd.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := r.addGrant(14*24*time.Hour, []string{"API_KEY"}, "sh", "-c"); !rep.resp.OK {
		t.Fatalf("14d under max_grant_ttl 10m: %+v", rep.resp)
	}
	rep := r.addGrant(15*24*time.Hour, []string{"API_KEY"}, "sh", "-c")
	wantErr(t, rep, proto.ErrBadRequest, proto.ReasonBadRequest)
	if !strings.Contains(rep.resp.Message, "max_standing_grant_ttl") {
		t.Errorf("message = %q", rep.resp.Message)
	}
	// The policy still limits what may be asked for at all.
	wantErr(t, r.addGrant(time.Hour, []string{"API_KEY"}, "rm"), proto.ErrRefused, proto.ReasonPolicyRefused)
}

func TestKindReachesTheApproverForEveryOp(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.run([]string{"API_KEY"}, "true")
	r.call(&proto.Request{Op: proto.OpShow, Name: "API_KEY", Cwd: r.cwd})
	r.addGrant(time.Hour, []string{"API_KEY"}, "true")
	var kinds []approve.Kind
	for _, q := range r.ap.Requests() {
		kinds = append(kinds, q.Kind)
	}
	want := []approve.Kind{approve.KindRelease, approve.KindShow, approve.KindStandingGrant}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

// A standing row is under the MAC like any other: relabelling a dialog grant as
// a standing one (or forging one outright) does not survive.
func TestStandingKindCannotBeForgedInTheDatabase(t *testing.T) {
	r := newRig(t)
	r.set("API_KEY", apiKey)
	r.ap.TTL = time.Hour
	first := r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if _, err := r.db.Exec(`UPDATE grants SET kind = 'standing', expires_at = expires_at + 3600000000000 WHERE id = ?`, first.resp.GrantID); err != nil {
		t.Fatal(err)
	}
	r.run([]string{"API_KEY"}, "sh", "-c", "exit 0")
	if r.asked() != 2 {
		t.Fatalf("promoted row still matched (asked %d)", r.asked())
	}
	for _, g := range r.grants() {
		if g.ID == first.resp.GrantID && !g.Tampered {
			t.Errorf("relabelled grant not flagged: %+v", g)
		}
	}
}

// update changes metadata over the real socket without the value ever being
// sent, read or logged, and a min_tier change keeps the secret usable.
func TestUpdateOverTheWire(t *testing.T) {
	r := newRig(t)
	hw := presence.TierHardware
	r.set("API_KEY", apiKey, func(q *proto.Request) { q.MinTier = &hw; q.Tags = []string{"prod"}; q.Notes = "old" })

	// hardware on a tier-none backend: refused until the tier is lowered
	wantErr(t, r.run([]string{"API_KEY"}, "true"), proto.ErrRefused, proto.ReasonTierUnmet)

	rep := r.call(&proto.Request{Op: proto.OpUpdate, Caller: "grantd-app", Name: "API_KEY", Tags: []string{"b", "a"}, Notes: "new"})
	if !rep.resp.OK || rep.resp.AuditID == "" {
		t.Fatalf("update = %+v", rep.resp)
	}
	r.noLeak(rep)
	var found *proto.SecretInfo
	for _, s := range result[[]proto.SecretInfo](t, r.call(&proto.Request{Op: proto.OpList})) {
		if s.Name == "API_KEY" {
			found = &s
		}
	}
	if found == nil || strings.Join(found.Tags, ",") != "a,b" || found.Notes != "new" || found.MinTier != hw {
		t.Fatalf("after update: %+v", found)
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionAllowedOnce || a.Reason != "update" || a.Caller != "grantd-app" || strings.Join(a.Argv, " ") != "grantd update API_KEY" {
		t.Fatalf("audit = %+v", a)
	}

	if r.asked() != 0 {
		t.Fatalf("a metadata update must not prompt; approver asked %d times", r.asked())
	}

	// Lowering the level is the one update that asks: the approver sees a
	// KindLowerTier request naming the secret and both levels, and the audit
	// row says so.
	none := presence.TierNone
	if rep := r.call(&proto.Request{Op: proto.OpUpdate, Caller: "grantd-app", Name: "API_KEY", MinTier: &none}); !rep.resp.OK {
		t.Fatalf("lower tier: %+v", rep.resp)
	}
	reqs := r.ap.Requests()
	if len(reqs) != 1 || reqs[0].Kind != approve.KindLowerTier || reqs[0].FromTier != hw || reqs[0].ToTier != none ||
		strings.Join(reqs[0].Secrets, ",") != "API_KEY" {
		t.Fatalf("approver saw %+v", reqs)
	}
	if a := lastAudit(t, r); a.Decision != audit.DecisionAllowedOnce || a.Reason != "update: lower min_tier" || a.Caller != "grantd-app" {
		t.Fatalf("audit after lowering = %+v", a)
	}
	run := r.run([]string{"API_KEY"}, "sh", "-c", `printf %s "$API_KEY"`)
	if !run.resp.OK || run.stdout != "[REDACTED:API_KEY]" {
		t.Fatalf("run after tier change: %+v stdout=%q", run.resp, run.stdout)
	}
	if r.asked() != 2 {
		t.Fatalf("approver asked %d times (want 2: the lowering and the run)", r.asked())
	}

	// A refused lowering changes nothing; raising again needs no approval.
	r.ap.SetAllow(false)
	dialog := presence.TierDialog
	if rep := r.call(&proto.Request{Op: proto.OpUpdate, Name: "API_KEY", MinTier: &hw}); !rep.resp.OK {
		t.Fatalf("raise tier: %+v", rep.resp)
	}
	if r.asked() != 2 {
		t.Fatalf("raising asked the approver (%d)", r.asked())
	}
	wantErr(t, r.call(&proto.Request{Op: proto.OpUpdate, Name: "API_KEY", MinTier: &dialog}), proto.ErrDenied, proto.ReasonUserDenied)
	if a := lastAudit(t, r); a.Decision != audit.DecisionDeniedUser || !strings.HasPrefix(a.Reason, "update: lower min_tier") {
		t.Fatalf("audit after refusal = %+v", a)
	}
	r.ap.SetAllow(true)

	wantErr(t, r.call(&proto.Request{Op: proto.OpUpdate, Name: "NOPE", Notes: "x"}), proto.ErrNotFound, proto.ReasonSecretNotFound)
	wantErr(t, r.call(&proto.Request{Op: proto.OpUpdate, Name: "API_KEY"}), proto.ErrBadRequest, proto.ReasonBadRequest)

	if v := result[proto.AuditVerifyResult](t, r.call(&proto.Request{Op: proto.OpAudit, Action: proto.ActionVerify})); !v.OK {
		t.Fatalf("audit chain broken after update: %+v", v)
	}
}
