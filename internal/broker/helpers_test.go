package broker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/grant"
	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/vault"
)

// idKeyStore is a no-op keystore: wrap is the identity. Test-only.
type idKeyStore struct{ tier presence.PresenceTier }

func (k idKeyStore) Wrap(_ context.Context, dk []byte) ([]byte, error) {
	return append([]byte(nil), dk...), nil
}
func (k idKeyStore) Unwrap(_ context.Context, w []byte) ([]byte, error) {
	return append([]byte(nil), w...), nil
}
func (k idKeyStore) Tier() presence.PresenceTier { return k.tier }

// fakeApprover answers per its fields and records requests.
type fakeApprover struct {
	mu    sync.Mutex
	tier  presence.PresenceTier
	allow bool
	ttl   time.Duration
	// standingTTL, if non-nil, replaces the duration a standing-grant allow
	// carries (default: exactly RequestedTTL, as a real approver answers).
	standingTTL *time.Duration
	reason      string
	err         error
	onAsk       func()        // if non-nil, called inside Ask
	block       chan struct{} // if non-nil, Ask waits for it (or ctx)
	reqs        []approve.ApprovalRequest
	inFlight    int
	maxSeen     int
}

func (f *fakeApprover) Tier() presence.PresenceTier { return f.tier }

func (f *fakeApprover) Ask(ctx context.Context, r approve.ApprovalRequest) (approve.Decision, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.inFlight++
	f.maxSeen = max(f.maxSeen, f.inFlight)
	block, err, allow, ttl, reason := f.block, f.err, f.allow, f.ttl, f.reason
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.inFlight--; f.mu.Unlock() }()
	if f.onAsk != nil {
		f.onAsk()
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return approve.Decision{}, ctx.Err()
		}
	}
	if err != nil {
		return approve.Decision{}, err
	}
	if allow && r.Kind == approve.KindStandingGrant {
		ttl = r.RequestedTTL
		if f.standingTTL != nil {
			ttl = *f.standingTTL
		}
	}
	return approve.Decision{Allow: allow, TTL: ttl, Reason: reason}, nil
}

func (f *fakeApprover) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeApprover) last() approve.ApprovalRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

// recWriter is a daemon.ResponseWriter that records everything.
type recWriter struct {
	mu     sync.Mutex
	frames []proto.StreamFrame
	final  *proto.Response
	nfin   int
	failAt int // if >0, Stream fails from the Nth call on
	calls  int
}

func (r *recWriter) Stream(stream string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failAt > 0 && r.calls >= r.failAt {
		return errors.New("broken pipe")
	}
	r.frames = append(r.frames, proto.StreamFrame{Stream: stream, Data: string(data)})
	return nil
}

func (r *recWriter) Finish(resp *proto.Response) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nfin++
	r.final = resp
	return nil
}

func (r *recWriter) out(stream string) string {
	var sb strings.Builder
	for _, f := range r.frames {
		if f.Stream == stream {
			sb.WriteString(f.Data)
		}
	}
	return sb.String()
}

// logSink collects the broker's log output.
type logSink struct {
	mu sync.Mutex
	sb strings.Builder
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb.String()
}

type env struct {
	logs   logSink
	t      *testing.T
	b      *Broker
	v      *vault.Vault
	g      *grant.Store
	a      *audit.Log
	ap     *fakeApprover
	cwd    string
	now    time.Time
	nowMu  sync.Mutex
	secret string
}

// newEnv builds a vault with a TierNone keystore and an allow-once approver.
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{t: t, now: time.Now(), secret: "s3cr3t-value-ABCDEFG"}
	ks := idKeyStore{tier: presence.TierNone}
	v, err := vault.Init(ctx, filepath.Join(t.TempDir(), "v", "vault.db"), ks, vault.WithDefaultMinTier(presence.TierNone))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := grant.Migrate(ctx, v.DB()); err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(ctx, v.DB(), v.DeriveKey("audit-hmac"))
	if err != nil {
		t.Fatal(err)
	}
	e.v, e.g, e.a = v, grant.NewStore(v.DB(), v.DeriveKey("grant-mac")), al
	e.ap = &fakeApprover{tier: presence.TierNone, allow: true}
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.cwd = cwd
	e.rebuild(presence.TierNone)
	if err := v.Set(ctx, vault.Meta{Name: "API_KEY"}, []byte(e.secret), false); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) rebuild(ksTier presence.PresenceTier) {
	b, err := New(Deps{Vault: e.v, Grants: e.g, Audit: e.a, Approver: e.ap, KeyStoreTier: ksTier,
		Logger: slog.New(slog.NewTextHandler(&e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    func() time.Time { e.nowMu.Lock(); defer e.nowMu.Unlock(); return e.now }})
	if err != nil {
		e.t.Fatal(err)
	}
	e.b = b
}

func (e *env) advance(d time.Duration) {
	e.nowMu.Lock()
	e.now = e.now.Add(d)
	e.nowMu.Unlock()
}

func (e *env) do(req *proto.Request) *recWriter {
	return e.doCtx(context.Background(), req)
}

func (e *env) doCtx(ctx context.Context, req *proto.Request) *recWriter {
	e.t.Helper()
	if req.V == 0 {
		req.V = proto.Version
	}
	w := &recWriter{}
	e.b.Handle(ctx, req, w)
	if w.nfin != 1 {
		e.t.Fatalf("op %s: Finish called %d times", req.Op, w.nfin)
	}
	return w
}

func (e *env) run(secrets []string, argv ...string) *proto.Request {
	return &proto.Request{Op: proto.OpRun, Caller: "tester", Cwd: e.cwd, Argv: argv, Secrets: secrets}
}

func (e *env) lastAudit() audit.Entry {
	e.t.Helper()
	es, err := e.a.List(context.Background(), 1, 0)
	if err != nil || len(es) == 0 {
		e.t.Fatalf("audit list: %v %v", es, err)
	}
	return es[0]
}

// lastPair returns the released and completed rows of the newest run, and
// fails the test if the newest two rows are not such a pair.
func (e *env) lastPair() (released, completed audit.Entry) {
	e.t.Helper()
	es, err := e.a.List(context.Background(), 2, 0)
	if err != nil || len(es) < 2 {
		e.t.Fatalf("audit list: %v %v", es, err)
	}
	released, completed = es[1], es[0]
	if released.Reason != ReasonReleased || released.ExitCode != nil ||
		completed.Decision != audit.DecisionCompleted || released.GrantID != completed.GrantID {
		e.t.Fatalf("not a released+completed pair: %+v / %+v", released, completed)
	}
	return released, completed
}

func (e *env) auditCount() int {
	es, err := e.a.List(context.Background(), 1000, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(es)
}

func wantFail(t *testing.T, w *recWriter, category, reason string) {
	t.Helper()
	r := w.final
	if r.OK || r.Error != category || r.Reason != reason {
		t.Fatalf("response = %+v, want %s/%s", r, category, reason)
	}
}

func wantOK(t *testing.T, w *recWriter) {
	t.Helper()
	if !w.final.OK {
		t.Fatalf("response = %+v, want ok", w.final)
	}
}

func decode[T any](t *testing.T, w *recWriter) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.final.Result, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func writePolicy(t *testing.T, dir, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, ".grantd.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func vaultMeta(name string, tier presence.PresenceTier) vault.Meta {
	return vault.Meta{Name: name, MinTier: tier}
}
