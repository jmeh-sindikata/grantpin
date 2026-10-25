package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"grantd/internal/approve"
	"grantd/internal/client"
	"grantd/internal/presence"
	"grantd/internal/vault"
)

// testKS is an identity keystore (test-only, no protection).
type testKS struct{}

func (testKS) Wrap(_ context.Context, k []byte) ([]byte, error) {
	return append([]byte(nil), k...), nil
}
func (testKS) Unwrap(_ context.Context, w []byte) ([]byte, error) {
	return append([]byte(nil), w...), nil
}
func (testKS) Tier() presence.PresenceTier { return presence.TierNone }

// testApprover answers per its fields.
type testApprover struct {
	mu    sync.Mutex
	allow bool
	ttl   time.Duration
	n     int
}

func (a *testApprover) Tier() presence.PresenceTier { return presence.TierNone }
func (a *testApprover) Ask(context.Context, approve.ApprovalRequest) (approve.Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	if !a.allow {
		return approve.Decision{Reason: "test denied"}, nil
	}
	return approve.Decision{Allow: true, TTL: a.ttl}, nil
}
func (a *testApprover) asked() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

// useFakeBackends points the vault at a temp dir and swaps in fake backends
// for the duration of the test.
func useFakeBackends(t *testing.T) *testApprover {
	t.Helper()
	t.Setenv("GRANTD_HOME", filepath.Join(t.TempDir(), "g"))
	ap := &testApprover{allow: true}
	old := openBackends
	openBackends = func(backendConfig) (backends, error) { return backends{ks: testKS{}, ap: ap}, nil }
	t.Cleanup(func() { openBackends = old })
	return ap
}

// testDaemon is an in-process daemon with an initialised vault.
type testDaemon struct {
	t      *testing.T
	sock   string
	ap     *testApprover
	cancel context.CancelFunc
	done   chan error
}

func startTestDaemon(t *testing.T, initVault bool) *testDaemon {
	t.Helper()
	ap := useFakeBackends(t)
	if initVault {
		initTestVault(t)
	}
	sock := shortSocket(t)
	t.Setenv("GRANTD_SOCKET", sock)
	ctx, cancel := context.WithCancel(context.Background())
	d := &testDaemon{t: t, sock: sock, ap: ap, cancel: cancel, done: make(chan error, 1)}
	go func() { d.done <- runDaemon(ctx, sock, nil, backendConfig{}) }()
	for range 200 {
		if _, err := client.Status(ctx, sock); err == nil {
			t.Cleanup(d.stop)
			return d
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	t.Fatalf("daemon did not start: %v", <-d.done)
	return nil
}

func (d *testDaemon) stop() {
	d.cancel()
	select {
	case <-d.done:
	case <-time.After(15 * time.Second):
		d.t.Error("daemon did not stop")
	}
}

func initTestVault(t *testing.T) {
	t.Helper()
	p, err := vault.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Init(context.Background(), p, testKS{}, vault.WithDefaultMinTier(presence.TierNone))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
}

// cli runs the grantd command tree in-process.
func cli(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	root := newRootCmd()
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

func mustCLI(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, errs, err := cli(t, stdin, args...)
	if err != nil {
		t.Fatalf("grantd %v: %v\nstdout: %s\nstderr: %s", args, err, out, errs)
	}
	return out
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
