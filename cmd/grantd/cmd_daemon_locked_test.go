package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"grantd/internal/client"
	"grantd/internal/keystore"
	"grantd/internal/proto"
)

// errLocked stands in for the macOS errSecInteractionNotAllowed (-25308), which
// no test can produce.
type errLocked struct{}

func (errLocked) Error() string   { return "fake keystore: decrypt: (OSStatus -25308)" }
func (errLocked) Transient() bool { return true }

// flakyKS is testKS whose Unwrap fails with a transient error while down, or
// for the first failN calls.
type flakyKS struct {
	testKS
	mu     sync.Mutex
	down   bool
	failN  int
	calls  int
	permEr error // if set, returned instead of the transient error
}

func (k *flakyKS) Unwrap(ctx context.Context, w []byte) ([]byte, error) {
	k.mu.Lock()
	k.calls++
	fail := k.down || k.failN > 0
	if k.failN > 0 {
		k.failN--
	}
	perm := k.permEr
	k.mu.Unlock()
	if fail {
		if perm != nil {
			return nil, perm
		}
		return nil, fmt.Errorf("darwin keystore: %w", errLocked{})
	}
	return k.testKS.Unwrap(ctx, w)
}

func (k *flakyKS) setDown(d bool) { k.mu.Lock(); k.down = d; k.mu.Unlock() }

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func fastBackoff(t *testing.T) {
	t.Helper()
	omin, omax := retryBackoffMin, retryBackoffMax
	retryBackoffMin, retryBackoffMax = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { retryBackoffMin, retryBackoffMax = omin, omax })
}

// startWithKS runs a daemon on an initialised vault with ks as its keystore.
func startWithKS(t *testing.T, ks keystore.KeyStore, logs *logBuf) (sock string, done chan error) {
	t.Helper()
	ap := useFakeBackends(t)
	initTestVault(t)
	openBackends = func() (backends, error) { return backends{ks: ks, ap: ap}, nil }
	sock = shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- runDaemon(ctx, sock, slog.New(slog.NewTextHandler(logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	return sock, done
}

func waitStatus(t *testing.T, sock string, ok func(*proto.StatusResult) bool) *proto.StatusResult {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := client.Status(context.Background(), sock); err == nil && ok(st) {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("status never reached the expected state")
	return nil
}

func listOp(sock string) (*proto.Response, error) {
	return client.Call(context.Background(), sock, &proto.Request{V: proto.Version, Op: proto.OpList}, nil)
}

func TestDaemonStaysUpWhileKeystoreLocked(t *testing.T) {
	fastBackoff(t)
	ks := &flakyKS{down: true}
	logs := &logBuf{}
	sock, done := startWithKS(t, ks, logs)

	// The socket comes up even though the vault cannot be opened.
	st := waitStatus(t, sock, func(*proto.StatusResult) bool { return true })
	if !st.VaultInitialized || !st.VaultLocked || !strings.Contains(st.VaultLockedError, "-25308") {
		t.Fatalf("status = %+v, want initialized+locked with the keystore error", st)
	}
	select {
	case err := <-done:
		t.Fatalf("daemon exited: %v", err)
	default:
	}

	// Ops fail with vault_locked, not internal.
	for range 3 {
		resp, err := listOp(sock)
		if err != nil || resp == nil || resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonVaultLocked {
			t.Fatalf("list = %+v, %v; want failed/vault_locked", resp, err)
		}
		if !strings.Contains(resp.Message, "vault keystore unavailable (screen locked?); retrying") {
			t.Errorf("message = %q", resp.Message)
		}
	}
	// grantd run reports it the same way.
	run := &proto.Request{V: proto.Version, Op: proto.OpRun, Caller: "t", Cwd: t.TempDir(), Argv: []string{"true"}, Secrets: []string{"x"}}
	if resp, _ := client.Call(context.Background(), sock, run, nil); resp == nil || resp.Reason != proto.ReasonVaultLocked {
		t.Errorf("run = %+v, want vault_locked", resp)
	}

	// The CLI shows it.
	out := mustCLI(t, "", "status", "--socket", sock)
	if !strings.Contains(out, "vault:        locked (retrying, last error: ") || !strings.Contains(out, "-25308") {
		t.Errorf("status output:\n%s", out)
	}

	// The keystore recovers: the next request works with no restart.
	ks.setDown(false)
	resp, err := listOp(sock)
	if err != nil || !resp.OK {
		t.Fatalf("list after recovery = %+v, %v", resp, err)
	}
	st = waitStatus(t, sock, func(s *proto.StatusResult) bool { return !s.VaultLocked })
	if !st.VaultInitialized {
		t.Errorf("status after recovery = %+v", st)
	}
	out = mustCLI(t, "", "status", "--socket", sock)
	if !strings.Contains(out, "vault:        initialized") {
		t.Errorf("status output after recovery:\n%s", out)
	}

	// One WARN for entering the locked state (however many retries and
	// requests there were) and one INFO for leaving it.
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d WARN lines, want 1:\n%s", n, logs.String())
	}
	if n := strings.Count(logs.String(), "vault keystore available again"); n != 1 {
		t.Errorf("%d recovery lines, want 1:\n%s", n, logs.String())
	}
}

func TestDaemonRecoversInBackgroundWithoutRequests(t *testing.T) {
	fastBackoff(t)
	ks := &flakyKS{failN: 4} // the start attempt and three retries fail
	logs := &logBuf{}
	sock, _ := startWithKS(t, ks, logs)

	waitStatus(t, sock, func(s *proto.StatusResult) bool { return !s.VaultLocked && s.VaultInitialized })
	ks.mu.Lock()
	calls := ks.calls
	ks.mu.Unlock()
	if calls != 5 {
		t.Errorf("Unwrap called %d times, want 5 (4 failures + the success)", calls)
	}
	if resp, err := listOp(sock); err != nil || !resp.OK {
		t.Errorf("list = %+v, %v", resp, err)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d WARN lines, want 1:\n%s", n, logs.String())
	}
}

func TestDaemonRefusesToStartOnPermanentKeystoreError(t *testing.T) {
	ap := useFakeBackends(t)
	initTestVault(t)
	perm := errors.New("fake keystore: wrong mode")
	ks := &flakyKS{down: true, permEr: perm}
	openBackends = func() (backends, error) { return backends{ks: ks, ap: ap}, nil }
	err := runDaemon(context.Background(), shortSocket(t), nil)
	if err == nil || !errors.Is(err, perm) || !strings.Contains(err.Error(), "start daemon: open vault") {
		t.Fatalf("runDaemon = %v, want fail-fast with the keystore error", err)
	}
}
