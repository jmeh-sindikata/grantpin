package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/client"
	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// blockingKS is testKS whose Unwrap announces itself and then waits to be
// released, as a Keychain or Secure Enclave call can.
type blockingKS struct {
	testKS
	entered chan struct{} // receives one value per Unwrap call
	release chan struct{} // closed to let every Unwrap return
	mu      sync.Mutex
	calls   int
}

func newBlockingKS() *blockingKS {
	return &blockingKS{entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (k *blockingKS) Unwrap(ctx context.Context, w []byte) ([]byte, error) {
	k.mu.Lock()
	k.calls++
	k.mu.Unlock()
	k.entered <- struct{}{}
	select {
	case <-k.release:
		return k.testKS.Unwrap(ctx, w)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (k *blockingKS) callCount() int { k.mu.Lock(); defer k.mu.Unlock(); return k.calls }

func waitEntered(t *testing.T, k *blockingKS) {
	t.Helper()
	select {
	case <-k.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the keystore was never called")
	}
}

func setOpenWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := openWait
	openWait = d
	t.Cleanup(func() { openWait = old })
}

// The socket must exist, and status answer, while the first open of the vault
// is stuck in the keystore; requests are answered vault_locked after waiting a
// little; and once the keystore returns the vault is usable. The keystore is
// called once, however many requests arrive meanwhile.
func TestDaemonListensWhileTheFirstOpenIsInProgress(t *testing.T) {
	setOpenWait(t, 150*time.Millisecond)
	ks := newBlockingKS()
	logs := &logBuf{}
	sock, done := startWithKS(t, ks, logs)
	waitEntered(t, ks)

	start := time.Now()
	st, err := client.Status(context.Background(), sock)
	if err != nil {
		t.Fatalf("status while opening: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("status took %v while the keystore call was stuck", d)
	}
	if !st.VaultInitialized || !st.VaultLocked || !strings.Contains(st.VaultLockedError, "being opened") {
		t.Errorf("status = %+v, want initialized and locked (being opened)", st)
	}
	out := mustCLI(t, "", "status", "--socket", sock)
	if !strings.Contains(out, "being opened") {
		t.Errorf("status output:\n%s", out)
	}

	for range 3 {
		resp, err := listOp(sock)
		if err != nil || resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonVaultLocked || !strings.Contains(resp.Message, "being opened") {
			t.Fatalf("list while opening = %+v, %v; want failed/vault_locked", resp, err)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("daemon exited: %v", err)
	default:
	}

	close(ks.release)
	waitStatus(t, sock, func(s *proto.StatusResult) bool { return !s.VaultLocked && s.VaultInitialized })
	if resp, err := listOp(sock); err != nil || !resp.OK {
		t.Fatalf("list after the open: %+v, %v", resp, err)
	}
	if n := ks.callCount(); n != 1 {
		t.Errorf("keystore called %d times, want 1 (one open at a time)", n)
	}
}

// Requests that arrive during the open wait for it (up to openWait) and are
// then served; they do not open again.
func TestRequestsDuringTheFirstOpenWaitForIt(t *testing.T) {
	setOpenWait(t, 20*time.Second)
	ks := newBlockingKS()
	sock, _ := startWithKS(t, ks, &logBuf{})
	waitEntered(t, ks)

	type result struct {
		resp *proto.Response
		err  error
	}
	results := make(chan result, 4)
	for range 4 {
		go func() {
			resp, err := listOp(sock)
			results <- result{resp, err}
		}()
	}
	select {
	case r := <-results:
		t.Fatalf("a request returned before the open finished: %+v %v", r.resp, r.err)
	case <-time.After(300 * time.Millisecond):
	}
	// Status still answers while they wait.
	if _, err := client.Status(context.Background(), sock); err != nil {
		t.Fatalf("status: %v", err)
	}
	close(ks.release)
	for range 4 {
		select {
		case r := <-results:
			if r.err != nil || !r.resp.OK {
				t.Fatalf("waiting request = %+v, %v", r.resp, r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("waiting requests were not served after the open")
		}
	}
	if n := ks.callCount(); n != 1 {
		t.Errorf("keystore called %d times, want 1", n)
	}
}

// Shutting down while the keystore call is stuck ends the daemon: the open is
// cancelled, not waited for.
func TestDaemonStopsWhileTheFirstOpenIsStuck(t *testing.T) {
	ks := newBlockingKS()
	ap := useFakeBackends(t)
	initTestVault(t)
	openBackends = func() (backends, error) { return backends{ks: ks, ap: ap}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, shortSocket(t), nil) }()
	waitEntered(t, ks)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop while the vault open was stuck")
	}
}

// The holder's mutex is not held during the keystore call: lockedState and
// loaded return at once.
func TestBrokerHolderDoesNotHoldItsMutexWhileOpening(t *testing.T) {
	useFakeBackends(t)
	initTestVault(t)
	ks := newBlockingKS()
	h, err := newBrokerHolder(backends{ks: ks, ap: &testApprover{allow: true}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	got := make(chan error, 1)
	go func() { _, err := h.get(context.Background()); got <- err }()
	waitEntered(t, ks)

	probe := make(chan string, 1)
	go func() {
		_ = h.loaded()
		probe <- h.lockedState()
	}()
	select {
	case s := <-probe:
		if !strings.Contains(s, "being opened") {
			t.Errorf("lockedState = %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lockedState blocked behind the keystore call")
	}
	close(ks.release)
	if err := <-got; err != nil {
		t.Fatalf("get: %v", err)
	}
	if h.loaded() == nil || h.lockedState() != "" {
		t.Error("broker not loaded after the open")
	}
}
