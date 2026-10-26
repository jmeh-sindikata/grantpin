package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/proto"
)

func TestRetryableAccept(t *testing.T) {
	for name, err := range map[string]error{
		"EMFILE":         &net.OpError{Op: "accept", Err: syscall.EMFILE},
		"ENFILE":         &net.OpError{Op: "accept", Err: syscall.ENFILE},
		"ECONNABORTED":   syscall.ECONNABORTED,
		"timeout":        timeoutErr{},
		"temporary":      tempErr{},
		"wrapped EMFILE": errors.Join(errors.New("x"), syscall.EMFILE),
	} {
		if !retryableAccept(err) {
			t.Errorf("%s: not retryable", name)
		}
	}
	for name, err := range map[string]error{
		"closed":  net.ErrClosed,
		"EBADF":   &net.OpError{Op: "accept", Err: syscall.EBADF},
		"generic": errors.New("boom"),
	} {
		if retryableAccept(err) {
			t.Errorf("%s: retryable", name)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

type tempErr struct{}

func (tempErr) Error() string   { return "temporary" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

// failingListener fails the first n Accepts with err, then delegates.
type failingListener struct {
	net.Listener
	err  error
	left int
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.left > 0 {
		l.left--
		return nil, l.err
	}
	return l.Listener.Accept()
}

// A transient Accept error is retried, not fatal: Serve keeps running and the
// next client is served.
func TestServeSurvivesTransientAcceptErrors(t *testing.T) {
	rt := NewRouter()
	srv, err := New(Config{SocketPath: filepath.Join(shortDir(t), "s.sock"), Router: rt})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	srv.ln = &failingListener{Listener: srv.ln, err: &net.OpError{Op: "accept", Err: syscall.EMFILE}, left: 3}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	_, resp := call(t, srv.SocketPath(), proto.Request{Op: proto.OpStatus})
	if !resp.OK {
		t.Fatalf("status after accept errors = %+v", resp)
	}
	select {
	case err := <-done:
		t.Fatalf("Serve returned: %v", err)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve = %v", err)
	}
}

// A non-transient Accept error still ends Serve.
func TestServeStopsOnFatalAcceptError(t *testing.T) {
	srv, err := New(Config{SocketPath: filepath.Join(shortDir(t), "s.sock")})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	srv.ln = &failingListener{Listener: srv.ln, err: errors.New("boom"), left: 1}
	err = srv.Serve(context.Background())
	if err == nil {
		t.Fatal("Serve returned nil")
	}
}

func TestConnectionsOverTheLimitGetBusy(t *testing.T) {
	r := start(t, Config{MaxConns: 2})
	// Two idle connections hold both slots (the request line is awaited).
	var held []net.Conn
	for range 2 {
		c, err := net.Dial("unix", r.path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	// Wait until the server has accepted both.
	deadline := time.Now().Add(5 * time.Second)
	for len(r.srv.slots) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("server did not take the two connections")
		}
		time.Sleep(5 * time.Millisecond)
	}

	_, resp := call(t, r.path, proto.Request{Op: proto.OpStatus})
	if resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonBusy {
		t.Fatalf("third connection: %+v", resp)
	}

	// Closing one frees a slot.
	held[0].Close()
	held = held[1:]
	for range 200 {
		if _, resp = call(t, r.path, proto.Request{Op: proto.OpStatus}); resp.OK {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("still busy after a slot was freed: %+v", resp)
}

func TestDefaultMaxConns(t *testing.T) {
	srv, err := New(Config{SocketPath: "/x"})
	if err != nil || cap(srv.slots) != 64 {
		t.Fatalf("cap = %d, %v", cap(srv.slots), err)
	}
}
