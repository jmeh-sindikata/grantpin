package client_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/client"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/proto"
)

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func startDaemon(t *testing.T, rt *daemon.Router, sf daemon.StatusFunc) string {
	t.Helper()
	path := filepath.Join(shortDir(t), "s.sock")
	srv, err := daemon.New(daemon.Config{SocketPath: path, Router: rt, StatusFunc: sf, Version: "9.9", ShutdownGrace: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

func TestStatus(t *testing.T) {
	path := startDaemon(t, nil, func(_ context.Context, st *proto.StatusResult) { st.Secrets = 3 })
	st, err := client.Status(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "9.9" || st.Secrets != 3 || st.PID != os.Getpid() {
		t.Errorf("status = %+v", st)
	}

	c, err := client.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background()); !errors.Is(err, client.ErrUsed) {
		t.Errorf("second request on one connection = %v, want ErrUsed", err)
	}
}

func TestNotRunning(t *testing.T) {
	dir := shortDir(t)

	// Socket file missing.
	missing := filepath.Join(dir, "none.sock")
	_, err := client.Dial(missing)
	if !errors.Is(err, client.ErrNotRunning) {
		t.Errorf("missing socket: %v", err)
	}
	if _, err := client.Status(context.Background(), missing); !errors.Is(err, client.ErrNotRunning) {
		t.Errorf("Status: %v", err)
	}
	if _, err := client.Call(context.Background(), missing, &proto.Request{Op: proto.OpStatus}, nil); !errors.Is(err, client.ErrNotRunning) {
		t.Errorf("Call: %v", err)
	}

	// Stale socket file: exists, refuses connections.
	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if _, err := client.Dial(stale); !errors.Is(err, client.ErrNotRunning) {
		t.Errorf("stale socket: %v", err)
	}

	// Some other failure is not ErrNotRunning (path is a directory's child of a file).
	f := filepath.Join(dir, "file")
	_ = os.WriteFile(f, nil, 0o600)
	_, err = client.Dial(filepath.Join(f, "x.sock"))
	if err == nil || errors.Is(err, client.ErrNotRunning) {
		t.Errorf("ENOTDIR: %v", err)
	}
}

func TestDoStreamsInOrderAndDefaultsVersion(t *testing.T) {
	rt := daemon.NewRouter()
	rt.Register(proto.OpRun, daemon.HandlerFunc(func(_ context.Context, req *proto.Request, w daemon.ResponseWriter) {
		_ = w.Stream(proto.StreamStdout, []byte("a"))
		_ = w.Stream(proto.StreamStderr, []byte("b"))
		_ = w.Stream(proto.StreamStdout, []byte("c"))
		_ = w.Finish(&proto.Response{OK: true, ExitCode: proto.IntPtr(7), GrantID: req.Caller})
	}))
	path := startDaemon(t, rt, nil)

	var got []proto.StreamFrame
	resp, err := client.Call(context.Background(), path,
		&proto.Request{Op: proto.OpRun, Caller: "tester", Argv: []string{"x"}}, // V left zero
		func(f proto.StreamFrame) { got = append(got, f) })
	if err != nil {
		t.Fatal(err)
	}
	want := []proto.StreamFrame{{Stream: "stdout", Data: "a"}, {Stream: "stderr", Data: "b"}, {Stream: "stdout", Data: "c"}}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("frames = %v", got)
	}
	if !resp.OK || *resp.ExitCode != 7 || resp.GrantID != "tester" {
		t.Errorf("resp = %+v", resp)
	}

	// nil onStream discards frames without error.
	if _, err := client.Call(context.Background(), path, &proto.Request{Op: proto.OpRun}, nil); err != nil {
		t.Errorf("nil onStream: %v", err)
	}
}

func TestDoDoesNotMutateRequest(t *testing.T) {
	path := startDaemon(t, nil, nil)
	req := &proto.Request{Op: proto.OpStatus}
	if _, err := client.Call(context.Background(), path, req, nil); err != nil {
		t.Fatal(err)
	}
	if req.V != 0 {
		t.Errorf("req.V mutated to %d", req.V)
	}
}

func TestErrorResponses(t *testing.T) {
	path := startDaemon(t, nil, nil)
	resp, err := client.Call(context.Background(), path, &proto.Request{Op: proto.OpRun}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Reason != proto.ReasonUnknownOp {
		t.Fatalf("resp = %+v", resp)
	}
	var ce *client.Error
	if err := client.ResponseError(resp); !errors.As(err, &ce) || ce.Category != proto.ErrBadRequest || ce.Reason != proto.ReasonUnknownOp {
		t.Errorf("ResponseError = %v", err)
	}
	if got := (&client.Error{Category: "denied", Reason: "user_denied"}).Error(); got != "denied: user_denied" {
		t.Errorf("Error() = %q", got)
	}
	if got := (&client.Error{Category: "failed"}).Error(); got != "failed" {
		t.Errorf("Error() = %q", got)
	}
	if client.ResponseError(&proto.Response{OK: true}) != nil {
		t.Error("OK response produced an error")
	}
	if !errors.Is(client.ResponseError(nil), client.ErrNoResponse) {
		t.Error("nil response")
	}
}

func TestStatusSurfacesDaemonError(t *testing.T) {
	rt := daemon.NewRouter()
	rt.Register(proto.OpStatus, daemon.HandlerFunc(func(_ context.Context, _ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Finish(daemon.Failure(proto.ErrFailed, proto.ReasonVaultNotInitialized))
	}))
	path := startDaemon(t, rt, nil)
	_, err := client.Status(context.Background(), path)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Reason != proto.ReasonVaultNotInitialized {
		t.Errorf("err = %v", err)
	}

	rt2 := daemon.NewRouter()
	rt2.Register(proto.OpStatus, daemon.HandlerFunc(func(_ context.Context, _ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Finish(&proto.Response{OK: true, Result: []byte(`"not an object"`)})
	}))
	if _, err := client.Status(context.Background(), startDaemon(t, rt2, nil)); err == nil {
		t.Error("garbled status accepted")
	}
}

func TestContextCancelAbortsAndCancelsDaemonSide(t *testing.T) {
	started := make(chan struct{})
	handlerCtxErr := make(chan error, 1)
	rt := daemon.NewRouter()
	rt.Register(proto.OpRun, daemon.HandlerFunc(func(ctx context.Context, _ *proto.Request, _ daemon.ResponseWriter) {
		close(started)
		<-ctx.Done()
		handlerCtxErr <- ctx.Err()
	}))
	path := startDaemon(t, rt, nil)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := client.Call(ctx, path, &proto.Request{Op: proto.OpRun}, nil)
		errc <- err
	}()
	<-started
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Do = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Do did not return after cancel")
	}
	select {
	case err := <-handlerCtxErr:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("daemon-side err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon handler not cancelled")
	}
}

func TestContextDeadline(t *testing.T) {
	rt := daemon.NewRouter()
	rt.Register(proto.OpRun, daemon.HandlerFunc(func(ctx context.Context, _ *proto.Request, _ daemon.ResponseWriter) { <-ctx.Done() }))
	path := startDaemon(t, rt, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.Call(ctx, path, &proto.Request{Op: proto.OpRun}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestDialContextCanceled(t *testing.T) {
	path := startDaemon(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.DialContext(ctx, path); err == nil {
		t.Error("DialContext with cancelled ctx succeeded")
	}
}

// fakeServer accepts one connection, reads the request line, then runs f.
func fakeServer(t *testing.T, f func(net.Conn)) string {
	t.Helper()
	path := filepath.Join(shortDir(t), "f.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = proto.NewReader(c).ReadRequest()
		f(c)
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return path
}

func TestConnectionClosedBeforeResponse(t *testing.T) {
	path := fakeServer(t, func(c net.Conn) {
		_ = proto.Write(c, &proto.StreamFrame{Stream: "stdout", Data: "partial"})
	})
	_, err := client.Call(context.Background(), path, &proto.Request{Op: proto.OpStatus}, nil)
	if !errors.Is(err, client.ErrNoResponse) {
		t.Errorf("err = %v, want ErrNoResponse", err)
	}
}

func TestGarbageFromServer(t *testing.T) {
	path := fakeServer(t, func(c net.Conn) { _, _ = c.Write([]byte("{\"neither\":1}\n")) })
	_, err := client.Call(context.Background(), path, &proto.Request{Op: proto.OpStatus}, nil)
	if err == nil || errors.Is(err, client.ErrNoResponse) {
		t.Errorf("err = %v", err)
	}
}

func TestSendFailure(t *testing.T) {
	path := filepath.Join(shortDir(t), "f.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := client.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := c.Do(context.Background(), &proto.Request{Op: proto.OpStatus}, nil); err == nil {
		t.Error("Do on closed connection succeeded")
	}
}
