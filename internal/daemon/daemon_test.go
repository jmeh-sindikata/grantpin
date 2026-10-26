package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

func routerWith(op string, f HandlerFunc) *Router {
	r := NewRouter()
	r.Register(op, f)
	return r
}

func TestStatusRoundTrip(t *testing.T) {
	r := start(t, Config{
		Version: "1.2.3",
		StatusFunc: func(_ context.Context, st *proto.StatusResult) {
			st.VaultInitialized = true
			st.Secrets = 7
		},
	})
	frames, resp := call(t, r.path, proto.Request{Op: proto.OpStatus})
	if len(frames) != 0 || !resp.OK {
		t.Fatalf("frames=%v resp=%+v", frames, resp)
	}
	var st proto.StatusResult
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		t.Fatal(err)
	}
	if st.PID != os.Getpid() || st.Version != "1.2.3" || st.ProtoV != proto.Version {
		t.Errorf("basics wrong: %+v", st)
	}
	if time.Since(st.StartedAt) > time.Minute || st.StartedAt.IsZero() {
		t.Errorf("StartedAt = %v", st.StartedAt)
	}
	if !st.VaultInitialized || st.Secrets != 7 {
		t.Errorf("StatusFunc not applied: %+v", st)
	}
}

func TestStatusWithoutStatusFuncAndDefaultVersion(t *testing.T) {
	r := start(t, Config{})
	_, resp := call(t, r.path, proto.Request{Op: proto.OpStatus})
	var st proto.StatusResult
	if err := json.Unmarshal(resp.Result, &st); err != nil || !resp.OK {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	if st.Version != "dev" || st.VaultInitialized {
		t.Errorf("%+v", st)
	}
}

func TestRouterStatusOverridesBuiltin(t *testing.T) {
	rt := routerWith(proto.OpStatus, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		_ = w.Finish(&proto.Response{OK: true, GrantID: "custom"})
	})
	r := start(t, Config{Router: rt})
	_, resp := call(t, r.path, proto.Request{Op: proto.OpStatus})
	if resp.GrantID != "custom" {
		t.Errorf("resp=%+v", resp)
	}
}

func TestBadRequests(t *testing.T) {
	var called atomic.Int32
	rt := routerWith(proto.OpList, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		called.Add(1)
		_ = w.Finish(okResp())
	})
	r := start(t, Config{Router: rt})

	tests := []struct {
		name   string
		line   string
		reason string
	}{
		{"unknown op", `{"v":1,"op":"frobnicate"}`, proto.ReasonUnknownOp},
		{"empty op", `{"v":1}`, proto.ReasonUnknownOp},
		{"known op without handler", `{"v":1,"op":"run"}`, proto.ReasonUnknownOp},
		{"bad version", `{"v":2,"op":"list"}`, proto.ReasonUnsupportedVersion},
		{"missing version", `{"op":"list"}`, proto.ReasonUnsupportedVersion},
		{"bad version beats bad op", `{"v":9,"op":"zzz"}`, proto.ReasonUnsupportedVersion},
		{"not json", `hello`, proto.ReasonBadRequest},
		{"wrong types", `{"v":1,"op":5}`, proto.ReasonBadRequest},
		{"negative timeout", `{"v":1,"op":"list","timeout_s":-1}`, proto.ReasonBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			frames, resp := exchange(t, r.path, []byte(tc.line))
			if len(frames) != 0 || resp.OK || resp.Error != proto.ErrBadRequest || resp.Reason != tc.reason {
				t.Errorf("frames=%v resp=%+v, want bad_request/%s", frames, resp, tc.reason)
			}
		})
	}
	if called.Load() != 0 {
		t.Errorf("handler ran for invalid requests")
	}
	// A valid request still works afterwards.
	if _, resp := call(t, r.path, proto.Request{Op: proto.OpList}); !resp.OK {
		t.Errorf("valid request failed: %+v", resp)
	}
}

func TestStreamingFramesThenResponseInOrder(t *testing.T) {
	rt := routerWith(proto.OpRun, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		for i := range 5 {
			s := proto.StreamStdout
			if i%2 == 1 {
				s = proto.StreamStderr
			}
			if err := w.Stream(s, fmt.Appendf(nil, "line %d\n", i)); err != nil {
				t.Errorf("Stream: %v", err)
			}
		}
		_ = w.Finish(&proto.Response{OK: true, ExitCode: proto.IntPtr(0), GrantID: "g1"})
	})
	r := start(t, Config{Router: rt})
	frames, resp := call(t, r.path, proto.Request{Op: proto.OpRun, Argv: []string{"x"}})
	if len(frames) != 5 {
		t.Fatalf("frames = %v", frames)
	}
	for i, f := range frames {
		want := proto.StreamStdout
		if i%2 == 1 {
			want = proto.StreamStderr
		}
		if f.Stream != want || f.Data != fmt.Sprintf("line %d\n", i) {
			t.Errorf("frame %d = %+v", i, f)
		}
	}
	if !resp.OK || resp.ExitCode == nil || *resp.ExitCode != 0 || resp.GrantID != "g1" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestResponseWriterRules(t *testing.T) {
	errs := make(chan [3]error, 1)
	rt := routerWith(proto.OpList, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		var e [3]error
		e[0] = w.Stream("stdin", nil)
		e[1] = w.Finish(nil)
		_ = w.Finish(okResp())
		e[2] = w.Stream(proto.StreamStdout, []byte("late"))
		if err := w.Finish(okResp()); !errors.Is(err, ErrFinished) {
			t.Errorf("second Finish = %v", err)
		}
		errs <- e
	})
	r := start(t, Config{Router: rt})
	frames, resp := call(t, r.path, proto.Request{Op: proto.OpList})
	e := <-errs
	if e[0] == nil || e[1] == nil || !errors.Is(e[2], ErrFinished) {
		t.Errorf("errors = %v", e)
	}
	if len(frames) != 0 || !resp.OK {
		t.Errorf("frames=%v resp=%+v", frames, resp)
	}
}

func TestHandlerWithoutFinishAndPanic(t *testing.T) {
	logs := &syncBuf{}
	rt := NewRouter()
	rt.Register(proto.OpList, HandlerFunc(func(context.Context, *proto.Request, ResponseWriter) {}))
	rt.Register(proto.OpExists, HandlerFunc(func(_ context.Context, req *proto.Request, _ ResponseWriter) {
		panic("boom " + req.Value)
	}))
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, nil))})

	for _, op := range []string{proto.OpList, proto.OpExists} {
		_, resp := call(t, r.path, proto.Request{Op: op, Value: "panic-secret-value"})
		if resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonInternal {
			t.Errorf("%s: resp = %+v", op, resp)
		}
	}
	if strings.Contains(logs.String(), "panic-secret-value") {
		t.Errorf("panic value leaked into logs:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "handler panic") {
		t.Errorf("panic not logged:\n%s", logs.String())
	}
}

func TestRequestTimeout(t *testing.T) {
	s, err := New(Config{SocketPath: "x", MaxTimeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		timeoutS int
		want     time.Duration
	}{
		{0, 90 * time.Second},
		{10, 10 * time.Second},
		{90, 90 * time.Second},
		{91, 90 * time.Second},
		{1 << 40, 90 * time.Second}, // no overflow
	} {
		if got := s.requestTimeout(&proto.Request{TimeoutS: tc.timeoutS}); got != tc.want {
			t.Errorf("TimeoutS=%d: got %v, want %v", tc.timeoutS, got, tc.want)
		}
	}
	d, _ := New(Config{SocketPath: "x"})
	if d.cfg.MaxTimeout != time.Hour || d.cfg.FirstLineTimeout != 5*time.Second {
		t.Errorf("defaults: %+v", d.cfg)
	}
	if _, err := New(Config{}); err == nil {
		t.Error("New without SocketPath succeeded")
	}
}

func TestTimeoutCapAppliedToHandlerContext(t *testing.T) {
	deadlines := make(chan time.Duration, 3)
	rt := routerWith(proto.OpList, func(ctx context.Context, _ *proto.Request, w ResponseWriter) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("no deadline")
		}
		deadlines <- time.Until(dl)
		_ = w.Finish(okResp())
	})
	r := start(t, Config{Router: rt, MaxTimeout: 30 * time.Second, ApprovalGrace: time.Minute})
	for _, ts := range []int{5, 3600, 0} {
		call(t, r.path, proto.Request{Op: proto.OpList, TimeoutS: ts})
	}
	// deadline = min(timeout_s, MaxTimeout) + ApprovalGrace
	for _, want := range []time.Duration{65 * time.Second, 90 * time.Second, 90 * time.Second} {
		got := <-deadlines
		if got > want || got < want-5*time.Second {
			t.Errorf("deadline in %v, want about %v", got, want)
		}
	}
}

func TestCommandTimeoutExcludesApprovalGrace(t *testing.T) {
	got := make(chan time.Duration, 3)
	rt := routerWith(proto.OpRun, func(ctx context.Context, _ *proto.Request, w ResponseWriter) {
		d, ok := CommandTimeout(ctx)
		if !ok {
			t.Error("CommandTimeout missing")
		}
		got <- d
		_ = w.Finish(okResp())
	})
	r := start(t, Config{Router: rt, MaxTimeout: 30 * time.Second})
	for _, ts := range []int{5, 3600, 0} {
		call(t, r.path, proto.Request{Op: proto.OpRun, TimeoutS: ts})
	}
	for _, want := range []time.Duration{5 * time.Second, 30 * time.Second, 30 * time.Second} {
		if d := <-got; d != want {
			t.Errorf("command timeout %v, want %v", d, want)
		}
	}
	if _, ok := CommandTimeout(context.Background()); ok {
		t.Error("CommandTimeout set on a foreign context")
	}
	d, _ := New(Config{SocketPath: "x"})
	if d.cfg.ApprovalGrace != 10*time.Minute {
		t.Errorf("default ApprovalGrace = %v", d.cfg.ApprovalGrace)
	}
}

func TestTimeoutEnforcedWithTimeoutReason(t *testing.T) {
	rt := routerWith(proto.OpRun, func(ctx context.Context, _ *proto.Request, _ ResponseWriter) {
		<-ctx.Done() // honours ctx but sends nothing
	})
	r := start(t, Config{Router: rt, MaxTimeout: 100 * time.Millisecond, ApprovalGrace: 50 * time.Millisecond})
	begin := time.Now()
	_, resp := call(t, r.path, proto.Request{Op: proto.OpRun, TimeoutS: 3600})
	if resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonTimeout {
		t.Errorf("resp = %+v", resp)
	}
	if time.Since(begin) > 5*time.Second {
		t.Errorf("took %v", time.Since(begin))
	}
}

func TestHandlerIgnoringContextIsAbandoned(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	rt := routerWith(proto.OpRun, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		<-release
		if err := w.Finish(okResp()); err == nil {
			t.Error("Finish after abandon should fail (already finished by server)")
		}
	})
	r := start(t, Config{Router: rt, MaxTimeout: 30 * time.Millisecond, ApprovalGrace: 20 * time.Millisecond, HandlerGrace: 100 * time.Millisecond})
	_, resp := call(t, r.path, proto.Request{Op: proto.OpRun})
	if resp.OK || resp.Reason != proto.ReasonTimeout {
		t.Errorf("resp = %+v", resp)
	}
}

func TestIdleFirstLineDeadline(t *testing.T) {
	r := start(t, Config{FirstLineTimeout: 100 * time.Millisecond})
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	begin := time.Now()
	_, resp := readAll(t, c) // send nothing
	if resp.OK || resp.Error != proto.ErrBadRequest {
		t.Errorf("resp = %+v", resp)
	}
	if el := time.Since(begin); el > 3*time.Second {
		t.Errorf("server took %v to give up", el)
	}
	// Partial line (no newline) also times out.
	c2, _ := net.Dial("unix", r.path)
	defer c2.Close()
	_, _ = c2.Write([]byte(`{"v":1,"op":"stat`))
	if _, resp := readAll(t, c2); resp.OK {
		t.Errorf("partial line: %+v", resp)
	}
}

func TestClientDisconnectWithoutRequestIsQuiet(t *testing.T) {
	r := start(t, Config{})
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, resp := call(t, r.path, proto.Request{Op: proto.OpStatus}); !resp.OK {
		t.Errorf("server unhealthy: %+v", resp)
	}
}

func TestClientDisconnectCancelsHandler(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan error, 1)
	rt := routerWith(proto.OpRun, func(ctx context.Context, _ *proto.Request, _ ResponseWriter) {
		close(started)
		<-ctx.Done()
		canceled <- ctx.Err()
	})
	r := start(t, Config{Router: rt})
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Write(c, &proto.Request{V: 1, Op: proto.OpRun}); err != nil {
		t.Fatal(err)
	}
	<-started
	c.Close()
	select {
	case err := <-canceled:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ctx err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler context not cancelled on disconnect")
	}
}

func TestConcurrentConnections(t *testing.T) {
	const n = 25
	var inflight sync.WaitGroup
	inflight.Add(n)
	rt := routerWith(proto.OpExists, func(_ context.Context, req *proto.Request, w ResponseWriter) {
		// Every handler waits until all n are running at once: proves true
		// concurrency (a serial server would deadlock and time out).
		inflight.Done()
		inflight.Wait()
		_ = w.Stream(proto.StreamStdout, []byte(req.Name))
		_ = w.Finish(&proto.Response{OK: true, GrantID: req.Name})
	})
	r := start(t, Config{Router: rt})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("n%d", i)
			frames, resp := call(t, r.path, proto.Request{Op: proto.OpExists, Name: name})
			if !resp.OK || resp.GrantID != name || len(frames) != 1 || frames[0].Data != name {
				t.Errorf("%s: frames=%v resp=%+v", name, frames, resp)
			}
		}()
	}
	wg.Wait()
}

func TestGracefulShutdownDrainsAndRemovesSocket(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	rt := routerWith(proto.OpRun, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		close(started)
		<-release
		_ = w.Finish(&proto.Response{OK: true, GrantID: "done"})
	})
	r := start(t, Config{Router: rt, ShutdownGrace: 10 * time.Second})

	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := proto.Write(c, &proto.Request{V: 1, Op: proto.OpRun}); err != nil {
		t.Fatal(err)
	}
	<-started

	r.cancel()
	// Socket disappears promptly, while the request is still in flight.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(r.path); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket file not removed on shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := net.Dial("unix", r.path); err == nil {
		t.Error("new connection accepted during shutdown")
	}
	select {
	case <-r.done:
		t.Fatal("Serve returned before in-flight request finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	_, resp := readAll(t, c)
	if !resp.OK || resp.GrantID != "done" {
		t.Errorf("in-flight request lost: %+v", resp)
	}
	if err := r.stop(t); err != nil {
		t.Errorf("Serve = %v", err)
	}
}

func TestShutdownGraceExpiryCancelsHandlers(t *testing.T) {
	started := make(chan struct{})
	rt := routerWith(proto.OpRun, func(ctx context.Context, _ *proto.Request, _ ResponseWriter) {
		close(started)
		<-ctx.Done()
	})
	r := start(t, Config{Router: rt, ShutdownGrace: 100 * time.Millisecond})
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = proto.Write(c, &proto.Request{V: 1, Op: proto.OpRun})
	<-started
	r.cancel()
	_, resp := readAll(t, c)
	if resp.OK || resp.Reason != proto.ReasonCanceled {
		t.Errorf("resp = %+v, want failed/canceled", resp)
	}
	if err := r.stop(t); err != nil {
		t.Errorf("Serve = %v", err)
	}
	if _, err := os.Lstat(r.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket remains: %v", err)
	}
}

func TestSocketAndDirModes(t *testing.T) {
	base := shortDir(t)
	path := filepath.Join(base, "newdir", "s.sock")
	r := start(t, Config{SocketPath: path})
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode().Type()&os.ModeSocket == 0 {
		t.Errorf("socket mode = %v", fi.Mode())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}
	_ = r.stop(t)
}

func TestLooseExistingDirWarnsButWorks(t *testing.T) {
	base := shortDir(t)
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	r := start(t, Config{SocketPath: filepath.Join(base, "s.sock"), Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if !strings.Contains(logs.String(), "accessible by group/other") {
		t.Errorf("no warning:\n%s", logs.String())
	}
	if fi, _ := os.Stat(r.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(base); fi.Mode().Perm() != 0o755 {
		t.Errorf("existing dir was chmodded to %v", fi.Mode().Perm())
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close() // leaves a socket file nobody answers on
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("setup: no stale socket", err)
	}
	r := start(t, Config{SocketPath: path})
	if _, resp := call(t, r.path, proto.Request{Op: proto.OpStatus}); !resp.OK {
		t.Errorf("resp = %+v", resp)
	}
}

func TestLiveSocketNotStolen(t *testing.T) {
	r := start(t, Config{})
	s2, _ := New(Config{SocketPath: r.path})
	if err := s2.Listen(); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("Listen = %v, want ErrAlreadyRunning", err)
	}
	// The first daemon is unharmed.
	if _, resp := call(t, r.path, proto.Request{Op: proto.OpStatus}); !resp.OK {
		t.Errorf("resp = %+v", resp)
	}
}

func TestListenRefusals(t *testing.T) {
	dir := shortDir(t)

	f := filepath.Join(dir, "regular")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := New(Config{SocketPath: f})
	if err := s.Listen(); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file: %v", err)
	}
	if b, _ := os.ReadFile(f); string(b) != "x" {
		t.Error("regular file was touched")
	}

	s, _ = New(Config{SocketPath: filepath.Join(f, "s.sock")}) // parent is a file
	if err := s.Listen(); err == nil {
		t.Error("parent-is-file succeeded")
	}

	long := filepath.Join(dir, strings.Repeat("a", 200), "s.sock")
	s, _ = New(Config{SocketPath: long})
	if err := s.Listen(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("long path: %v", err)
	}

	s, _ = New(Config{SocketPath: "s.sock"})
	_ = s // relative path in cwd; just ensure empty-path check separately
	if _, err := listenUnix("", nil); err == nil {
		t.Error("empty path accepted")
	}

	// Listen is idempotent and Serve works after it.
	s, _ = New(Config{SocketPath: filepath.Join(dir, "ok.sock")})
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Errorf("second Listen: %v", err)
	}
	if s.SocketPath() != filepath.Join(dir, "ok.sock") {
		t.Error("SocketPath")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); err != nil {
		t.Errorf("Serve = %v", err)
	}
}

func TestCheckPeerUID(t *testing.T) {
	if err := checkPeerUID(501, 501); err != nil {
		t.Errorf("same uid: %v", err)
	}
	if err := checkPeerUID(0, 0); err != nil {
		t.Errorf("root-to-root: %v", err)
	}
	for _, tc := range []struct {
		peer uint32
		self int
	}{{0, 501}, {502, 501}, {501, 0}, {1<<32 - 1, -1}, {1<<32 - 1, 1<<32 - 1 - 1}} {
		if err := checkPeerUID(tc.peer, tc.self); err == nil {
			t.Errorf("peer=%d self=%d accepted", tc.peer, tc.self)
		}
	}
}

func TestRejectedPeerGetsPeerRejectedAndHandlerNeverRuns(t *testing.T) {
	var ran atomic.Int32
	rt := routerWith(proto.OpStatus, func(context.Context, *proto.Request, ResponseWriter) { ran.Add(1) })
	logs := &syncBuf{}
	srv, err := New(Config{SocketPath: filepath.Join(shortDir(t), "s.sock"), Router: rt, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv.peerCheck = func(*net.UnixConn) error { return errors.New("simulated other user") }
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() { cancel(); <-done }()

	c, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Do not even send a request: the rejection must not depend on it.
	_, resp := readAll(t, c)
	if resp.OK || resp.Error != proto.ErrRefused || resp.Reason != proto.ReasonPeerRejected {
		t.Errorf("resp = %+v", resp)
	}
	if ran.Load() != 0 {
		t.Error("handler ran for a rejected peer")
	}
	if !strings.Contains(logs.String(), "peer rejected") {
		t.Errorf("rejection not logged:\n%s", logs.String())
	}
}

func TestLogsNeverContainValues(t *testing.T) {
	const secret = "s3cr3t-VALUE-do-not-log-9f8e7d"
	logs := &syncBuf{}
	rt := NewRouter()
	rt.Register(proto.OpSet, HandlerFunc(func(_ context.Context, req *proto.Request, w ResponseWriter) {
		_ = w.Finish(okResp())
	}))
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})

	_, resp := call(t, r.path, proto.Request{
		Op: proto.OpSet, Caller: "claude-code", Cwd: "/work/proj", Name: "API_KEY",
		Value: secret, Notes: "note-" + secret,
	})
	if !resp.OK {
		t.Fatalf("resp = %+v", resp)
	}
	// Bad requests carrying the value must not leak it either.
	exchange(t, r.path, []byte(`{"v":1,"op":"set","value":"`+secret+`","timeout_s":"oops"}`))
	exchange(t, r.path, []byte(`{"v":7,"op":"set","value":"`+secret+`"}`))
	exchange(t, r.path, []byte(`{"v":1,"op":"nope","value":"`+secret+`"}`))
	exchange(t, r.path, []byte(`garbage `+secret))
	_ = r.stop(t)

	out := logs.String()
	if strings.Contains(out, secret) {
		t.Fatalf("log contains the secret value:\n%s", out)
	}
	for _, want := range []string{"op=set", "caller=claude-code", "cwd=/work/proj", "outcome=ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

func TestLogsRecordOutcomeAndErrors(t *testing.T) {
	logs := &syncBuf{}
	rt := routerWith(proto.OpRun, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		_ = w.Finish(&proto.Response{OK: true, ExitCode: proto.IntPtr(3)})
	})
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	call(t, r.path, proto.Request{Op: proto.OpRun, Argv: []string{"php", "artisan", "sync"}})
	call(t, r.path, proto.Request{Op: proto.OpList})
	_ = r.stop(t)
	out := logs.String()
	for _, want := range []string{"argc=3", "exit_code=3", "reason=unknown_op", "outcome=error"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

// The daemon has no redactor, so a value a caller smuggles into argv must not
// reach its log, for any outcome.
func TestLogsNeverContainArgv(t *testing.T) {
	const marker = "argv-marker-s3cr3t-7c1d"
	logs := &syncBuf{}
	rt := routerWith(proto.OpRun, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		_ = w.Finish(&proto.Response{OK: true, ExitCode: proto.IntPtr(0)})
	})
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	argv := []string{"curl", "-H", "Authorization: " + marker, marker}
	_, resp := call(t, r.path, proto.Request{Op: proto.OpRun, Caller: "tester", Cwd: "/work", Argv: argv})
	if !resp.OK {
		t.Fatalf("resp = %+v", resp)
	}
	call(t, r.path, proto.Request{Op: proto.OpRun, Argv: argv, TimeoutS: -1}) // rejected before dispatch
	call(t, r.path, proto.Request{Op: proto.OpList, Argv: argv})              // unknown op for this router
	exchange(t, r.path, []byte(`{"v":9,"op":"run","argv":["`+marker+`"]}`))   // bad version
	_ = r.stop(t)
	out := logs.String()
	if strings.Contains(out, marker) {
		t.Fatalf("argv leaked into the daemon log:\n%s", out)
	}
	for _, want := range []string{"op=run", "caller=tester", "cwd=/work", "argc=4", "outcome=ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

// A response that cannot be encoded within MaxLineBytes used to be dropped
// silently: the client saw EOF and the log said ok. It must become a small
// failure the client can read, and the log must say failed.
func TestOversizedResponseBecomesAFailure(t *testing.T) {
	logs := &syncBuf{}
	var finishErr error
	rt := routerWith(proto.OpList, func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		huge, _ := json.Marshal(strings.Repeat("x", proto.MaxLineBytes))
		finishErr = w.Finish(&proto.Response{OK: true, Result: huge})
	})
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	_, resp := call(t, r.path, proto.Request{Op: proto.OpList})
	if resp.OK || resp.Error != proto.ErrFailed || resp.Reason != proto.ReasonInternal || resp.Message != "response too large" {
		t.Fatalf("resp = %+v", resp)
	}
	_ = r.stop(t)
	if !errors.Is(finishErr, proto.ErrLineTooLong) {
		t.Errorf("Finish returned %v, want the handler told the response did not fit", finishErr)
	}
	out := logs.String()
	if !strings.Contains(out, "outcome=failed") || strings.Contains(out, "outcome=ok") {
		t.Errorf("log should say failed:\n%s", out)
	}
}

func TestRouter(t *testing.T) {
	r := NewRouter()
	h := HandlerFunc(func(context.Context, *proto.Request, ResponseWriter) {})
	r.Register(proto.OpRun, h)
	r.Register(proto.OpList, h)
	if got := r.Ops(); len(got) != 2 || got[0] != proto.OpList || got[1] != proto.OpRun {
		t.Errorf("Ops = %v", got)
	}
	if _, ok := r.Lookup(proto.OpRun); !ok {
		t.Error("Lookup run")
	}
	if _, ok := r.Lookup(proto.OpSet); ok {
		t.Error("Lookup unregistered")
	}
	for name, f := range map[string]func(){
		"duplicate":  func() { r.Register(proto.OpRun, h) },
		"unknown op": func() { r.Register("nope", h) },
		"nil":        func() { r.Register(proto.OpSet, nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
	if f := Failure(proto.ErrDenied, proto.ReasonUserDenied); f.OK || f.Error != "denied" || f.Reason != "user_denied" {
		t.Errorf("Failure = %+v", f)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	t.Setenv(SocketEnv, "/x/override.sock")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1")
	if p, err := DefaultSocketPath(); err != nil || p != "/x/override.sock" {
		t.Errorf("override: %q %v", p, err)
	}

	t.Setenv(SocketEnv, "")
	if p, err := DefaultSocketPath(); err != nil || p != "/run/user/1/grantpin.sock" {
		t.Errorf("xdg runtime: %q %v", p, err)
	}

	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_DATA_HOME", "")
	p, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	want := "/home/u/.local/share/grantpin/grantpin.sock"
	if runtime.GOOS == "darwin" {
		want = "/home/u/Library/Application Support/grantpin/grantpin.sock"
	}
	if p != want {
		t.Errorf("fallback: %q, want %q", p, want)
	}

	if runtime.GOOS != "darwin" {
		t.Setenv("XDG_DATA_HOME", "/data")
		if p, _ := DefaultSocketPath(); p != "/data/grantpin/grantpin.sock" {
			t.Errorf("xdg data: %q", p)
		}
	}
}

func TestBackoff(t *testing.T) {
	if backoff(0) != 10*time.Millisecond || backoff(600*time.Millisecond) != time.Second || backoff(time.Second) != time.Second {
		t.Error("backoff")
	}
}

func TestClipLogBoundsUntrustedFields(t *testing.T) {
	if got := clipLog("/work/proj"); got != "/work/proj" {
		t.Fatalf("short field changed: %q", got)
	}
	long := strings.Repeat("x", 3<<20)
	if got := clipLog(long); len(got) != maxLogField || !strings.HasSuffix(got, "...") {
		t.Fatalf("long field: %d bytes", len(got))
	}
	// Never cuts inside a multi-byte character.
	for n := 190; n < 210; n++ {
		got := clipLog(strings.Repeat("x", n-190) + strings.Repeat("€", 100))
		if len(got) > maxLogField || !utf8.ValidString(got) {
			t.Fatalf("n=%d: %d bytes, valid=%v", n, len(got), utf8.ValidString(got))
		}
	}
}

func TestLogRequestClipsCallerAndCwd(t *testing.T) {
	logs := &syncBuf{}
	rt := NewRouter()
	rt.Register(proto.OpList, HandlerFunc(func(_ context.Context, _ *proto.Request, w ResponseWriter) {
		_ = w.Finish(okResp())
	}))
	r := start(t, Config{Router: rt, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	_, _ = call(t, r.path, proto.Request{Op: proto.OpList, Caller: strings.Repeat("c", 1<<20), Cwd: "/" + strings.Repeat("d", 1<<20)})
	_ = r.stop(t)
	if out := logs.String(); len(out) > 4<<10 || !strings.Contains(out, "op=list") {
		t.Fatalf("log is %d bytes:\n%.300s", len(out), out)
	}
}

// closeHook wraps a listener and runs hook right after the real Close, to
// simulate a successor daemon binding the path the instant ours is released.
type closeHook struct {
	net.Listener
	hook func()
	once sync.Once
}

func (c *closeHook) Close() error {
	err := c.Listener.Close()
	c.once.Do(c.hook)
	return err
}

func TestShutdownDoesNotRemoveSuccessorSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	srv, err := New(Config{SocketPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	var successor net.Listener
	srv.ln = &closeHook{Listener: srv.ln, hook: func() {
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Errorf("successor bind: %v", err)
			return
		}
		successor = l
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	if successor == nil {
		t.Fatal("successor was not bound")
	}
	defer successor.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("successor socket was removed by the old daemon: %v", err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial successor: %v", err)
	}
	c.Close()
}
