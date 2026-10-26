package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
)

// ---- fake daemon ----

type fake struct {
	t      *testing.T
	path   string
	router *daemon.Router

	mu   sync.Mutex
	reqs []proto.Request
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "m")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func newFake(t *testing.T) *fake {
	t.Helper()
	return &fake{t: t, path: filepath.Join(shortDir(t), "s.sock"), router: daemon.NewRouter()}
}

// on registers a handler for op that records the request first.
func (f *fake) on(op string, h func(req *proto.Request, w daemon.ResponseWriter)) {
	f.router.Register(op, daemon.HandlerFunc(func(_ context.Context, req *proto.Request, w daemon.ResponseWriter) {
		f.mu.Lock()
		f.reqs = append(f.reqs, *req)
		f.mu.Unlock()
		h(req, w)
	}))
}

func (f *fake) requests() []proto.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proto.Request(nil), f.reqs...)
}

// listen starts the daemon on f.path and stops it at test end.
func (f *fake) listen() {
	f.t.Helper()
	srv, err := daemon.New(daemon.Config{SocketPath: f.path, Router: f.router, ShutdownGrace: time.Second})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(done) }()
	f.t.Cleanup(func() { cancel(); <-done })
}

func ok(t *testing.T, w daemon.ResponseWriter, result any, mod func(*proto.Response)) {
	t.Helper()
	resp := &proto.Response{OK: true}
	if result != nil {
		raw, err := proto.NewResult(result)
		if err != nil {
			t.Error(err)
		}
		resp.Result = raw
	}
	if mod != nil {
		mod(resp)
	}
	_ = w.Finish(resp)
}

// ---- MCP plumbing ----

func connect(t *testing.T, cfg Config, clientName string) *sdk.ClientSession {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t1, t2 := sdk.NewInMemoryTransports()
	ss, err := srv.SDK().Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := sdk.NewClient(&sdk.Implementation{Name: clientName, Version: "1"}, nil)
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Wait(); cancel() })
	return cs
}

func setup(t *testing.T, f *fake, mod func(*Config)) *sdk.ClientSession {
	t.Helper()
	f.listen()
	cfg := Config{SocketPath: f.path, Getwd: func() (string, error) { return "/work/proj", nil }}
	if mod != nil {
		mod(&cfg)
	}
	return connect(t, cfg, "claude-code")
}

func call(t *testing.T, cs *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: protocol error: %v", name, err)
	}
	return res
}

func text(res *sdk.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func structured(t *testing.T, res *sdk.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// ---- tests ----

func TestToolListIsExactlyFour(t *testing.T) {
	f := newFake(t)
	cs := setup(t, f, nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
		if tl.InputSchema == nil || tl.OutputSchema == nil {
			t.Errorf("%s: missing schema", tl.Name)
		}
	}
	want := []string{"secret_exists", "secret_list", "secret_masked", "secret_run"}
	if len(got) != len(want) {
		t.Fatalf("tools = %v, want exactly %v", got, want)
	}
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("missing tool %s (got %v)", n, got)
		}
	}
}

func TestRunSchemaRequiredFields(t *testing.T) {
	f := newFake(t)
	cs := setup(t, f, nil)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		b, _ := json.MarshalIndent(map[string]any{"in": tl.InputSchema, "out": tl.OutputSchema}, "", " ")
		t.Logf("%s schema: %s", tl.Name, b)
		if tl.Name != ToolRun {
			continue
		}
		in := tl.InputSchema.(map[string]any)
		req, _ := in["required"].([]any)
		got := map[string]bool{}
		for _, r := range req {
			got[r.(string)] = true
		}
		if !got["argv"] || !got["secrets"] || got["cwd"] || got["timeout_s"] || len(got) != 2 {
			t.Errorf("secret_run required = %v, want exactly argv, secrets", req)
		}
	}
}

// Guard against a future "convenience" tool that returns values: the shim must
// never reference the show op or its result type.
func TestSourceNeverReferencesShow(t *testing.T) {
	forbidden := []string{"Op" + "Show", "Show" + "Result"}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v %v", files, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range forbidden {
			if strings.Contains(string(b), s) {
				t.Errorf("%s references %q; the MCP shim must never touch the show op", f, s)
			}
		}
	}
}

func TestList(t *testing.T) {
	f := newFake(t)
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f.on(proto.OpList, func(_ *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, []proto.SecretInfo{
			{Name: "aws/key", Tags: []string{"prod"}, URL: "https://x", Notes: "private note", ExpiresAt: &exp, MinTier: presence.TierHardware},
			{Name: "DB_URL", MinTier: presence.TierDialog},
		}, nil)
	})
	cs := setup(t, f, nil)
	res := call(t, cs, ToolList, map[string]any{})
	var out listOutput
	structured(t, res, &out)
	if len(out.Secrets) != 2 {
		t.Fatalf("secrets = %+v", out.Secrets)
	}
	a := out.Secrets[0]
	if a.Name != "aws/key" || a.URL != "https://x" || a.ExpiresAt != "2030-01-02T03:04:05Z" || a.MinTier != "hardware" || len(a.Tags) != 1 {
		t.Errorf("entry = %+v", a)
	}
	if out.Secrets[1].MinTier != "dialog" || out.Secrets[1].ExpiresAt != "" {
		t.Errorf("entry = %+v", out.Secrets[1])
	}
	if strings.Contains(text(res), "private note") {
		t.Error("notes leaked into list output")
	}
	reqs := f.requests()
	if len(reqs) != 1 || reqs[0].Op != proto.OpList || reqs[0].Caller != "claude-code" {
		t.Errorf("requests = %+v", reqs)
	}
}

func TestListEmpty(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpList, func(_ *proto.Request, w daemon.ResponseWriter) { ok(t, w, nil, nil) })
	cs := setup(t, f, nil)
	var out listOutput
	structured(t, call(t, cs, ToolList, nil), &out)
	if out.Secrets == nil || len(out.Secrets) != 0 {
		t.Errorf("secrets = %#v, want empty non-nil", out.Secrets)
	}
}

func TestExistsAndMasked(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpExists, func(r *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, proto.ExistsResult{Exists: r.Name == "A"}, nil)
	})
	f.on(proto.OpMasked, func(r *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, proto.MaskedResult{Masked: "****WXYZ"}, nil)
	})
	cs := setup(t, f, nil)

	var e existsOutput
	structured(t, call(t, cs, ToolExists, map[string]any{"name": "A"}), &e)
	if !e.Exists {
		t.Error("A should exist")
	}
	structured(t, call(t, cs, ToolExists, map[string]any{"name": "B"}), &e)
	if e.Exists {
		t.Error("B should not exist")
	}
	var m maskedOutput
	structured(t, call(t, cs, ToolMasked, map[string]any{"name": "A"}), &m)
	if m.Masked != "****WXYZ" {
		t.Errorf("masked = %q", m.Masked)
	}
	reqs := f.requests()
	if len(reqs) != 3 || reqs[2].Op != proto.OpMasked || reqs[2].Name != "A" {
		t.Errorf("requests = %+v", reqs)
	}

	for _, tool := range []string{ToolExists, ToolMasked} {
		for _, args := range []any{map[string]any{"name": ""}, map[string]any{}} {
			if res := call(t, cs, tool, args); !res.IsError {
				t.Errorf("%s %v: want tool error", tool, args)
			}
		}
	}
	if n := len(f.requests()); n != 3 {
		t.Errorf("invalid calls reached the daemon: %d requests", n)
	}
}

func TestDaemonErrorsAreToolErrors(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpMasked, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Finish(daemon.Failure(proto.ErrNotFound, proto.ReasonSecretNotFound))
	})
	f.on(proto.OpExists, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Finish(daemon.Failure(proto.ErrRefused, proto.ReasonPeerRejected))
	})
	f.on(proto.OpList, func(_ *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, "not a list", nil) // malformed result
	})
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Finish(daemon.Failure(proto.ErrDenied, proto.ReasonUserDenied))
	})
	cs := setup(t, f, nil)
	cases := []struct {
		tool string
		args any
		want string
	}{
		{ToolMasked, map[string]any{"name": "X"}, "not_found: secret_not_found"},
		{ToolExists, map[string]any{"name": "X"}, "refused: peer_rejected"},
		{ToolList, nil, "malformed"},
		{ToolRun, map[string]any{"argv": []string{"true"}, "secrets": []string{"A"}}, "denied: user_denied"},
	}
	for _, c := range cases {
		res := call(t, cs, c.tool, c.args)
		if !res.IsError || !strings.Contains(text(res), c.want) {
			t.Errorf("%s: IsError=%v text=%q, want error containing %q", c.tool, res.IsError, text(res), c.want)
		}
	}
}

func TestRunCollectsStreams(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Stream(proto.StreamStdout, []byte("hello "))
		_ = w.Stream(proto.StreamStderr, []byte("warn\n"))
		_ = w.Stream(proto.StreamStdout, []byte("[REDACTED:API_KEY] world"))
		ok(t, w, nil, func(r *proto.Response) { r.ExitCode = proto.IntPtr(3); r.GrantID = "g-1" })
	})
	cs := setup(t, f, nil)
	res := call(t, cs, ToolRun, map[string]any{
		"argv": []string{"php", "artisan", "sync"}, "secrets": []string{"API_KEY", "aws/*"}, "cwd": "/abs/dir/../dir", "timeout_s": 30,
	})
	var out runOutput
	structured(t, res, &out)
	if out.ExitCode != 3 || out.Stdout != "hello [REDACTED:API_KEY] world" || out.Stderr != "warn\n" || out.GrantID != "g-1" {
		t.Errorf("out = %+v", out)
	}
	r := f.requests()[0]
	if r.Op != proto.OpRun || r.Cwd != "/abs/dir" || r.TimeoutS != 30 || r.Caller != "claude-code" ||
		strings.Join(r.Argv, " ") != "php artisan sync" || strings.Join(r.Secrets, ",") != "API_KEY,aws/*" {
		t.Errorf("request = %+v", r)
	}
}

func TestRunExitCodeZeroAndDefaultCwd(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, nil, func(r *proto.Response) { r.ExitCode = proto.IntPtr(0) })
	})
	cs := setup(t, f, nil)
	var out runOutput
	structured(t, call(t, cs, ToolRun, map[string]any{"argv": []string{"true"}, "secrets": []string{"A"}}), &out)
	if out.ExitCode != 0 {
		t.Errorf("out = %+v", out)
	}
	if r := f.requests()[0]; r.Cwd != "/work/proj" || r.TimeoutS != 0 {
		t.Errorf("request = %+v, want default cwd /work/proj", r)
	}
}

func TestRunOutputTruncated(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Stream(proto.StreamStdout, []byte("0123456789"))
		_ = w.Stream(proto.StreamStdout, []byte("abcdefghij")) // over the 16-byte cap
		_ = w.Stream(proto.StreamStdout, []byte("ignored"))
		_ = w.Stream(proto.StreamStderr, []byte("short"))
		ok(t, w, nil, func(r *proto.Response) { r.ExitCode = proto.IntPtr(0) })
	})
	cs := setup(t, f, func(c *Config) { c.MaxOutput = 16 })
	var out runOutput
	structured(t, call(t, cs, ToolRun, map[string]any{"argv": []string{"x"}, "secrets": []string{"A"}}), &out)
	if !strings.HasPrefix(out.Stdout, "0123456789abcdef\n[grantd mcp: output truncated at 16 bytes]") {
		t.Errorf("stdout = %q", out.Stdout)
	}
	if strings.Contains(out.Stdout, "ignored") || out.Stderr != "short" {
		t.Errorf("out = %+v", out)
	}
}

func TestCappedRuneBoundary(t *testing.T) {
	c := newCapped(4)
	c.write("ab€") // € is 3 bytes: "ab" + 3 = 5 > 4, must not split it
	if got := c.String(); !strings.HasPrefix(got, "ab\n[grantd mcp") {
		t.Errorf("got %q", got)
	}
	c = newCapped(5)
	c.write("ab€")
	if got := c.String(); got != "ab€" {
		t.Errorf("got %q", got)
	}
}

func TestRunErrorKeepsPartialOutput(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		_ = w.Stream(proto.StreamStdout, []byte("partial-out"))
		_ = w.Finish(daemon.Failure(proto.ErrFailed, proto.ReasonTimeout))
	})
	cs := setup(t, f, nil)
	res := call(t, cs, ToolRun, map[string]any{"argv": []string{"x"}, "secrets": []string{"A"}})
	if !res.IsError || !strings.Contains(text(res), "failed: timeout") || !strings.Contains(text(res), "partial-out") {
		t.Errorf("IsError=%v text=%q", res.IsError, text(res))
	}
}

func TestRunNoExitCode(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) { ok(t, w, nil, nil) })
	cs := setup(t, f, nil)
	res := call(t, cs, ToolRun, map[string]any{"argv": []string{"x"}, "secrets": []string{"A"}})
	if !res.IsError || !strings.Contains(text(res), "no exit code") {
		t.Errorf("IsError=%v text=%q", res.IsError, text(res))
	}
}

func TestRunInputValidation(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpRun, func(_ *proto.Request, w daemon.ResponseWriter) {
		ok(t, w, nil, func(r *proto.Response) { r.ExitCode = proto.IntPtr(0) })
	})
	cs := setup(t, f, nil)
	s := []string{"A"}
	for name, args := range map[string]map[string]any{
		"relative cwd":    {"argv": []string{"x"}, "secrets": s, "cwd": "rel/dir"},
		"dot cwd":         {"argv": []string{"x"}, "secrets": s, "cwd": "."},
		"empty argv":      {"argv": []string{}, "secrets": s},
		"blank argv0":     {"argv": []string{""}, "secrets": s},
		"missing argv":    {"secrets": s},
		"empty secrets":   {"argv": []string{"x"}, "secrets": []string{}},
		"blank secret":    {"argv": []string{"x"}, "secrets": []string{""}},
		"missing secrets": {"argv": []string{"x"}},
		"negative t/o":    {"argv": []string{"x"}, "secrets": s, "timeout_s": -1},
	} {
		if res := call(t, cs, ToolRun, args); !res.IsError {
			t.Errorf("%s: want tool error, got %q", name, text(res))
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d invalid requests reached the daemon", n)
	}
}

func TestRunCwdProblems(t *testing.T) {
	f := newFake(t)
	cs := setup(t, f, func(c *Config) { c.Getwd = func() (string, error) { return "", errors.New("boom") } })
	res := call(t, cs, ToolRun, map[string]any{"argv": []string{"x"}, "secrets": []string{"A"}})
	if !res.IsError || !strings.Contains(text(res), "working directory") {
		t.Errorf("text=%q", text(res))
	}
	cs = connect(t, Config{SocketPath: f.path, Getwd: func() (string, error) { return "relative", nil }}, "c")
	res = call(t, cs, ToolRun, map[string]any{"argv": []string{"x"}, "secrets": []string{"A"}})
	if !res.IsError || !strings.Contains(text(res), "absolute") {
		t.Errorf("text=%q", text(res))
	}
}

func TestCallerDerivation(t *testing.T) {
	for in, want := range map[string]string{
		"claude-code":            "claude-code",
		"Claude Code":            "claude_code",
		"Cursor/1.2 (beta)":      "cursor_1.2__beta_",
		"":                       "mcp",
		"   ":                    "mcp",
		"é":                      "_",
		strings.Repeat("A", 100): strings.Repeat("a", 64),
	} {
		if got := SanitizeCaller(in); got != want {
			t.Errorf("SanitizeCaller(%q) = %q, want %q", in, got, want)
		}
	}

	f := newFake(t)
	f.on(proto.OpExists, func(_ *proto.Request, w daemon.ResponseWriter) { ok(t, w, proto.ExistsResult{}, nil) })
	f.listen()
	for _, name := range []string{"My Client!", ""} {
		cs := connect(t, Config{SocketPath: f.path}, name)
		call(t, cs, ToolExists, map[string]any{"name": "A"})
	}
	reqs := f.requests()
	if len(reqs) != 2 || reqs[0].Caller != "my_client_" || reqs[1].Caller != "mcp" {
		t.Errorf("callers = %+v", reqs)
	}
	if got := callerFor(nil); got != "mcp" {
		t.Errorf("callerFor(nil) = %q", got)
	}
}

// ---- auto-start ----

func TestAutoStartInvokedOnceAndRetries(t *testing.T) {
	f := newFake(t)
	f.on(proto.OpExists, func(_ *proto.Request, w daemon.ResponseWriter) { ok(t, w, proto.ExistsResult{Exists: true}, nil) })
	var started atomic.Int32
	cs := connect(t, Config{
		SocketPath: f.path,
		StartWait:  3 * time.Second,
		Starter: func(context.Context) error {
			started.Add(1)
			f.listen() // the "daemon" comes up
			return nil
		},
	}, "claude-code")
	var out existsOutput
	structured(t, call(t, cs, ToolExists, map[string]any{"name": "A"}), &out)
	if !out.Exists || started.Load() != 1 {
		t.Errorf("exists=%v started=%d", out.Exists, started.Load())
	}
	// Daemon is up now; further calls must not start anything.
	structured(t, call(t, cs, ToolExists, map[string]any{"name": "A"}), &out)
	if started.Load() != 1 {
		t.Errorf("started = %d, want 1", started.Load())
	}
}

func TestAutoStartFailureModes(t *testing.T) {
	cases := map[string]struct {
		starter   func(*atomic.Int32) Starter
		wantStart int32
	}{
		"nil starter": {func(*atomic.Int32) Starter { return nil }, 0},
		"starter error": {func(n *atomic.Int32) Starter {
			return func(context.Context) error { n.Add(1); return errors.New("spawn failed") }
		}, 2}, // a synchronous failure spawned nothing: the second call retries at once
		"never comes up": {func(n *atomic.Int32) Starter {
			return func(context.Context) error { n.Add(1); return nil }
		}, 1}, // second call is within the cooldown: no second attempt
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t) // never listens
			var n atomic.Int32
			cs := connect(t, Config{SocketPath: f.path, Starter: c.starter(&n), StartWait: 200 * time.Millisecond}, "x")
			for i := 0; i < 2; i++ {
				res := call(t, cs, ToolList, nil)
				if !res.IsError || !strings.Contains(text(res), NotRunningMessage) {
					t.Fatalf("call %d: IsError=%v text=%q", i, res.IsError, text(res))
				}
			}
			if n.Load() != c.wantStart {
				t.Errorf("starter invoked %d times, want %d", n.Load(), c.wantStart)
			}
		})
	}
}

func TestAutoStartHonoursCancel(t *testing.T) {
	f := newFake(t)
	s, err := New(Config{SocketPath: f.path, StartWait: 5 * time.Second, Starter: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.ensureDaemon(ctx); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("err=%v after %v, want prompt cancellation error", err, time.Since(start))
	}
}

// ---- misc ----

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty socket path should be rejected")
	}
	if err := Serve(context.Background(), Config{}, nil); err == nil {
		t.Error("Serve with empty config should fail")
	}
}

func TestServeRunsUntilClientCloses(t *testing.T) {
	f := newFake(t)
	f.listen()
	t1, t2 := sdk.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), Config{SocketPath: f.path}, t1) }()
	c := sdk.NewClient(&sdk.Implementation{Name: "c", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = cs.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after client closed")
	}
}

func TestDaemonEnvAllowList(t *testing.T) {
	env := map[string]string{
		"HOME": "/h", "PATH": "/bin", "GRANTD_SOCKET": "/x", "AWS_SECRET_ACCESS_KEY": "s3cr3t", "API_KEY": "k",
	}
	got := daemonEnv(func(k string) string { return env[k] })
	if len(got) != 2 || got[0] != "HOME=/h" || got[1] != "PATH=/bin" {
		t.Errorf("env = %v", got)
	}
}

func TestStarterErrorDoesNotStartCooldown(t *testing.T) {
	f := newFake(t) // never listens until the second attempt succeeds
	var n atomic.Int32
	s, err := New(Config{SocketPath: f.path, StartWait: 2 * time.Second, Starter: func(context.Context) error {
		if n.Add(1) == 1 {
			return errors.New("spawn failed")
		}
		f.listen()
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensureDaemon(context.Background()); err == nil {
		t.Fatal("first attempt should fail")
	}
	if !s.lastStartAt.IsZero() {
		t.Error("a failed Starter recorded lastStartAt")
	}
	if err := s.ensureDaemon(context.Background()); err != nil {
		t.Fatalf("immediate retry: %v", err)
	}
	if n.Load() != 2 {
		t.Errorf("starter invoked %d times, want 2", n.Load())
	}
}
