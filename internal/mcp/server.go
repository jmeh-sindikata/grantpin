package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jmeh-sindikata/grantpin/internal/client"
	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// Tool names. These are fixed by HANDOFF §9; do not add to this list.
const (
	ToolList   = "secret_list"
	ToolExists = "secret_exists"
	ToolMasked = "secret_masked"
	ToolRun    = "secret_run"
)

// Defaults.
const (
	// DefaultMaxOutput caps each of stdout and stderr in a secret_run result.
	DefaultMaxOutput = 1 << 20
	// DefaultStartWait is how long to poll the socket after auto-starting.
	DefaultStartWait = 5 * time.Second
	// DefaultCaller is used when the MCP client sent no usable name.
	DefaultCaller = "mcp"

	startPoll     = 50 * time.Millisecond
	startCooldown = 30 * time.Second
)

// NotRunningMessage is the tool error text when the daemon cannot be reached
// and auto-start did not help.
const NotRunningMessage = "grantpin daemon is not running; run `grantpin daemon` or `grantpin service install`"

// Starter launches the daemon (detached) so the shim can retry. It must return
// promptly; the shim polls the socket afterwards. Tests inject a fake.
type Starter func(ctx context.Context) error

// Config configures a Server.
type Config struct {
	// SocketPath is the daemon socket. Required.
	SocketPath string
	// Starter auto-starts the daemon on client.ErrNotRunning. nil disables
	// auto-start (the tool then reports NotRunningMessage).
	Starter Starter
	// Logger receives operational logs (op names only, never arguments). nil
	// discards. It must not write to stdout, which is the protocol channel.
	Logger *slog.Logger
	// Version is advertised in the MCP initialize result. Default "dev".
	Version string
	// MaxOutput caps each of stdout/stderr in secret_run (bytes). 0 = DefaultMaxOutput.
	MaxOutput int
	// StartWait bounds polling after Starter. 0 = DefaultStartWait.
	StartWait time.Duration
	// Getwd returns the shim's working directory. nil = os.Getwd.
	Getwd func() (string, error)
}

// Server is the MCP shim.
type Server struct {
	cfg Config
	log *slog.Logger
	srv *sdk.Server

	startMu     sync.Mutex
	lastStartAt time.Time
}

// New builds a Server with the four tools registered.
func New(cfg Config) (*Server, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("mcp: empty socket path")
	}
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutput
	}
	if cfg.StartWait <= 0 {
		cfg.StartWait = DefaultStartWait
	}
	if cfg.Getwd == nil {
		cfg.Getwd = os.Getwd
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	s := &Server{cfg: cfg, log: cfg.Logger}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.srv = sdk.NewServer(&sdk.Implementation{Name: "grantpin", Version: cfg.Version}, &sdk.ServerOptions{
		Instructions: "grantpin runs commands with secrets injected after a human approves; no tool here ever returns a secret value. " +
			"Use secret_list to discover names, secret_run to run a command with secrets in its environment.",
	})
	s.register()
	return s, nil
}

// Serve builds a Server from cfg and runs it over t until the client
// disconnects or ctx is cancelled.
func Serve(ctx context.Context, cfg Config, t sdk.Transport) error {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	return s.Run(ctx, t)
}

// Run serves one session over t.
func (s *Server) Run(ctx context.Context, t sdk.Transport) error {
	return s.srv.Run(ctx, t)
}

// SDK returns the underlying MCP server (for tests that Connect directly).
func (s *Server) SDK() *sdk.Server { return s.srv }

// ---- tool types ----

type listInput struct{}

// SecretEntry is one secret's metadata. It never carries a value.
type SecretEntry struct {
	Name      string   `json:"name" jsonschema:"secret name, e.g. aws/access_key"`
	Tags      []string `json:"tags,omitempty" jsonschema:"free-form tags"`
	URL       string   `json:"url,omitempty" jsonschema:"where the secret is used or issued"`
	ExpiresAt string   `json:"expires_at,omitempty" jsonschema:"RFC 3339 expiry time, if any"`
	MinTier   string   `json:"min_tier" jsonschema:"minimum presence tier needed to release it: none, dialog or hardware"`
}

type listOutput struct {
	Secrets []SecretEntry `json:"secrets" jsonschema:"stored secrets (metadata only, never values)"`
}

type nameInput struct {
	Name string `json:"name" jsonschema:"secret name"`
}

type existsOutput struct {
	Exists bool `json:"exists" jsonschema:"whether a secret with that name exists"`
}

type maskedOutput struct {
	Masked string `json:"masked" jsonschema:"the secret masked to its last 4 characters (fully masked if short); not usable as a credential"`
}

type runInput struct {
	Argv     []string `json:"argv" jsonschema:"command and arguments, executed directly without a shell"`
	Secrets  []string `json:"secrets" jsonschema:"secret names or globs (e.g. aws/*) to inject as environment variables"`
	Cwd      string   `json:"cwd,omitempty" jsonschema:"absolute working directory; defaults to the MCP server's own working directory"`
	TimeoutS int      `json:"timeout_s,omitempty" jsonschema:"timeout in seconds; 0 or omitted uses the daemon default"`
}

type runOutput struct {
	ExitCode int    `json:"exit_code" jsonschema:"process exit code"`
	Stdout   string `json:"stdout" jsonschema:"redacted standard output (truncated at 1 MiB)"`
	Stderr   string `json:"stderr" jsonschema:"redacted standard error (truncated at 1 MiB)"`
	GrantID  string `json:"grant_id" jsonschema:"id of the grant that authorised the run, if any"`
}

func (s *Server) register() {
	ro := &sdk.ToolAnnotations{ReadOnlyHint: true}
	sdk.AddTool(s.srv, &sdk.Tool{
		Name:        ToolList,
		Description: "List stored secrets: names and metadata (tags, url, expires_at, min_tier). Never returns values.",
		Annotations: ro,
	}, s.handleList)
	sdk.AddTool(s.srv, &sdk.Tool{
		Name:        ToolExists,
		Description: "Check whether a secret with the given name exists.",
		Annotations: ro,
	}, s.handleExists)
	sdk.AddTool(s.srv, &sdk.Tool{
		Name:        ToolMasked,
		Description: "Return a masked form of a secret (last 4 characters only, fully masked if shorter than 12) to confirm which value is stored. Not a usable credential.",
		Annotations: ro,
	}, s.handleMasked)
	destructive := true
	openWorld := true
	sdk.AddTool(s.srv, &sdk.Tool{
		Name: ToolRun,
		Description: "Run a command with the named secrets injected as environment variables. " +
			"A human must approve the release (unless a matching grant exists), so the call may block while a prompt is shown. " +
			"Output is redacted: injected values appear as [REDACTED:NAME]. The secret values are never returned.",
		Annotations: &sdk.ToolAnnotations{DestructiveHint: &destructive, OpenWorldHint: &openWorld},
	}, s.handleRun)
}

// ---- handlers ----

func (s *Server) handleList(ctx context.Context, req *sdk.CallToolRequest, _ listInput) (*sdk.CallToolResult, listOutput, error) {
	resp, err := s.do(ctx, req, &proto.Request{Op: proto.OpList}, nil)
	if err != nil {
		return nil, listOutput{}, err
	}
	var infos []proto.SecretInfo
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &infos); err != nil {
			return nil, listOutput{}, errors.New("grantpin: malformed list result from daemon")
		}
	}
	out := listOutput{Secrets: make([]SecretEntry, 0, len(infos))}
	for _, in := range infos {
		e := SecretEntry{Name: in.Name, Tags: in.Tags, URL: in.URL, MinTier: in.MinTier.String()}
		if in.ExpiresAt != nil {
			e.ExpiresAt = in.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out.Secrets = append(out.Secrets, e)
	}
	return nil, out, nil
}

func (s *Server) handleExists(ctx context.Context, req *sdk.CallToolRequest, in nameInput) (*sdk.CallToolResult, existsOutput, error) {
	if in.Name == "" {
		return nil, existsOutput{}, errors.New("name is required")
	}
	resp, err := s.do(ctx, req, &proto.Request{Op: proto.OpExists, Name: in.Name}, nil)
	if err != nil {
		return nil, existsOutput{}, err
	}
	var r proto.ExistsResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, existsOutput{}, errors.New("grantpin: malformed exists result from daemon")
	}
	return nil, existsOutput{Exists: r.Exists}, nil
}

func (s *Server) handleMasked(ctx context.Context, req *sdk.CallToolRequest, in nameInput) (*sdk.CallToolResult, maskedOutput, error) {
	if in.Name == "" {
		return nil, maskedOutput{}, errors.New("name is required")
	}
	resp, err := s.do(ctx, req, &proto.Request{Op: proto.OpMasked, Name: in.Name}, nil)
	if err != nil {
		return nil, maskedOutput{}, err
	}
	var r proto.MaskedResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, maskedOutput{}, errors.New("grantpin: malformed masked result from daemon")
	}
	return nil, maskedOutput{Masked: r.Masked}, nil
}

func (s *Server) handleRun(ctx context.Context, req *sdk.CallToolRequest, in runInput) (*sdk.CallToolResult, runOutput, error) {
	if len(in.Argv) == 0 || in.Argv[0] == "" {
		return nil, runOutput{}, errors.New("argv must be a non-empty command (argv[0] is the program)")
	}
	if len(in.Secrets) == 0 {
		return nil, runOutput{}, errors.New("secrets must list at least one secret name or glob")
	}
	for _, n := range in.Secrets {
		if n == "" {
			return nil, runOutput{}, errors.New("secrets must not contain empty names")
		}
	}
	if in.TimeoutS < 0 {
		return nil, runOutput{}, errors.New("timeout_s must not be negative")
	}
	cwd := in.Cwd
	if cwd == "" {
		wd, err := s.cfg.Getwd()
		if err != nil {
			return nil, runOutput{}, fmt.Errorf("cannot determine working directory: %w; pass an absolute cwd", err)
		}
		cwd = wd
	}
	if !filepath.IsAbs(cwd) {
		return nil, runOutput{}, fmt.Errorf("cwd must be an absolute path, got %q", cwd)
	}
	cwd = filepath.Clean(cwd)

	stdout := newCapped(s.cfg.MaxOutput)
	stderr := newCapped(s.cfg.MaxOutput)
	onStream := func(f proto.StreamFrame) {
		switch f.Stream {
		case proto.StreamStdout:
			stdout.write(f.Data)
		case proto.StreamStderr:
			stderr.write(f.Data)
		}
	}
	pr := &proto.Request{
		Op:       proto.OpRun,
		Cwd:      cwd,
		Argv:     in.Argv,
		Secrets:  in.Secrets,
		TimeoutS: in.TimeoutS,
	}
	resp, err := s.do(ctx, req, pr, onStream)
	if err != nil {
		// Surface whatever (already redacted) output arrived before the failure,
		// e.g. before a timeout.
		if so, se := stdout.String(), stderr.String(); so != "" || se != "" {
			err = fmt.Errorf("%w\n--- stdout ---\n%s\n--- stderr ---\n%s", err, so, se)
		}
		return nil, runOutput{}, err
	}
	if resp.ExitCode == nil {
		return nil, runOutput{}, errors.New("grantpin: daemon returned no exit code")
	}
	return nil, runOutput{
		ExitCode: *resp.ExitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		GrantID:  resp.GrantID,
	}, nil
}

// ---- daemon access ----

// do sends pr (setting Caller from the MCP handshake) and returns the OK
// response. Not-OK responses and transport failures become Go errors, which
// the SDK turns into IsError tool results.
func (s *Server) do(ctx context.Context, req *sdk.CallToolRequest, pr *proto.Request, onStream func(proto.StreamFrame)) (*proto.Response, error) {
	pr.Caller = callerFor(req)
	s.log.Info("tool call", "op", pr.Op)

	resp, err := client.Call(ctx, s.cfg.SocketPath, pr, onStream)
	if errors.Is(err, client.ErrNotRunning) {
		if serr := s.ensureDaemon(ctx); serr != nil {
			s.log.Warn("daemon unavailable", "op", pr.Op, "err", serr)
			return nil, errors.New(NotRunningMessage)
		}
		resp, err = client.Call(ctx, s.cfg.SocketPath, pr, onStream)
		if errors.Is(err, client.ErrNotRunning) {
			return nil, errors.New(NotRunningMessage)
		}
	}
	if err != nil {
		s.log.Warn("daemon call failed", "op", pr.Op, "err", err)
		return nil, fmt.Errorf("grantpin: %w", err)
	}
	if rerr := client.ResponseError(resp); rerr != nil {
		s.log.Info("daemon refused", "op", pr.Op, "error", resp.Error, "reason", resp.Reason)
		return nil, rerr
	}
	return resp, nil
}

// ensureDaemon tries to start the daemon via cfg.Starter and waits for the
// socket. Concurrent callers share one attempt, and a failed attempt is not
// repeated for startCooldown. A Starter that fails synchronously starts no
// cooldown.
func (s *Server) ensureDaemon(ctx context.Context) error {
	if s.cfg.Starter == nil {
		return client.ErrNotRunning
	}
	s.startMu.Lock()
	defer s.startMu.Unlock()
	// Another call may have started it while we waited for the lock.
	if s.reachable(ctx) {
		return nil
	}
	if !s.lastStartAt.IsZero() && time.Since(s.lastStartAt) < startCooldown {
		return client.ErrNotRunning
	}
	s.log.Info("starting daemon")
	if err := s.cfg.Starter(ctx); err != nil {
		// Nothing was spawned, so the next call may try again at once.
		return fmt.Errorf("start daemon: %w", err)
	}
	// Only a spawned daemon starts the cooldown; it keeps us from spawning
	// another one while the first is still coming up or has failed to.
	s.lastStartAt = time.Now()
	deadline := time.Now().Add(s.cfg.StartWait)
	for {
		if s.reachable(ctx) {
			return nil
		}
		if time.Now().After(deadline) {
			return client.ErrNotRunning
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startPoll):
		}
	}
}

func (s *Server) reachable(ctx context.Context) bool {
	c, err := client.DialContext(ctx, s.cfg.SocketPath)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ---- caller derivation ----

func callerFor(req *sdk.CallToolRequest) string {
	var name string
	if req != nil && req.Session != nil {
		if ip := req.Session.InitializeParams(); ip != nil && ip.ClientInfo != nil {
			name = ip.ClientInfo.Name
		}
	}
	return SanitizeCaller(name)
}

// SanitizeCaller turns the MCP client's name into the canonical caller label
// (proto.CanonicalCaller: lowercased, separators folded to '-', at most 64
// bytes), or "mcp" when nothing is left. It is the same normal form
// `grants add --caller` stores, so a standing grant typed as "claude-code"
// matches the client "Claude Code".
func SanitizeCaller(name string) string {
	if c := proto.CanonicalCaller(name); c != "" {
		return c
	}
	return DefaultCaller
}

// ---- capped output ----

const truncMarker = "\n[grantpin mcp: output truncated at %d bytes]\n"

type capped struct {
	max       int
	b         strings.Builder
	truncated bool
}

func newCapped(max int) *capped { return &capped{max: max} }

func (c *capped) write(data string) {
	if c.truncated {
		return
	}
	room := c.max - c.b.Len()
	if len(data) <= room {
		c.b.WriteString(data)
		return
	}
	// Cut on a rune boundary.
	cut := room
	for cut > 0 && !utf8.RuneStart(data[cut]) {
		cut--
	}
	c.b.WriteString(data[:cut])
	c.truncated = true
}

func (c *capped) String() string {
	if c.truncated {
		return c.b.String() + fmt.Sprintf(truncMarker, c.max)
	}
	return c.b.String()
}
