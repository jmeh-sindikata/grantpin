package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// Defaults for Config zero values.
const (
	DefaultMaxTimeout       = time.Hour
	DefaultFirstLineTimeout = 5 * time.Second
	DefaultShutdownGrace    = 10 * time.Second
	DefaultHandlerGrace     = 5 * time.Second
	// DefaultMaxConns is the number of connections served at once. A request
	// that is waiting for a human or running a command holds its connection,
	// so this also bounds the daemon's file descriptors.
	DefaultMaxConns      = 64
	DefaultApprovalGrace = 10 * time.Minute

	// writeTimeout bounds a single write to a client that stopped reading.
	writeTimeout = 30 * time.Second
)

// StatusFunc lets the integration layer add vault/backends/grants information
// to the built-in status reply. It receives the basics already filled in
// (Version, ProtoV, PID, StartedAt) and may set any field.
type StatusFunc func(ctx context.Context, st *proto.StatusResult)

// Config configures a Server. Only SocketPath is required.
type Config struct {
	SocketPath string
	// Router holds the op handlers. nil means an empty router (only the
	// built-in status op answers).
	Router *Router
	// Logger receives operational logs. nil discards. The daemon logs op,
	// caller, cwd, argv element count and outcome only, never request bodies,
	// argv or values.
	Logger *slog.Logger
	// StatusFunc, if set, augments the built-in status reply.
	StatusFunc StatusFunc
	// Version is the build version reported by status (default "dev").
	Version string

	// MaxTimeout caps a request's timeout_s, and is also used when a request
	// sets none (default 1h). It bounds the command, not the wait for human
	// approval (see ApprovalGrace).
	MaxTimeout time.Duration
	// ApprovalGrace is added to the command budget to form the per-connection
	// deadline, so the time a human takes to answer a prompt does not eat the
	// command's timeout_s:
	//
	//	deadline = min(timeout_s, MaxTimeout) + ApprovalGrace
	//
	// (timeout_s of 0 means MaxTimeout). Handlers read the command budget with
	// CommandTimeout. Default 10m.
	ApprovalGrace time.Duration
	// FirstLineTimeout is how long a new connection may take to deliver its
	// request line (default 5s).
	FirstLineTimeout time.Duration
	// ShutdownGrace is how long Serve waits for in-flight connections after
	// its context is cancelled before cancelling their handlers (default 10s).
	ShutdownGrace time.Duration
	// MaxConns is the most connections served concurrently (default
	// DefaultMaxConns). A connection over the limit is answered `failed` /
	// `busy` when that line can be written at once, and closed otherwise;
	// the accept loop never waits for a slot.
	MaxConns int
	// HandlerGrace is how long after a connection's context ends (timeout,
	// client gone, forced shutdown) the server waits for the handler to return
	// before replying itself and abandoning it (default 5s).
	HandlerGrace time.Duration
}

// Server is the daemon's socket server.
type Server struct {
	cfg    Config
	log    *slog.Logger
	router *Router

	// peerCheck verifies a connection's peer; replaced in tests.
	peerCheck func(*net.UnixConn) error

	startedAt time.Time

	mu       sync.Mutex
	ln       net.Listener
	listened bool

	baseCtx    context.Context
	baseCancel context.CancelFunc
	conns      sync.WaitGroup
	slots      chan struct{} // one token per connection being served

	rejectLogged atomic.Int64 // UnixNano of the last "rejected" log line
}

// New validates cfg and builds a Server. It does not touch the filesystem.
func New(cfg Config) (*Server, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("daemon: Config.SocketPath is required")
	}
	if cfg.Router == nil {
		cfg.Router = NewRouter()
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.MaxTimeout <= 0 {
		cfg.MaxTimeout = DefaultMaxTimeout
	}
	if cfg.ApprovalGrace <= 0 {
		cfg.ApprovalGrace = DefaultApprovalGrace
	}
	if cfg.FirstLineTimeout <= 0 {
		cfg.FirstLineTimeout = DefaultFirstLineTimeout
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = DefaultShutdownGrace
	}
	if cfg.HandlerGrace <= 0 {
		cfg.HandlerGrace = DefaultHandlerGrace
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, log: log, router: cfg.Router, peerCheck: checkPeer, slots: make(chan struct{}, cfg.MaxConns)}
	s.baseCtx, s.baseCancel = context.WithCancel(context.Background())
	return s, nil
}

// SocketPath returns the configured socket path.
func (s *Server) SocketPath() string { return s.cfg.SocketPath }

// Listen binds the socket (parent dir 0700, socket 0600, stale socket
// removed). It is idempotent; Serve calls it if needed. Calling it separately
// lets a caller report bind errors before serving.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listened {
		return nil
	}
	ln, err := listenUnix(s.cfg.SocketPath, func(msg string, args ...any) { s.log.Warn(msg, args...) })
	if err != nil {
		return err
	}
	s.ln = ln
	s.listened = true
	s.startedAt = time.Now()
	return nil
}

// Serve accepts connections until ctx is cancelled, then stops accepting,
// waits up to ShutdownGrace for in-flight connections, cancels any that remain,
// and removes the socket file. A Server serves once.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	s.log.Info("listening", "socket", s.cfg.SocketPath, "pid", os.Getpid(), "version", s.cfg.Version)

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		_ = s.ln.Close()
	}()

	var acceptErr error
	for delay := time.Duration(0); ; {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if !retryableAccept(err) {
				acceptErr = fmt.Errorf("daemon: accept: %w", err)
				break
			}
			// Out of descriptors (EMFILE/ENFILE) or another transient
			// condition: this must not take the daemon down and with it every
			// command it is running. Back off and try again; the pending
			// connection stays queued in the kernel meanwhile.
			delay = backoff(delay)
			s.log.Warn("accept failed; retrying", "err", err.Error(), "delay", delay.String())
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
			}
			continue
		}
		delay = 0
		select {
		case s.slots <- struct{}{}:
		default:
			s.reject(conn)
			continue
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			defer func() { <-s.slots }()
			s.serveConn(conn)
		}()
	}
	close(stopped)
	// Closing the listener also unlinks the socket path (net.UnixListener does
	// that for a socket it created), so new clients see "not running" and a
	// new daemon can bind while we drain. Do not Remove the path again here: by
	// now a successor daemon may already have bound a fresh socket at it.
	_ = s.ln.Close()

	s.log.Info("shutting down", "grace", s.cfg.ShutdownGrace.String())
	if !waitTimeout(&s.conns, s.cfg.ShutdownGrace) {
		s.log.Warn("grace period expired; cancelling in-flight requests")
		s.baseCancel()
		waitTimeout(&s.conns, s.cfg.HandlerGrace+time.Second)
	}
	s.baseCancel()
	return acceptErr
}

// retryableAccept reports whether an Accept error is transient: running out of
// file descriptors (per process or system-wide), a connection that died before
// it was accepted, a timeout, or anything that calls itself temporary.
func retryableAccept(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var tmp interface{ Temporary() bool }
	return errors.As(err, &tmp) && tmp.Temporary()
}

// rejectWriteTimeout bounds the attempt to tell an over-limit client that the
// daemon is busy. The line is a few dozen bytes into a fresh socket buffer, so
// it normally goes at once; if it does not, the connection is just closed.
const rejectWriteTimeout = 20 * time.Millisecond

// reject answers a connection over the MaxConns limit with failed / busy if
// that can be written cheaply, and closes it. It reads nothing.
func (s *Server) reject(conn net.Conn) {
	defer conn.Close()
	resp := Failure(proto.ErrFailed, proto.ReasonBusy)
	resp.Message = "too many concurrent connections; retry shortly"
	line, err := proto.Encode(resp)
	if err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(rejectWriteTimeout))
		_, _ = conn.Write(line)
	}
	// A flood of clients must not also flood the log: one line per second.
	if now := time.Now().UnixNano(); now-s.rejectLogged.Load() > int64(time.Second) {
		s.rejectLogged.Store(now)
		s.log.Warn("connection rejected: too many concurrent connections", "max", s.cfg.MaxConns)
	}
}

func backoff(d time.Duration) time.Duration {
	if d == 0 {
		return 10 * time.Millisecond
	}
	return min(d*2, time.Second)
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// connWriter implements ResponseWriter for one connection.
type connWriter struct {
	conn net.Conn

	mu       sync.Mutex
	finished bool
	final    *proto.Response
	frames   int
	err      error // sticky write error
}

// write encodes v and sends it. An encode or size error (the message is bad,
// the connection is fine) is returned without poisoning the writer; only a
// failed network write is sticky.
func (w *connWriter) write(v any) error {
	b, err := proto.Encode(v)
	if err != nil {
		return err
	}
	return w.writeLine(b)
}

func (w *connWriter) writeLine(b []byte) error {
	_ = w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := w.conn.Write(b); err != nil {
		w.err = err
		return err
	}
	return nil
}

func (w *connWriter) Stream(stream string, data []byte) error {
	if stream != proto.StreamStdout && stream != proto.StreamStderr {
		return fmt.Errorf("daemon: invalid stream %q", stream)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return ErrFinished
	}
	if w.err != nil {
		return w.err
	}
	if err := w.write(&proto.StreamFrame{Stream: stream, Data: string(data)}); err != nil {
		return err
	}
	w.frames++
	return nil
}

func (w *connWriter) Finish(resp *proto.Response) error {
	if resp == nil {
		return errors.New("daemon: nil response")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return ErrFinished
	}
	w.finished = true
	line, encErr := proto.Encode(resp)
	if encErr != nil {
		// The response cannot be sent (typically a result larger than
		// MaxLineBytes). Do not leave the client with a bare EOF that looks
		// like success: send a small failure that always fits, and record
		// that as the outcome.
		msg := "response could not be encoded"
		if errors.Is(encErr, proto.ErrLineTooLong) {
			msg = "response too large"
		}
		resp = Failure(proto.ErrFailed, proto.ReasonInternal)
		resp.Message = msg
		line, _ = proto.Encode(resp)
	}
	w.final = resp
	if w.err != nil {
		return w.err
	}
	if err := w.writeLine(line); err != nil {
		return err
	}
	return encErr
}

// finishIfOpen sends resp unless the handler already finished.
func (w *connWriter) finishIfOpen(resp *proto.Response) {
	_ = w.Finish(resp) // ErrFinished is fine
}

// outcome returns the final response (nil if none was sent).
func (w *connWriter) outcome() (*proto.Response, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.final, w.frames
}

func (s *Server) serveConn(conn net.Conn) {
	start := time.Now()
	defer conn.Close()

	w := &connWriter{conn: conn}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		s.log.Error("non-unix connection refused")
		return
	}

	if err := s.peerCheck(uc); err != nil {
		// Log the reason (UIDs), not request content: nothing was read.
		s.log.Warn("peer rejected", "err", err)
		w.finishIfOpen(Failure(proto.ErrRefused, proto.ReasonPeerRejected))
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.FirstLineTimeout))
	req, err := proto.NewReader(conn).ReadRequest()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		switch {
		case errors.Is(err, io.EOF):
			s.log.Debug("connection closed without a request")
		case errors.Is(err, os.ErrDeadlineExceeded):
			s.log.Warn("no request within deadline", "after", s.cfg.FirstLineTimeout.String())
			w.finishIfOpen(Failure(proto.ErrBadRequest, proto.ReasonBadRequest))
		default:
			// Decode errors can quote bytes of the body, so do not log err.
			s.log.Warn("malformed request")
			w.finishIfOpen(Failure(proto.ErrBadRequest, proto.ReasonBadRequest))
		}
		return
	}

	// Validate. Order matters: version first, then op, then op-specific.
	var (
		h      Handler
		reject *proto.Response
	)
	switch {
	case req.V != proto.Version:
		reject = Failure(proto.ErrBadRequest, proto.ReasonUnsupportedVersion)
	case req.TimeoutS < 0:
		reject = Failure(proto.ErrBadRequest, proto.ReasonBadRequest)
	default:
		h = s.lookup(req.Op)
		if h == nil {
			reject = Failure(proto.ErrBadRequest, proto.ReasonUnknownOp)
		}
	}
	if reject != nil {
		w.finishIfOpen(reject)
		s.logRequest(req, w, start)
		return
	}

	budget := s.requestTimeout(req)
	ctx, cancel := context.WithTimeout(context.WithValue(s.baseCtx, budgetKey{}, budget), budget+s.cfg.ApprovalGrace)
	defer cancel()

	// Cancel the handler if the client goes away. The protocol is strictly
	// request-then-response, so any read result (EOF/error) means the peer is
	// gone or half-closed; clients must keep their write side open.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()

	s.runHandler(ctx, h, req, w)

	_ = conn.Close()
	<-watchDone
	s.logRequest(req, w, start)
}

func (s *Server) lookup(op string) Handler {
	if h, ok := s.router.Lookup(op); ok {
		return h
	}
	if op == proto.OpStatus {
		return HandlerFunc(s.handleStatus)
	}
	return nil
}

type budgetKey struct{}

// CommandTimeout returns the command time budget the daemon granted this
// request: timeout_s capped by Config.MaxTimeout (MaxTimeout when the request
// set none). It excludes the approval grace added to the connection deadline,
// so a handler should apply it to the command itself. ok is false for a
// context that did not come from the daemon.
func CommandTimeout(ctx context.Context) (d time.Duration, ok bool) {
	d, ok = ctx.Value(budgetKey{}).(time.Duration)
	return d, ok
}

// requestTimeout is the command budget for req (see CommandTimeout).
func (s *Server) requestTimeout(req *proto.Request) time.Duration {
	max := s.cfg.MaxTimeout
	if req.TimeoutS <= 0 {
		return max
	}
	if int64(req.TimeoutS) > int64(max/time.Second) {
		return max
	}
	return time.Duration(req.TimeoutS) * time.Second
}

// runHandler runs h and guarantees a final response is written.
func (s *Server) runHandler(ctx context.Context, h Handler, req *proto.Request, w *connWriter) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				// The panic value may embed request data; log its type only.
				s.log.Error("handler panic", "op", req.Op, "panic_type", fmt.Sprintf("%T", r))
			}
		}()
		h.Handle(ctx, req, w)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t := time.NewTimer(s.cfg.HandlerGrace)
		select {
		case <-done:
		case <-t.C:
			s.log.Warn("handler ignored cancellation; abandoning", "op", req.Op)
		}
		t.Stop()
	}

	reason := proto.ReasonInternal
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		reason = proto.ReasonTimeout
	case ctx.Err() != nil:
		reason = proto.ReasonCanceled
	}
	w.finishIfOpen(Failure(proto.ErrFailed, reason))
}

// maxLogField bounds the untrusted caller and cwd strings in a log line; a
// request can carry megabytes in either, and refused requests are logged too.
const maxLogField = 200

// clipLog cuts s to at most maxLogField bytes at a character boundary and marks
// the cut with "...".
func clipLog(s string) string {
	if len(s) <= maxLogField {
		return s
	}
	n := maxLogField - 3
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// logRequest logs the allowed fields only: op, caller, cwd, the number of argv
// elements, outcome and duration. Never the request body, never Request.Value
// and never argv itself: the daemon has no redactor, and a caller can put a
// secret value into argv. The broker audits argv, scrubbed of injected values.
func (s *Server) logRequest(req *proto.Request, w *connWriter, start time.Time) {
	resp, frames := w.outcome()
	attrs := []any{
		"op", req.Op,
		"caller", clipLog(req.Caller),
		"cwd", clipLog(req.Cwd),
		"argc", len(req.Argv),
		"frames", frames,
		"duration_ms", time.Since(start).Milliseconds(),
	}
	switch {
	case resp == nil:
		attrs = append(attrs, "outcome", "no_response")
	case resp.OK:
		attrs = append(attrs, "outcome", "ok")
		if resp.ExitCode != nil {
			attrs = append(attrs, "exit_code", *resp.ExitCode)
		}
	case resp.Error == proto.ErrFailed:
		attrs = append(attrs, "outcome", "failed", "error", resp.Error, "reason", resp.Reason)
	default:
		attrs = append(attrs, "outcome", "error", "error", resp.Error, "reason", resp.Reason)
	}
	s.log.Info("request", attrs...)
}

// handleStatus is the built-in status op.
func (s *Server) handleStatus(ctx context.Context, _ *proto.Request, w ResponseWriter) {
	st := proto.StatusResult{
		Version:   s.cfg.Version,
		ProtoV:    proto.Version,
		PID:       os.Getpid(),
		StartedAt: s.startedAt,
	}
	if s.cfg.StatusFunc != nil {
		s.cfg.StatusFunc(ctx, &st)
	}
	res, err := proto.NewResult(st)
	if err != nil {
		_ = w.Finish(Failure(proto.ErrFailed, proto.ReasonInternal))
		return
	}
	_ = w.Finish(&proto.Response{OK: true, Result: res})
}
