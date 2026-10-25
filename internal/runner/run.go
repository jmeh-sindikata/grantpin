package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Exit codes reported in Result.ExitCode. They follow shell conventions.
const (
	ExitTimeout       = 124 // Spec.Timeout elapsed and the process group was killed
	ExitCannotExecute = 126 // command found but could not be executed (or bad Cwd)
	ExitNotFound      = 127 // command not found
	// ExitNotStarted is reported when Run failed before any process existed
	// (invalid Spec, context already cancelled, unsupported platform).
	ExitNotStarted = -1
)

// DefaultKillGrace is the SIGTERM -> SIGKILL delay when Spec.KillGrace is 0.
const DefaultKillGrace = 5 * time.Second

const defaultPath = "/usr/bin:/bin" // what execvp falls back to without PATH

var (
	// ErrInvalidSpec: the Spec was rejected before anything was started.
	ErrInvalidSpec = errors.New("runner: invalid spec")
	// ErrCommandNotFound: Argv[0] does not resolve to a file (exit code 127).
	ErrCommandNotFound = errors.New("runner: command not found")
	// ErrCannotExecute: Argv[0] exists but cannot be run, or Cwd is unusable
	// (exit code 126).
	ErrCannotExecute = errors.New("runner: cannot execute command")
	// ErrUnsupported: Run is not implemented on this platform.
	ErrUnsupported = errors.New("runner: unsupported platform")
)

// Spec describes one command execution.
type Spec struct {
	// Argv is the command and its arguments. Argv[0] is resolved against the
	// PATH of the CHILD's environment (ParentEnv plus injections), not the
	// daemon's own PATH. Entries of PATH that are empty or relative are
	// ignored. A name containing '/' is taken relative to Cwd.
	Argv []string
	// Cwd is the working directory; it must be absolute if set. Empty means
	// the current directory of the calling process.
	Cwd string
	// Env is the secrets to inject: env var name -> plaintext value. Names must
	// match [A-Za-z_][A-Za-z0-9_]* and values must not contain NUL. Injected
	// variables replace same-named ones from ParentEnv.
	Env map[string]string
	// Labels optionally maps an Env name to the label used in the
	// [REDACTED:label] placeholder (typically the vault secret name, e.g.
	// "aws/access_key"). Missing entries default to the env var name.
	Labels map[string]string
	// ParentEnv is the base environment in "K=V" form. nil means os.Environ();
	// a non-nil empty slice means an empty environment.
	ParentEnv []string
	// Timeout bounds the run; 0 means none. On expiry the process group gets
	// SIGTERM, then SIGKILL after KillGrace.
	Timeout time.Duration
	// KillGrace is the delay between SIGTERM and SIGKILL, and also how long Run
	// waits for output to drain after the process exits. 0 means
	// DefaultKillGrace.
	KillGrace time.Duration
	// Signals, if non-nil, delivers signals to forward to the child's process
	// group (e.g. from signal.Notify). The caller owns the channel and its
	// Notify registration; Run stops reading it when the child is done.
	Signals <-chan os.Signal

	// loopHook, if set, is called on every turn of Run's wait loop (tests).
	loopHook func()
}

// Result is the outcome of a finished command.
//
// ExitCode:
//
//	normal exit              the command's own status (0-255)
//	killed by signal N       128+N (Signaled is true), e.g. 137 for SIGKILL
//	Spec.Timeout elapsed     124 (TimedOut is true), whatever the child did
//	command not found        127, with an error wrapping ErrCommandNotFound
//	not executable / bad cwd 126, with an error wrapping ErrCannotExecute
//	never started            -1, with an error (ErrInvalidSpec, ctx error, ...)
//
// When the context is cancelled, ExitCode is the child's real status (usually
// 143 after SIGTERM) and Run additionally returns the context's error.
type Result struct {
	ExitCode int
	Duration time.Duration
	// Signaled reports that the process was terminated by a signal.
	Signaled bool
	// TimedOut reports that Spec.Timeout expired.
	TimedOut bool
	// Overrode lists, sorted, the names of injected variables that replaced a
	// variable already present in ParentEnv. Names only, never values.
	Overrode []string
}

// Run executes spec and streams its output to stdout/stderr as it is produced,
// with every injected value replaced by [REDACTED:NAME] (see the package
// comment for the limits of that). The child gets a copy of ParentEnv with the
// injected variables replacing same-named entries, runs in its own process
// group, and has stdin connected to /dev/null: v0.1 deliberately offers no way
// to feed a child interactively.
//
// stdout and stderr may be the same writer; Run serialises writes to them. A
// nil writer discards that stream. If a writer fails, Run keeps draining the
// child (so it is not blocked), discards the rest and returns the write error
// alongside the Result; callers should cancel ctx when their consumer goes
// away.
//
// Context cancellation behaves like a timeout (SIGTERM, then SIGKILL after
// KillGrace) but TimedOut stays false and ctx's error is returned. Signals on
// spec.Signals are forwarded to the process group (closing the channel just
// stops forwarding). On normal exit, any
// processes the command left behind in its process group are killed.
//
// Run never logs. Error text never contains injected values: anything derived
// from lower layers is passed through a Redactor first.
func Run(ctx context.Context, spec Spec, stdout, stderr io.Writer) (Result, error) {
	res := Result{ExitCode: ExitNotStarted}
	if !supported {
		return res, ErrUnsupported
	}

	labelled := make(map[string]string, len(spec.Env))
	for name, v := range spec.Env {
		label := name
		if l, ok := spec.Labels[name]; ok && l != "" {
			label = l
		}
		labelled[label] = v
	}
	red := NewRedactor(labelled)
	fail := func(code int, sentinel error, detail string) (Result, error) {
		res.ExitCode = code
		return res, fmt.Errorf("%w: %s", sentinel, red.RedactString(detail))
	}

	if err := validateSpec(spec); err != nil {
		return fail(ExitNotStarted, ErrInvalidSpec, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("runner: %w", err)
	}

	env, overrode := buildEnv(spec)
	res.Overrode = overrode

	if spec.Cwd != "" {
		if st, err := os.Stat(spec.Cwd); err != nil || !st.IsDir() {
			return fail(ExitCannotExecute, ErrCannotExecute, fmt.Sprintf("bad working directory %q", spec.Cwd))
		}
	}
	path, code, lerr := lookPath(spec.Argv[0], env, spec.Cwd)
	if lerr != nil {
		return fail(code, lerr, spec.Argv[0])
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		return fail(ExitNotStarted, ErrCannotExecute, "pipe: "+err.Error())
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return fail(ExitNotStarted, ErrCannotExecute, "pipe: "+err.Error())
	}

	cmd := &exec.Cmd{
		Path:        path,
		Args:        spec.Argv,
		Dir:         spec.Cwd,
		Env:         env,
		Stdin:       nil, // os.DevNull
		Stdout:      outW,
		Stderr:      errW,
		SysProcAttr: sysProcAttr(),
	}
	start := time.Now()
	startErr := cmd.Start()
	_ = outW.Close() // child holds its own copies now
	_ = errW.Close()
	if startErr != nil {
		_ = outR.Close()
		_ = errR.Close()
		code := ExitCannotExecute
		sentinel := ErrCannotExecute
		if errors.Is(startErr, fs.ErrNotExist) {
			code, sentinel = ExitNotFound, ErrCommandNotFound
		}
		return fail(code, sentinel, startErr.Error())
	}
	pid := cmd.Process.Pid

	var mu sync.Mutex
	outW2 := red.Writer(&lockedWriter{mu: &mu, w: stdout})
	errW2 := red.Writer(&lockedWriter{mu: &mu, w: stderr})
	var outErr, errErr error
	outDone, errDone := make(chan struct{}), make(chan struct{})
	go pump(outR, outW2, &outErr, outDone)
	go pump(errR, errW2, &errErr, errDone)

	waitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait() // no copier goroutines (files passed directly): returns at exit
		close(waitCh)
	}()

	grace := spec.KillGrace
	if grace == 0 {
		grace = DefaultKillGrace
	}
	var timeoutC <-chan time.Time
	if spec.Timeout > 0 {
		t := time.NewTimer(spec.Timeout)
		defer t.Stop()
		timeoutC = t.C
	}
	var killC <-chan time.Time
	var killTimer *time.Timer
	defer func() {
		if killTimer != nil {
			killTimer.Stop()
		}
	}()
	ctxDone := ctx.Done()
	sigC := spec.Signals
	terminating := false
	terminate := func() {
		if terminating {
			return
		}
		terminating = true
		_ = signalGroup(pid, sigTerm())
		killTimer = time.NewTimer(grace)
		killC = killTimer.C
	}
	var ctxErr error

loop:
	for {
		if spec.loopHook != nil {
			spec.loopHook()
		}
		select {
		case <-waitCh:
			break loop
		case <-ctxDone:
			ctxErr = ctx.Err()
			ctxDone = nil
			terminate()
		case <-timeoutC:
			res.TimedOut = true
			timeoutC = nil
			terminate()
		case <-killC:
			killC = nil
			_ = signalGroup(pid, sigKill())
		case sig, ok := <-sigC:
			if !ok {
				// The caller closed the channel: stop selecting on it (a closed
				// channel is always ready and would spin this loop).
				sigC = nil
				continue
			}
			if sig != nil {
				_ = signalGroup(pid, sig)
			}
		}
	}

	// The leader is gone. Kill whatever it left in the group so no process
	// keeps running with the injected environment after the run has ended.
	_ = signalGroup(pid, sigKill())

	// Let the pumps hit EOF; force them if something escaped the group
	// (setsid, daemonising) and still holds the pipes open.
	drained := make(chan struct{})
	go func() { <-outDone; <-errDone; close(drained) }()
	dt := time.NewTimer(grace)
	select {
	case <-drained:
	case <-dt.C:
		_ = outR.Close()
		_ = errR.Close()
		<-drained
	}
	dt.Stop()
	_ = outR.Close()
	_ = errR.Close()

	res.Duration = time.Since(start)
	res.ExitCode, res.Signaled = exitStatus(cmd.ProcessState)
	if res.TimedOut {
		res.ExitCode = ExitTimeout
	}

	switch {
	case ctxErr != nil:
		return res, fmt.Errorf("runner: %w", ctxErr)
	case outErr != nil:
		return res, fmt.Errorf("runner: writing stdout: %s", red.RedactString(outErr.Error()))
	case errErr != nil:
		return res, fmt.Errorf("runner: writing stderr: %s", red.RedactString(errErr.Error()))
	}
	return res, nil
}

// pump copies src to dst as data arrives, then flushes dst. After a write error
// it keeps reading (and discarding) so the child never blocks on a full pipe.
func pump(src *os.File, dst io.WriteCloser, errp *error, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 32*1024)
	var werr error
	for {
		n, rerr := src.Read(buf)
		if n > 0 && werr == nil {
			_, werr = dst.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	if cerr := dst.Close(); werr == nil {
		werr = cerr
	}
	*errp = werr
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	if l.w == nil {
		return len(p), nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func validateSpec(spec Spec) error {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return errors.New("empty argv")
	}
	for _, a := range spec.Argv {
		if strings.IndexByte(a, 0) >= 0 {
			return errors.New("argv contains NUL")
		}
	}
	if spec.Cwd != "" && !filepath.IsAbs(spec.Cwd) {
		return errors.New("cwd must be absolute")
	}
	if strings.IndexByte(spec.Cwd, 0) >= 0 {
		return errors.New("cwd contains NUL")
	}
	if spec.Timeout < 0 || spec.KillGrace < 0 {
		return errors.New("negative duration")
	}
	for name, v := range spec.Env {
		if !anyEnvRE.MatchString(name) {
			return fmt.Errorf("invalid env name %q", name)
		}
		if strings.IndexByte(v, 0) >= 0 {
			return fmt.Errorf("value of %s contains NUL", name)
		}
	}
	for _, e := range spec.ParentEnv {
		if strings.IndexByte(e, 0) >= 0 {
			return errors.New("parent env contains NUL")
		}
	}
	return nil
}

// buildEnv returns the child environment and the sorted names of injected
// variables that displaced a parent variable.
func buildEnv(spec Spec) (env, overrode []string) {
	parent := spec.ParentEnv
	if parent == nil {
		parent = os.Environ()
	}
	hit := map[string]bool{}
	env = make([]string, 0, len(parent)+len(spec.Env))
	for _, e := range parent {
		name, _, _ := strings.Cut(e, "=")
		if _, inj := spec.Env[name]; inj {
			hit[name] = true
			continue
		}
		env = append(env, e)
	}
	for _, k := range sortedKeys(spec.Env) {
		env = append(env, k+"="+spec.Env[k])
	}
	return env, sortedKeys(hit)
}

func envGet(env []string, key string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			val, found = v, true // last one wins, like exec
		}
	}
	return val, found
}

// lookPath resolves argv0 using the child's PATH. It returns the exit code and
// sentinel error to report when resolution fails.
func lookPath(argv0 string, env []string, cwd string) (string, int, error) {
	if strings.Contains(argv0, "/") {
		p := argv0
		if !filepath.IsAbs(p) {
			base := cwd
			if base == "" {
				base, _ = os.Getwd()
			}
			p = filepath.Join(base, p)
		}
		switch execCheck(p) {
		case nil:
			return p, 0, nil
		case fs.ErrPermission:
			return "", ExitCannotExecute, ErrCannotExecute
		default:
			return "", ExitNotFound, ErrCommandNotFound
		}
	}
	pathVar, ok := envGet(env, "PATH")
	if !ok {
		pathVar = defaultPath
	}
	denied := false
	for _, dir := range filepath.SplitList(pathVar) {
		if !filepath.IsAbs(dir) {
			continue // empty or relative entries are never searched
		}
		p := filepath.Join(dir, argv0)
		switch execCheck(p) {
		case nil:
			return p, 0, nil
		case fs.ErrPermission:
			denied = true
		}
	}
	if denied {
		return "", ExitCannotExecute, ErrCannotExecute
	}
	return "", ExitNotFound, ErrCommandNotFound
}

// execCheck returns nil for an executable regular file, fs.ErrPermission for
// something that exists but is not runnable, and fs.ErrNotExist otherwise.
func execCheck(p string) error {
	st, err := os.Stat(p)
	if err != nil {
		return fs.ErrNotExist
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fs.ErrPermission
	}
	return nil
}
