package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/client"
	"github.com/jmeh-sindikata/grantpin/internal/daemon"
)

// Result is the outcome of one launchctl invocation.
type Result struct {
	Output   string // combined stdout and stderr
	ExitCode int
}

// Runner executes launchctl. It returns an error only when the command could
// not be run at all; a non-zero exit is reported through Result.ExitCode.
// Everything that talks to launchd goes through this seam so tests never touch
// the real service manager.
type Runner interface {
	Run(ctx context.Context, args ...string) (Result, error)
}

const launchctlPath = "/bin/launchctl"

// execRunner is the real Runner.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, args ...string) (Result, error) {
	out, err := execCommand(ctx, launchctlPath, args...)
	return out, err
}

// launchd manages the LaunchAgent. It is platform-neutral Go (so it is unit
// tested everywhere) but only constructed on darwin.
type launchd struct {
	run       Runner
	home      string
	uid       int
	tempRoots []string
	sleep     func(time.Duration)
	ready     ReadyFunc // nil means realReady
}

func newLaunchd(r Runner) (*launchd, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("service: locate home directory: %w", err)
	}
	return &launchd{run: r, home: home, uid: os.Getuid(), tempRoots: defaultTempRoots(), sleep: time.Sleep, ready: realReady}, nil
}

func (l *launchd) domain() string { return "gui/" + strconv.Itoa(l.uid) }
func (l *launchd) target() string { return l.domain() + "/" + Label }
func (l *launchd) plistPath() string {
	return filepath.Join(l.home, "Library", "LaunchAgents", Label+".plist")
}
func (l *launchd) defaultLogDir() string {
	return filepath.Join(l.home, "Library", "Logs", "grantpin")
}

// loaded reports whether launchd currently knows the job, returning the raw
// `launchctl print` output.
func (l *launchd) print(ctx context.Context) (Result, bool, error) {
	res, err := l.run.Run(ctx, "print", l.target())
	if err != nil {
		return res, false, fmt.Errorf("service: launchctl print: %w", err)
	}
	return res, res.ExitCode == 0, nil
}

func (l *launchd) bootout(ctx context.Context) error {
	res, err := l.run.Run(ctx, "bootout", l.target())
	if err != nil {
		return fmt.Errorf("service: launchctl bootout: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("service: launchctl bootout failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Output))
	}
	return nil
}

// pathFor is the PATH to record: the override, else the installing process's.
func pathFor(opts Options) string {
	if opts.Path != "" {
		return sanitizePath(opts.Path)
	}
	return sanitizePath(os.Getenv("PATH"))
}

func (l *launchd) Install(ctx context.Context, opts Options) error {
	exe, err := resolveExe(opts.Exe)
	if err != nil {
		return err
	}
	if err := checkExe(exe, l.tempRoots); err != nil {
		return err
	}
	if opts.Socket != "" && !filepath.IsAbs(opts.Socket) {
		return fmt.Errorf("service: socket path %q must be absolute", opts.Socket)
	}
	logDir := opts.LogDir
	if logDir == "" {
		logDir = l.defaultLogDir()
	}
	if !filepath.IsAbs(logDir) {
		return fmt.Errorf("service: log directory %q must be absolute", logDir)
	}
	outLog, errLog := logPaths(logDir)
	data, err := renderPlist(plistSpec{Label: Label, Exe: exe, Socket: opts.Socket, Path: pathFor(opts), OutLog: outLog, ErrLog: errLog})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fmt.Errorf("service: create log directory: %w", err)
	}
	if err := writePlist(l.plistPath(), data); err != nil {
		return err
	}

	_, loaded, err := l.print(ctx)
	if err != nil {
		return err
	}
	if loaded {
		if err := l.bootout(ctx); err != nil {
			return err
		}
	}
	// bootout is asynchronous enough that an immediate bootstrap can fail
	// with EIO; retry a few times, but only after we booted something out.
	attempts := 1
	if loaded {
		attempts = 5
	}
	var last Result
	for i := 0; i < attempts; i++ {
		if i > 0 {
			l.sleep(300 * time.Millisecond)
		}
		last, err = l.run.Run(ctx, "bootstrap", l.domain(), l.plistPath())
		if err != nil {
			return fmt.Errorf("service: launchctl bootstrap: %w", err)
		}
		if last.ExitCode == 0 {
			return l.waitReady(ctx, opts, errLog)
		}
	}
	return fmt.Errorf("service: launchctl bootstrap failed (exit %d): %s", last.ExitCode, strings.TrimSpace(last.Output))
}

// realReady connects to the daemon socket and asks for its status.
func realReady(ctx context.Context, socket string) error {
	_, err := client.Status(ctx, socket)
	return err
}

// waitReady polls until the daemon socket is connectable. A timeout is
// reported as ErrNotReady (launchd itself succeeded); a cancelled ctx is
// returned as is.
func (l *launchd) waitReady(ctx context.Context, opts Options, errLog string) error {
	socket := opts.Socket
	if socket == "" {
		p, err := daemon.DefaultSocketPath()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotReady, err)
		}
		socket = p
	}
	timeout := opts.ReadyTimeout
	if timeout <= 0 {
		timeout = DefaultReadyTimeout
	}
	ready := l.ready
	if ready == nil {
		ready = realReady
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		last = ready(wctx, socket)
		if last == nil {
			return nil
		}
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w within %s (socket %s, last error: %v); check %s", ErrNotReady, timeout, socket, last, errLog)
		case <-time.After(readyPollInterval):
		}
	}
}

// writePlist writes atomically with mode 0644 (launchd rejects plists that
// are group- or world-writable).
func writePlist(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("service: create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".grantpin-plist-*")
	if err != nil {
		return fmt.Errorf("service: write plist: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("service: write plist: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return fmt.Errorf("service: chmod plist: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("service: write plist: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("service: install plist: %w", err)
	}
	return nil
}

func (l *launchd) Uninstall(ctx context.Context) error {
	_, loaded, err := l.print(ctx)
	if err != nil {
		return err
	}
	if loaded {
		if err := l.bootout(ctx); err != nil {
			return err
		}
	}
	if err := os.Remove(l.plistPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("service: remove plist: %w", err)
	}
	return nil
}

func (l *launchd) Status(ctx context.Context) (Status, error) {
	st := Status{Label: Label, PlistPath: l.plistPath()}
	data, err := os.ReadFile(st.PlistPath)
	switch {
	case err == nil:
		st.Installed = true
		if exe, perr := plistExe(data); perr == nil {
			st.ExePath = exe
			if _, serr := os.Stat(exe); serr != nil {
				st.ExeMissing = true
			}
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return st, fmt.Errorf("service: read plist: %w", err)
	}

	res, loaded, err := l.print(ctx)
	if err != nil {
		return st, err
	}
	if loaded {
		st.Loaded = true
		state, pid := parsePrint(res.Output)
		st.State = state
		if pid > 0 {
			st.Running, st.PID = true, pid
		}
	}
	return st, nil
}

// parsePrint extracts the top-level "state" and "pid" fields from `launchctl
// print` output. Only lines indented by exactly one tab belong to the service
// itself; deeper lines are nested blocks (endpoints, event triggers, ...).
func parsePrint(out string) (state string, pid int) {
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			state = strings.TrimSpace(v)
		case "pid":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				pid = n
			}
		}
	}
	return state, pid
}
