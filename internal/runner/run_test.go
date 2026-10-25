//go:build unix

package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// safeBuf is a concurrency-safe buffer with arrival timestamps.
type safeBuf struct {
	mu     sync.Mutex
	b      bytes.Buffer
	events []event
}

type event struct {
	at   time.Time
	data string
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event{time.Now(), string(p)})
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var baseEnv = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}

func sh(script string) Spec {
	return Spec{Argv: []string{"/bin/sh", "-c", script}, ParentEnv: baseEnv, KillGrace: 500 * time.Millisecond}
}

func run(t *testing.T, spec Spec) (Result, string, string, error) {
	t.Helper()
	var so, se safeBuf
	res, err := Run(context.Background(), spec, &so, &se)
	return res, so.String(), se.String(), err
}

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		code     int
		signaled bool
	}{
		{"zero", "exit 0", 0, false},
		{"one", "exit 1", 1, false},
		{"forty-two", "exit 42", 42, false},
		{"255", "exit 255", 255, false},
		{"self sigkill", "kill -9 $$", 137, true},
		{"self sigterm", "kill -TERM $$", 143, true},
		{"self sighup", "kill -HUP $$", 129, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, _, _, err := run(t, sh(tc.script))
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != tc.code || res.Signaled != tc.signaled || res.TimedOut {
				t.Fatalf("got %+v", res)
			}
			if res.Duration <= 0 {
				t.Fatalf("duration %v", res.Duration)
			}
		})
	}
}

func TestRunBasicOutputAndTrueFalse(t *testing.T) {
	res, out, errOut, err := run(t, Spec{Argv: []string{"true"}, ParentEnv: baseEnv})
	if err != nil || res.ExitCode != 0 || out != "" || errOut != "" {
		t.Fatalf("true: %+v %q %q %v", res, out, errOut, err)
	}
	res, _, _, err = run(t, Spec{Argv: []string{"false"}, ParentEnv: baseEnv})
	if err != nil || res.ExitCode != 1 {
		t.Fatalf("false: %+v %v", res, err)
	}
	_, out, errOut, _ = run(t, sh("echo to-out; echo to-err >&2"))
	if out != "to-out\n" || errOut != "to-err\n" {
		t.Fatalf("out=%q err=%q", out, errOut)
	}
}

func TestRunInjectsAndRedacts(t *testing.T) {
	spec := sh(`printenv ACCESS_KEY; echo "again: $ACCESS_KEY" >&2; echo "tok=$TOKEN"`)
	spec.Env = map[string]string{"ACCESS_KEY": "AKIAEXAMPLE1234", "TOKEN": "t0k3n-xyz"}
	spec.Labels = map[string]string{"ACCESS_KEY": "aws/access_key"}
	res, out, errOut, err := run(t, spec)
	if err != nil || res.ExitCode != 0 {
		t.Fatal(res, err)
	}
	if out != "[REDACTED:aws/access_key]\ntok=[REDACTED:TOKEN]\n" {
		t.Fatalf("stdout %q", out)
	}
	if errOut != "again: [REDACTED:aws/access_key]\n" {
		t.Fatalf("stderr %q", errOut)
	}
	if len(res.Overrode) != 0 {
		t.Fatalf("overrode %v", res.Overrode)
	}
}

func TestRunChildActuallyReceivesPlainValue(t *testing.T) {
	// guards against redacting on the way *in*: the child must see the real value.
	spec := sh(`[ "$K" = "real-value-123" ] && exit 7; exit 8`)
	spec.Env = map[string]string{"K": "real-value-123"}
	res, _, _, err := run(t, spec)
	if err != nil || res.ExitCode != 7 {
		t.Fatal(res, err)
	}
}

func TestRunRedactsAcrossWriteBoundaries(t *testing.T) {
	// printf emits the value in two separate writes with a pause between them.
	spec := sh(`printf 'before AKIA'; sleep 0.2; printf 'EXAMPLE after\n'`)
	spec.Env = map[string]string{"K": "AKIAEXAMPLE"}
	_, out, _, err := run(t, spec)
	if err != nil || out != "before [REDACTED:K] after\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestRunEnvOverrideAndOverrode(t *testing.T) {
	spec := sh(`printenv FOO; printenv KEEP`)
	spec.ParentEnv = append([]string{"FOO=from-parent", "KEEP=kept", "FOO=dup"}, baseEnv...)
	spec.Env = map[string]string{"FOO": "injected-val", "NEW": "n"}
	res, out, _, err := run(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	if out != "[REDACTED:FOO]\nkept\n" {
		t.Fatalf("out %q", out)
	}
	if got := strings.Join(res.Overrode, ","); got != "FOO" {
		t.Fatalf("overrode %q", got)
	}
}

func TestRunParentEnvDefaultsToOSEnviron(t *testing.T) {
	t.Setenv("RUNNER_TEST_MARKER", "visible")
	_, out, _, err := run(t, Spec{Argv: []string{"/bin/sh", "-c", "printenv RUNNER_TEST_MARKER"}})
	if err != nil || out != "visible\n" {
		t.Fatalf("%q %v", out, err)
	}
	// an explicit empty env is empty
	res, out, _, err := run(t, Spec{Argv: []string{"/usr/bin/env"}, ParentEnv: []string{}})
	if err != nil || res.ExitCode != 0 || strings.Contains(out, "RUNNER_TEST_MARKER") {
		t.Fatalf("%+v %q %v", res, out, err)
	}
}

func TestRunCleanEnvDoesNotLeakDaemonEnv(t *testing.T) {
	t.Setenv("DAEMON_ONLY", "x")
	spec := sh(`printenv DAEMON_ONLY`)
	res, out, _, err := run(t, spec) // ParentEnv explicit: daemon env absent
	if err != nil || res.ExitCode != 1 || out != "" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
}

func TestRunCwd(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	spec := sh("pwd")
	spec.Cwd = dir
	_, out, _, err := run(t, spec)
	if err != nil || strings.TrimSpace(out) != dir {
		t.Fatalf("%q %v", out, err)
	}
}

func TestRunRelativeCommandResolvedAgainstCwd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh"), []byte("#!/bin/sh\necho deployed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, out, _, err := run(t, Spec{Argv: []string{"./deploy.sh"}, Cwd: dir, ParentEnv: baseEnv})
	if err != nil || res.ExitCode != 0 || out != "deployed\n" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
}

func TestRunPathLookupUsesChildPATH(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mytool"), []byte("#!/bin/sh\necho mytool-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// "." and "" in PATH must be ignored; the absolute dir is honoured.
	env := []string{"PATH=:.:" + dir + ":/usr/bin:/bin"}
	res, out, _, err := run(t, Spec{Argv: []string{"mytool"}, ParentEnv: env})
	if err != nil || res.ExitCode != 0 || out != "mytool-ran\n" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
	// relative PATH entries are never searched
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "planted"), []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, out, _, err = run(t, Spec{Argv: []string{"planted"}, Cwd: cwd, ParentEnv: []string{"PATH=.:"}})
	if !errors.Is(err, ErrCommandNotFound) || res.ExitCode != 127 || out != "" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
	// injected PATH wins over the parent's
	spec := Spec{Argv: []string{"mytool"}, ParentEnv: []string{"PATH=/usr/bin:/bin"}, Env: map[string]string{"PATH": dir}}
	res, out, _, err = run(t, spec)
	if err != nil || out != "mytool-ran\n" || len(res.Overrode) != 1 || res.Overrode[0] != "PATH" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
	// no PATH at all falls back to /usr/bin:/bin
	res, _, _, err = run(t, Spec{Argv: []string{"true"}, ParentEnv: []string{}})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	for _, argv0 := range []string{"definitely-not-a-command-xyz", "/no/such/binary", "./missing"} {
		res, _, _, err := run(t, Spec{Argv: []string{argv0}, ParentEnv: baseEnv})
		if !errors.Is(err, ErrCommandNotFound) || res.ExitCode != 127 {
			t.Errorf("%s: %+v %v", argv0, res, err)
		}
	}
}

func TestRunCannotExecute(t *testing.T) {
	dir := t.TempDir()
	noexec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(noexec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, _, err := run(t, Spec{Argv: []string{noexec}, ParentEnv: baseEnv})
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("noexec: %+v %v", res, err)
	}
	res, _, _, err = run(t, Spec{Argv: []string{dir}, ParentEnv: baseEnv})
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("dir: %+v %v", res, err)
	}
	// non-exec file found via PATH
	res, _, _, err = run(t, Spec{Argv: []string{"noexec"}, ParentEnv: []string{"PATH=" + dir}})
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("path noexec: %+v %v", res, err)
	}
	// exec format error: executable file without shebang that is binary junk
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte{0x01, 0x02, 0x03, 0x04}, 0o755); err != nil {
		t.Fatal(err)
	}
	res, _, _, err = run(t, Spec{Argv: []string{junk}, ParentEnv: baseEnv})
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("junk: %+v %v", res, err)
	}
	// bad cwd
	spec := sh("true")
	spec.Cwd = filepath.Join(dir, "nope")
	res, _, _, err = run(t, spec)
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("cwd: %+v %v", res, err)
	}
	spec.Cwd = noexec // a file, not a dir
	res, _, _, err = run(t, spec)
	if !errors.Is(err, ErrCannotExecute) || res.ExitCode != 126 {
		t.Errorf("cwd file: %+v %v", res, err)
	}
}

func TestRunInvalidSpecs(t *testing.T) {
	tests := map[string]Spec{
		"empty argv":     {},
		"empty argv0":    {Argv: []string{""}},
		"nul in argv":    {Argv: []string{"true", "a\x00b"}},
		"relative cwd":   {Argv: []string{"true"}, Cwd: "rel/dir"},
		"nul in cwd":     {Argv: []string{"true"}, Cwd: "/tmp/\x00"},
		"neg timeout":    {Argv: []string{"true"}, Timeout: -1},
		"neg grace":      {Argv: []string{"true"}, KillGrace: -1},
		"bad env name":   {Argv: []string{"true"}, Env: map[string]string{"A=B": "x"}},
		"empty env name": {Argv: []string{"true"}, Env: map[string]string{"": "x"}},
		"digit env name": {Argv: []string{"true"}, Env: map[string]string{"1A": "x"}},
		"nul in value":   {Argv: []string{"true"}, Env: map[string]string{"A": "x\x00y"}},
		"nul in parent":  {Argv: []string{"true"}, ParentEnv: []string{"A=b\x00"}},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := Run(context.Background(), spec, nil, nil)
			if !errors.Is(err, ErrInvalidSpec) || res.ExitCode != ExitNotStarted {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

func TestRunErrorsNeverContainSecretValues(t *testing.T) {
	const secret = "sup3r-s3cret-v@lue-9999"
	var so, se bytes.Buffer
	// Force several error paths with the secret present in Spec.Env, and in
	// attacker-influenced places (argv0, cwd) where lower layers echo input.
	specs := []Spec{
		{Argv: []string{"/bin/nonexistent-" + secret}, Env: map[string]string{"A": secret}},
		{Argv: []string{"nonexistent-" + secret}, Env: map[string]string{"A": secret}, ParentEnv: baseEnv},
		{Argv: []string{"true"}, Cwd: "/no/such/" + secret, Env: map[string]string{"A": secret}},
		{Argv: []string{"true"}, Cwd: "relative/" + secret, Env: map[string]string{"A": secret}},
		{Argv: []string{"true", "x\x00" + secret}, Env: map[string]string{"A": secret}},
		{Argv: []string{"true"}, Env: map[string]string{"A": secret, "bad=name" + secret: "x"}},
		{Argv: []string{"true"}, Env: map[string]string{"A": secret + "\x00"}},
		{Argv: []string{"true"}, Env: map[string]string{"A": secret}, Timeout: -1},
	}
	for i, spec := range specs {
		_, err := Run(context.Background(), spec, &so, &se)
		if err == nil {
			t.Fatalf("spec %d: expected error", i)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("spec %d: error leaks secret: %v", i, err)
		}
		if i < 3 && !strings.Contains(err.Error(), "[REDACTED:A]") {
			t.Errorf("spec %d: expected scrubbed placeholder in %v", i, err)
		}
	}
	// writer errors must not leak either
	spec := sh("echo hi")
	spec.Env = map[string]string{"A": secret}
	_, err := Run(context.Background(), spec, errWriter{errors.New("write failed: " + secret)}, nil)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("writer error: %v", err)
	}
}

func TestRunStreamsIncrementally(t *testing.T) {
	spec := sh(`echo first; sleep 1; echo second`)
	spec.Env = map[string]string{"UNUSED": "a-secret-longer-than-line-0123456789"}
	var so safeBuf
	res, err := Run(context.Background(), spec, &so, nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatal(res, err)
	}
	var first, second time.Time
	for _, ev := range so.events {
		if strings.Contains(ev.data, "first") && first.IsZero() {
			first = ev.at
		}
		if strings.Contains(ev.data, "second") && second.IsZero() {
			second = ev.at
		}
	}
	if first.IsZero() || second.IsZero() {
		t.Fatalf("events: %+v", so.events)
	}
	if gap := second.Sub(first); gap < 700*time.Millisecond {
		t.Fatalf("first line was not delivered before the second was produced (gap %v)", gap)
	}
}

func TestRunStdinIsClosed(t *testing.T) {
	// cat would block forever if stdin were an open pipe/tty.
	spec := sh("cat; echo done")
	spec.Timeout = 5 * time.Second
	res, out, _, err := run(t, spec)
	if err != nil || res.TimedOut || out != "done\n" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
}

func TestRunTimeout(t *testing.T) {
	spec := sh("sleep 30")
	spec.Timeout = 200 * time.Millisecond
	res, _, _, err := run(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != 124 || !res.Signaled {
		t.Fatalf("%+v", res)
	}
	if res.Duration > 5*time.Second {
		t.Fatalf("took %v", res.Duration)
	}
}

func TestRunTimeoutTermTrappedStill124(t *testing.T) {
	spec := sh(`trap 'echo cleaning; exit 3' TERM; sleep 30 & wait`)
	spec.Timeout = time.Second // generous: the trap must be installed before TERM
	res, out, _, err := run(t, spec)
	if err != nil || !res.TimedOut || res.ExitCode != 124 || res.Signaled {
		t.Fatalf("%+v %v", res, err)
	}
	if out != "cleaning\n" {
		t.Fatalf("graceful TERM handler output lost: %q", out)
	}
}

func TestRunTimeoutEscalatesToSIGKILL(t *testing.T) {
	// sh ignores TERM and so does its sleep child (ignored dispositions are inherited).
	spec := sh(`trap '' TERM; sleep 30`)
	spec.Timeout = time.Second // generous: the trap must be installed before TERM
	spec.KillGrace = 300 * time.Millisecond
	start := time.Now()
	res, _, _, err := run(t, spec)
	if err != nil || !res.TimedOut || res.ExitCode != 124 || !res.Signaled {
		t.Fatalf("%+v %v", res, err)
	}
	if el := time.Since(start); el < 1250*time.Millisecond || el > 10*time.Second {
		t.Fatalf("elapsed %v: expected TERM then KILL after grace", el)
	}
}

// pidAlive reports whether pid still exists (zombies count as dead for our
// purposes only if reaped; the orphaned sleep is reparented to init and reaped).
func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("grandchild %d still alive", pid)
}

func TestRunTimeoutKillsWholeProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	spec := sh(`sleep 30 & echo $! > ` + pidFile + `; wait`)
	spec.Timeout = 300 * time.Millisecond
	res, _, _, err := run(t, spec)
	if err != nil || !res.TimedOut {
		t.Fatalf("%+v %v", res, err)
	}
	b, rerr := os.ReadFile(pidFile)
	if rerr != nil {
		t.Fatal(rerr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		t.Fatalf("bad pid %q", b)
	}
	waitDead(t, pid)
}

func TestRunCancelKillsWholeProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	spec := sh(`sleep 30 & echo $! > ` + pidFile + `; wait`)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res, err := Run(ctx, spec, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if res.TimedOut || res.ExitCode != 143 || !res.Signaled {
		t.Fatalf("%+v", res)
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		t.Fatalf("bad pid %q", b)
	}
	waitDead(t, pid)
}

func TestRunContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, sh("echo should-not-run"), nil, nil)
	if !errors.Is(err, context.Canceled) || res.ExitCode != ExitNotStarted {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRunKillsBackgroundLeftoversAfterNormalExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	// sh exits immediately, leaving a sleeping background child in the group.
	spec := sh(`sleep 30 >/dev/null 2>&1 & echo $! > ` + pidFile)
	start := time.Now()
	res, _, _, err := run(t, spec)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Run blocked on leftover child")
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	waitDead(t, pid)
}

func TestRunDoesNotHangOnEscapedPipeHolder(t *testing.T) {
	// A grandchild in its own session keeps stdout open past the leader. Run
	// must give up draining after KillGrace instead of hanging.
	if _, err := os.Stat("/usr/bin/perl"); err != nil {
		t.Skip("perl not available for setsid")
	}
	spec := Spec{
		Argv:      []string{"/usr/bin/perl", "-e", `use POSIX; if (fork() == 0) { POSIX::setsid(); sleep 3; exit 0 } print "parent-done\n"; exit 0`},
		ParentEnv: baseEnv,
		KillGrace: 300 * time.Millisecond,
	}
	start := time.Now()
	res, out, _, err := run(t, spec)
	if err != nil || res.ExitCode != 0 || out != "parent-done\n" {
		t.Fatalf("%+v %q %v", res, out, err)
	}
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("hung waiting for escaped pipe holder: %v", time.Since(start))
	}
}

func TestRunForwardsSignals(t *testing.T) {
	spec := sh(`trap "exit 42" TERM; echo ready; sleep 10`)
	sigs := make(chan os.Signal, 1)
	spec.Signals = sigs
	var so safeBuf
	go func() {
		for i := 0; i < 500 && !strings.Contains(so.String(), "ready"); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		sigs <- syscall.SIGTERM
	}()
	start := time.Now()
	res, err := Run(context.Background(), spec, &so, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 42 || res.TimedOut || res.Signaled {
		t.Fatalf("%+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("signal not forwarded promptly")
	}
}

func TestRunForwardedSignalReachesGrandchildren(t *testing.T) {
	spec := sh(`sleep 30 & wait`)
	sigs := make(chan os.Signal, 2)
	spec.Signals = sigs
	sigs <- nil // nil entries are ignored
	go func() {
		time.Sleep(300 * time.Millisecond)
		sigs <- syscall.SIGTERM
	}()
	start := time.Now()
	res, _, _, err := run(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 143 || time.Since(start) > 5*time.Second {
		t.Fatalf("%+v", res)
	}
}

func TestRunNonSyscallSignalIgnored(t *testing.T) {
	spec := sh(`sleep 0.5; exit 5`)
	sigs := make(chan os.Signal, 1)
	spec.Signals = sigs
	sigs <- fakeSig{}
	res, _, _, err := run(t, spec)
	if err != nil || res.ExitCode != 5 {
		t.Fatalf("%+v %v", res, err)
	}
}

type fakeSig struct{}

func (fakeSig) String() string { return "fake" }
func (fakeSig) Signal()        {}

func TestRunWriterErrorDoesNotBlockChild(t *testing.T) {
	boom := errors.New("client went away")
	// 1 MiB > pipe buffer: the child would block if we stopped reading.
	spec := sh(`head -c 1048576 /dev/zero | tr '\0' x; echo done >&2`)
	spec.Timeout = 10 * time.Second
	var se safeBuf
	res, err := Run(context.Background(), spec, errWriter{boom}, &se)
	if err == nil || !strings.Contains(err.Error(), "client went away") {
		t.Fatalf("err = %v", err)
	}
	if res.ExitCode != 0 || res.TimedOut {
		t.Fatalf("%+v", res)
	}
	if se.String() != "done\n" {
		t.Fatalf("stderr %q", se.String())
	}
	// and the stderr side
	_, err = Run(context.Background(), sh("echo x >&2"), nil, errWriter{boom})
	if err == nil || !strings.Contains(err.Error(), "stderr") {
		t.Fatalf("stderr err = %v", err)
	}
}

func TestRunSameWriterForBothStreamsIsSerialised(t *testing.T) {
	spec := sh(`for i in 1 2 3 4 5 6 7 8 9 10; do echo out$i; echo err$i >&2; done`)
	var buf bytes.Buffer // not goroutine-safe: relies on Run's serialisation (-race)
	res, err := Run(context.Background(), spec, &buf, &buf)
	if err != nil || res.ExitCode != 0 {
		t.Fatal(res, err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 20 {
		t.Fatalf("lines = %d", n)
	}
}

func TestRunLargeOutputIntegrity(t *testing.T) {
	spec := sh(`head -c 2000000 /dev/zero | tr '\0' a; printf SECRETVAL; head -c 100 /dev/zero | tr '\0' b`)
	spec.Env = map[string]string{"S": "SECRETVAL"}
	var out bytes.Buffer
	res, err := Run(context.Background(), spec, &out, nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatal(res, err)
	}
	want := strings.Repeat("a", 2000000) + "[REDACTED:S]" + strings.Repeat("b", 100)
	if out.String() != want {
		t.Fatalf("len %d vs %d", out.Len(), len(want))
	}
}
