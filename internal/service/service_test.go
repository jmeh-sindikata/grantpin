package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls   []string
	results map[string][]Result // by first arg; consumed in order, last repeats
	err     error
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (Result, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.err != nil {
		return Result{}, f.err
	}
	rs := f.results[args[0]]
	if len(rs) == 0 {
		return Result{}, nil
	}
	r := rs[0]
	if len(rs) > 1 {
		f.results[args[0]] = rs[1:]
	}
	return r, nil
}

func newTest(t *testing.T, r Runner) (*launchd, string) {
	t.Helper()
	home := t.TempDir()
	exe := filepath.Join(home, "bin", "grantd")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(exe)
	return &launchd{run: r, home: home, uid: 501, sleep: func(time.Duration) {}}, real
}

const wantPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.grantd.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/g &amp; co/grantd</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>StandardOutPath</key>
	<string>/logs/daemon.out.log</string>
	<key>StandardErrorPath</key>
	<string>/logs/daemon.err.log</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>GRANTD_SOCKET</key>
		<string>/run/g.sock</string>
	</dict>
</dict>
</plist>
`

func TestPlistGolden(t *testing.T) {
	got, err := renderPlist(plistSpec{Label: Label, Exe: "/opt/g & co/grantd", Socket: "/run/g.sock", OutLog: "/logs/daemon.out.log", ErrLog: "/logs/daemon.err.log"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantPlist {
		t.Fatalf("plist mismatch:\n%s", got)
	}
}

const wantPlistKeychainFallback = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.grantd.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/grantd</string>
		<string>daemon</string>
		<string>--keychain-fallback</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>StandardOutPath</key>
	<string>/logs/daemon.out.log</string>
	<key>StandardErrorPath</key>
	<string>/logs/daemon.err.log</string>
</dict>
</plist>
`

func TestPlistGoldenKeychainFallback(t *testing.T) {
	got, err := renderPlist(plistSpec{Label: Label, Exe: "/opt/grantd", OutLog: "/logs/daemon.out.log", ErrLog: "/logs/daemon.err.log", KeychainFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantPlistKeychainFallback {
		t.Fatalf("plist mismatch:\n%s", got)
	}
	args, err := plistArgs(got)
	if err != nil || !reflect.DeepEqual(args, []string{"/opt/grantd", "daemon", "--keychain-fallback"}) {
		t.Errorf("plistArgs = %q, %v", args, err)
	}
}

func TestStatusReportsKeychainFallback(t *testing.T) {
	ctx := context.Background()
	for _, fb := range []bool{false, true} {
		f := &fakeRunner{results: map[string][]Result{"print": {{Output: printRunning}}}}
		l, exe := newTest(t, f)
		if err := l.Install(ctx, Options{Exe: exe, KeychainFallback: fb}); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(l.plistPath())
		if got := strings.Contains(string(data), "--keychain-fallback"); got != fb {
			t.Errorf("fallback=%v: plist contains flag = %v", fb, got)
		}
		st, err := l.Status(ctx)
		if err != nil || st.KeychainFallback != fb || st.ExePath != exe {
			t.Errorf("fallback=%v: status = %+v, %v", fb, st, err)
		}
	}
}

func TestPlistRoundTrip(t *testing.T) {
	for _, sock := range []string{"", "/run/g.sock"} {
		data, _ := renderPlist(plistSpec{Label: Label, Exe: "/opt/g & co/grantd", Socket: sock, OutLog: "/o", ErrLog: "/e"})
		m, err := parsePlist(data)
		if err != nil {
			t.Fatal(err)
		}
		if m["Label"] != Label || m["RunAtLoad"] != true || m["ProcessType"] != "Background" || m["LimitLoadToSessionType"] != "Aqua" {
			t.Errorf("bad scalars: %v", m)
		}
		if !reflect.DeepEqual(m["ProgramArguments"], []any{"/opt/g & co/grantd", "daemon"}) {
			t.Errorf("args: %v", m["ProgramArguments"])
		}
		if !reflect.DeepEqual(m["KeepAlive"], map[string]any{"SuccessfulExit": false}) {
			t.Errorf("keepalive: %v", m["KeepAlive"])
		}
		env, has := m["EnvironmentVariables"]
		if sock == "" && has {
			t.Errorf("env present without socket: %v", env)
		}
		if sock != "" && !reflect.DeepEqual(env, map[string]any{"GRANTD_SOCKET": sock}) {
			t.Errorf("env: %v", env)
		}
		if exe, err := plistExe(data); err != nil || exe != "/opt/g & co/grantd" {
			t.Errorf("plistExe = %q, %v", exe, err)
		}
	}
}

func TestParsePlistErrors(t *testing.T) {
	if _, err := parsePlist([]byte("<plist><dict><key>a</key><string>x")); err == nil {
		t.Error("truncated plist accepted")
	}
	if _, err := parsePlist([]byte("")); err == nil {
		t.Error("empty plist accepted")
	}
	if _, err := plistExe([]byte("<plist><dict></dict></plist>")); err == nil {
		t.Error("missing ProgramArguments accepted")
	}
	if _, err := plistExe([]byte("<plist><dict><key>ProgramArguments</key><array><true/></array></dict></plist>")); err == nil {
		t.Error("non-string arg accepted")
	}
	m, err := parsePlist([]byte("<plist><dict><key>n</key><integer>7</integer><key>d</key><date>x</date></dict></plist>"))
	if err != nil || m["n"] != int64(7) {
		t.Errorf("integer: %v %v", m, err)
	}
	if _, err := parsePlist([]byte("<plist><dict><key>n</key><integer>x</integer></dict></plist>")); err == nil {
		t.Error("bad integer accepted")
	}
}

func TestInstallSequenceFresh(t *testing.T) {
	f := &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}}}
	l, exe := newTest(t, f)
	logs := filepath.Join(l.home, "logs")
	if err := l.Install(context.Background(), Options{Exe: exe, Socket: "/run/g.sock", LogDir: logs}); err != nil {
		t.Fatal(err)
	}
	want := []string{"print gui/501/dev.grantd.daemon", "bootstrap gui/501 " + l.plistPath()}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q, want %q", f.calls, want)
	}
	fi, err := os.Stat(l.plistPath())
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("plist stat: %v %v", fi, err)
	}
	data, _ := os.ReadFile(l.plistPath())
	if got, _ := plistExe(data); got != exe {
		t.Errorf("exe = %q want %q", got, exe)
	}
	if di, err := os.Stat(logs); err != nil || !di.IsDir() {
		t.Errorf("log dir not created: %v", err)
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("plutil"); err == nil {
			if out, err := exec.Command("plutil", "-lint", l.plistPath()).CombinedOutput(); err != nil {
				t.Errorf("plutil -lint: %v: %s", err, out)
			}
		}
	}
}

func TestInstallIdempotentWhenLoaded(t *testing.T) {
	f := &fakeRunner{results: map[string][]Result{
		"print":     {{ExitCode: 0}},
		"bootstrap": {{ExitCode: 5, Output: "Input/output error"}, {ExitCode: 0}},
	}}
	l, exe := newTest(t, f)
	if err := l.Install(context.Background(), Options{Exe: exe}); err != nil {
		t.Fatal(err)
	}
	bp := "bootstrap gui/501 " + l.plistPath()
	want := []string{"print gui/501/dev.grantd.daemon", "bootout gui/501/dev.grantd.daemon", bp, bp}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q, want %q", f.calls, want)
	}
	// second install produces the same file
	if err := l.Install(context.Background(), Options{Exe: exe}); err != nil {
		t.Fatal(err)
	}
}

func TestInstallErrors(t *testing.T) {
	ctx := context.Background()
	f := &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}, "bootstrap": {{ExitCode: 5, Output: "boom"}}}}
	l, exe := newTest(t, f)
	if err := l.Install(ctx, Options{Exe: exe}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("bootstrap failure: %v", err)
	}
	if err := l.Install(ctx, Options{Exe: "relative/grantd"}); err == nil {
		t.Error("relative exe accepted")
	}
	if err := l.Install(ctx, Options{Exe: filepath.Join(l.home, "nope")}); err == nil {
		t.Error("missing exe accepted")
	}
	if err := l.Install(ctx, Options{Exe: exe, Socket: "rel.sock"}); err == nil {
		t.Error("relative socket accepted")
	}
	if err := l.Install(ctx, Options{Exe: exe, LogDir: "rel"}); err == nil {
		t.Error("relative log dir accepted")
	}
	g := &fakeRunner{err: errors.New("no launchctl")}
	l2, exe2 := newTest(t, g)
	if err := l2.Install(ctx, Options{Exe: exe2}); err == nil {
		t.Error("runner error swallowed")
	}
	h := &fakeRunner{results: map[string][]Result{"print": {{}}, "bootout": {{ExitCode: 1, Output: "denied"}}}}
	l3, exe3 := newTest(t, h)
	if err := l3.Install(ctx, Options{Exe: exe3}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("bootout failure: %v", err)
	}
	// directory instead of file, non-executable file
	if err := l.Install(ctx, Options{Exe: l.home}); err == nil {
		t.Error("directory accepted as exe")
	}
	plain := filepath.Join(l.home, "plain")
	os.WriteFile(plain, nil, 0o644)
	if err := l.Install(ctx, Options{Exe: plain}); err == nil {
		t.Error("non-executable accepted")
	}
}

func TestInstallRefusesTempDir(t *testing.T) {
	f := &fakeRunner{}
	l, exe := newTest(t, f)
	l.tempRoots = []string{filepath.Dir(exe)}
	err := l.Install(context.Background(), Options{Exe: exe})
	if err == nil || !strings.Contains(err.Error(), "temporary directory") {
		t.Fatalf("err = %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("launchctl called: %v", f.calls)
	}
	if _, serr := os.Stat(l.plistPath()); !os.IsNotExist(serr) {
		t.Error("plist written despite refusal")
	}
	// the real temp roots refuse t.TempDir() binaries too
	l.tempRoots = defaultTempRoots()
	if err := l.Install(context.Background(), Options{Exe: exe}); err == nil {
		t.Error("default temp roots did not refuse a TempDir binary")
	}
}

func TestResolveExeDefaultAndSymlink(t *testing.T) {
	got, err := resolveExe("")
	if err != nil || !filepath.IsAbs(got) {
		t.Fatalf("default exe: %q %v", got, err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	os.WriteFile(target, nil, 0o755)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(target)
	if got, err := resolveExe(link); err != nil || got != want {
		t.Errorf("resolveExe(link) = %q, %v; want %q", got, err, want)
	}
}

func TestUninstall(t *testing.T) {
	ctx := context.Background()
	// absent
	f := &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}}}
	l, _ := newTest(t, f)
	if err := l.Uninstall(ctx); err != nil {
		t.Fatalf("absent uninstall: %v", err)
	}
	if !reflect.DeepEqual(f.calls, []string{"print gui/501/dev.grantd.daemon"}) {
		t.Errorf("calls: %q", f.calls)
	}
	// present and loaded
	g := &fakeRunner{results: map[string][]Result{"print": {{}}}}
	l2, _ := newTest(t, g)
	os.MkdirAll(filepath.Dir(l2.plistPath()), 0o755)
	os.WriteFile(l2.plistPath(), []byte("x"), 0o644)
	if err := l2.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.calls, []string{"print gui/501/dev.grantd.daemon", "bootout gui/501/dev.grantd.daemon"}) {
		t.Errorf("calls: %q", g.calls)
	}
	if _, err := os.Stat(l2.plistPath()); !os.IsNotExist(err) {
		t.Error("plist not removed")
	}
	// bootout failure keeps plist
	h := &fakeRunner{results: map[string][]Result{"print": {{}}, "bootout": {{ExitCode: 1}}}}
	l3, _ := newTest(t, h)
	os.MkdirAll(filepath.Dir(l3.plistPath()), 0o755)
	os.WriteFile(l3.plistPath(), []byte("x"), 0o644)
	if err := l3.Uninstall(ctx); err == nil {
		t.Error("bootout failure ignored")
	}
	if _, err := os.Stat(l3.plistPath()); err != nil {
		t.Error("plist removed despite failed bootout")
	}
	// runner error
	l4, _ := newTest(t, &fakeRunner{err: errors.New("x")})
	if err := l4.Uninstall(ctx); err == nil {
		t.Error("runner error swallowed")
	}
}

// Trimmed from `launchctl print gui/501/com.apple.Finder` on macOS (real
// format; nested blocks kept to prove they are not mistaken for top-level).
const printRunning = `gui/501/com.apple.Finder = {
	active count = 8
	path = /System/Library/LaunchAgents/com.apple.Finder.plist
	type = LaunchAgent
	state = running

	program = /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}

	domain = gui/501 [100023]
	runs = 1
	pid = 682
	immediate reason = non-ipc demand
	forks = 0

	event triggers = {
		com.example.finder.RemoveOldTrashItems => {
			keepalive = 0
			descriptor = {
				"Priority" => "Maintenance"
			}
		}
	}

	dynamic endpoints = {
		"com.apple.finder.ServiceProvider" = {
			port = 0x96a63
			state = nested
			pid = 1
		}
	}
}
`

const printIdle = `gui/501/dev.grantd.daemon = {
	active count = 0
	state = not running
	runs = 3
	last exit code = 1
}
`

func TestParsePrint(t *testing.T) {
	if s, p := parsePrint(printRunning); s != "running" || p != 682 {
		t.Errorf("running: %q %d", s, p)
	}
	if s, p := parsePrint(printIdle); s != "not running" || p != 0 {
		t.Errorf("idle: %q %d", s, p)
	}
	if s, p := parsePrint("garbage\n\tpid = abc\n"); s != "" || p != 0 {
		t.Errorf("garbage: %q %d", s, p)
	}
}

func TestStatus(t *testing.T) {
	ctx := context.Background()
	// not installed, not loaded
	l, _ := newTest(t, &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}}})
	st, err := l.Status(ctx)
	if err != nil || st.Installed || st.Loaded || st.Running {
		t.Fatalf("absent: %+v %v", st, err)
	}
	// installed + running
	f := &fakeRunner{results: map[string][]Result{"print": {{Output: printRunning}}}}
	l, exe := newTest(t, f)
	if err := l.Install(ctx, Options{Exe: exe}); err != nil {
		t.Fatal(err)
	}
	st, err = l.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed || !st.Loaded || !st.Running || st.PID != 682 || st.State != "running" || st.ExePath != exe || st.ExeMissing || st.PlistPath != l.plistPath() || st.Label != Label {
		t.Errorf("status: %+v", st)
	}
	// exe vanished, loaded but idle
	os.Remove(exe)
	f.results["print"] = []Result{{Output: printIdle}}
	st, _ = l.Status(ctx)
	if !st.ExeMissing || st.Running || !st.Loaded || st.State != "not running" {
		t.Errorf("missing exe: %+v", st)
	}
	// corrupt plist: installed, no exe, no error
	os.WriteFile(l.plistPath(), []byte("junk"), 0o644)
	st, err = l.Status(ctx)
	if err != nil || !st.Installed || st.ExePath != "" {
		t.Errorf("corrupt: %+v %v", st, err)
	}
	// unreadable plist path (a directory)
	os.Remove(l.plistPath())
	os.Mkdir(l.plistPath(), 0o755)
	if _, err := l.Status(ctx); err == nil {
		t.Error("read error swallowed")
	}
	// runner error
	l5, _ := newTest(t, &fakeRunner{err: errors.New("x")})
	if _, err := l5.Status(ctx); err == nil {
		t.Error("runner error swallowed")
	}
}

func TestPathsAndNew(t *testing.T) {
	l, err := newLaunchd(&fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(l.plistPath(), "/Library/LaunchAgents/dev.grantd.daemon.plist") || !strings.HasSuffix(l.defaultLogDir(), "/Library/Logs/grantd") {
		t.Errorf("paths: %s %s", l.plistPath(), l.defaultLogDir())
	}
	m, err := New()
	if runtime.GOOS == "darwin" {
		if err != nil || m == nil {
			t.Errorf("New: %v", err)
		}
	} else if !errors.Is(err, ErrUnsupported) {
		t.Errorf("New err = %v", err)
	}
}

func TestExecRunnerNonDestructive(t *testing.T) {
	ctx := context.Background()
	res, err := execCommand(ctx, "/bin/sh", "-c", "echo hi; exit 3")
	if err != nil || res.ExitCode != 3 || !strings.Contains(res.Output, "hi") {
		t.Errorf("exit code: %+v %v", res, err)
	}
	res, err = execCommand(ctx, "/bin/sh", "-c", "true")
	if err != nil || res.ExitCode != 0 {
		t.Errorf("ok: %+v %v", res, err)
	}
	if _, err := execCommand(ctx, "/nonexistent/binary"); err == nil {
		t.Error("missing binary not an error")
	}
}
