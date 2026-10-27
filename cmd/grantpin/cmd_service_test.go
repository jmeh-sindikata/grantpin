package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmeh-sindikata/grantpin/internal/daemon"
	"github.com/jmeh-sindikata/grantpin/internal/proto"
	"github.com/jmeh-sindikata/grantpin/internal/service"
)

type fakeMgr struct {
	opts       service.Options
	st         service.Status
	err        error
	installErr error
	uninstall  bool
}

func (f *fakeMgr) Install(_ context.Context, o service.Options) error {
	f.opts = o
	return errors.Join(f.err, f.installErr)
}
func (f *fakeMgr) Uninstall(context.Context) error                { f.uninstall = true; return f.err }
func (f *fakeMgr) Status(context.Context) (service.Status, error) { return f.st, f.err }

var statusErr error

func runService(t *testing.T, m *fakeMgr, mkErr error, args ...string) (string, int, error) {
	t.Helper()
	if os.Getenv("GRANTPIN_HOME") == "" {
		t.Setenv("GRANTPIN_HOME", t.TempDir())
	}
	oldNew, oldExit, oldStatus := newServiceManager, serviceExit, daemonStatus
	defer func() { newServiceManager, serviceExit, daemonStatus = oldNew, oldExit, oldStatus }()
	daemonStatus = func(_ context.Context, socket string) (*proto.StatusResult, error) {
		if statusErr != nil {
			return nil, statusErr
		}
		return &proto.StatusResult{PID: 42, Version: "v", Socket: socket}, nil
	}
	newServiceManager = func() (service.Manager, error) {
		if mkErr != nil {
			return nil, mkErr
		}
		return m, nil
	}
	code := 0
	serviceExit = func(c int) { code = c }
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"service"}, args...))
	err := root.Execute()
	return out.String(), code, err
}

func TestServiceInstallFlags(t *testing.T) {
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true, Loaded: true, Running: true, PID: 7, PlistPath: "/p", ExePath: "/e"}}
	out, _, err := runService(t, m, nil, "install", "--exe", "/x/grantpin", "--socket", "/s.sock", "--path", "/opt/homebrew/bin:/usr/bin", "--log-dir", "/logs")
	if err != nil {
		t.Fatal(err)
	}
	if m.opts.Exe != "/x/grantpin" || m.opts.Socket != "/s.sock" || m.opts.LogDir != "/logs" || m.opts.Path != "/opt/homebrew/bin:/usr/bin" {
		t.Errorf("opts = %+v", m.opts)
	}
	if !strings.Contains(out, "pid 7") || !strings.Contains(out, "installed") {
		t.Errorf("out = %q", out)
	}
}

func TestServiceStatusExitCodes(t *testing.T) {
	m := &fakeMgr{}
	out, code, err := runService(t, m, nil, "status")
	if err != nil || code != 3 || !strings.Contains(out, "installed: no") {
		t.Errorf("not installed: %q %v %d", out, err, code)
	}
	m.st = service.Status{Label: "l", Installed: true, ExeMissing: true, ExePath: "/gone"}
	out, code, err = runService(t, m, nil, "status")
	if err != nil || code != 0 || !strings.Contains(out, "no longer exists") || !strings.Contains(out, "running:   no") {
		t.Errorf("installed: %q %v %d", out, err, code)
	}
}

func TestServiceUninstallAndErrors(t *testing.T) {
	m := &fakeMgr{}
	if out, _, err := runService(t, m, nil, "uninstall"); err != nil || !m.uninstall || !strings.Contains(out, "removed") {
		t.Errorf("uninstall: %q %v", out, err)
	}
	boom := errors.New("boom")
	for _, verb := range []string{"install", "uninstall", "status"} {
		if _, _, err := runService(t, &fakeMgr{err: boom}, nil, verb); !errors.Is(err, boom) {
			t.Errorf("%s manager error: %v", verb, err)
		}
		if _, _, err := runService(t, m, service.ErrUnsupported, verb); !errors.Is(err, service.ErrUnsupported) {
			t.Errorf("%s ctor error: %v", verb, err)
		}
	}
}

func TestServiceInstallDaemonStatusAndWarning(t *testing.T) {
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	out, _, err := runService(t, m, nil, "install", "--socket", "/s.sock")
	if err != nil || !strings.Contains(out, "daemon:    running (pid 42") {
		t.Errorf("ready: %q %v", out, err)
	}

	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}, installErr: fmt.Errorf("%w within 10s; check /logs/daemon.err.log", service.ErrNotReady)}
	out, _, err = runService(t, m, nil, "install")
	if err != nil || !strings.Contains(out, "service installed and started") || !strings.Contains(out, "WARNING:") || !strings.Contains(out, "/logs/daemon.err.log") || strings.Contains(out, "daemon:    running") {
		t.Errorf("not ready: %q %v", out, err)
	}

	statusErr = errors.New("refused")
	defer func() { statusErr = nil }()
	out, _, err = runService(t, &fakeMgr{st: service.Status{Label: "l", Installed: true}}, nil, "install", "--socket", "/s.sock")
	if err != nil || !strings.Contains(out, "WARNING:   daemon status: refused") {
		t.Errorf("status err: %q %v", out, err)
	}
}

func TestServiceInstallRecordsNonDefaultSocket(t *testing.T) {
	platform, err := daemon.PlatformSocketPath()
	if err != nil {
		t.Fatal(err)
	}

	// Default socket: the plist stays minimal.
	t.Setenv("GRANTPIN_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	out, _, err := runService(t, m, nil, "install")
	if err != nil || m.opts.Socket != "" || strings.Contains(out, "GRANTPIN_SOCKET") {
		t.Errorf("default: socket=%q out=%q err=%v", m.opts.Socket, out, err)
	}

	// $GRANTPIN_SOCKET differing from the default is recorded and printed.
	t.Setenv("GRANTPIN_SOCKET", "/tmp/gd.sock")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	out, _, err = runService(t, m, nil, "install")
	if err != nil || m.opts.Socket != "/tmp/gd.sock" || !strings.Contains(out, "/tmp/gd.sock") || !strings.Contains(out, platform) {
		t.Errorf("env: socket=%q out=%q err=%v", m.opts.Socket, out, err)
	}

	// $XDG_RUNTIME_DIR likewise.
	t.Setenv("GRANTPIN_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install"); err != nil || m.opts.Socket != "/run/user/1/grantpin.sock" {
		t.Errorf("xdg: socket=%q err=%v", m.opts.Socket, err)
	}

	// An env socket equal to the default is not recorded.
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("GRANTPIN_SOCKET", platform)
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install"); err != nil || m.opts.Socket != "" {
		t.Errorf("equal: socket=%q err=%v", m.opts.Socket, err)
	}

	// An explicit --socket wins and is not second-guessed.
	t.Setenv("GRANTPIN_SOCKET", "/tmp/other.sock")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install", "--socket", "/s.sock"); err != nil || m.opts.Socket != "/s.sock" {
		t.Errorf("flag: socket=%q err=%v", m.opts.Socket, err)
	}
}

func markerPath(t *testing.T) string {
	t.Helper()
	dir, err := serviceDataDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, service.WantedFile)
}

func TestServiceDataDirFollowsGrantpinHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GRANTPIN_HOME", home)
	if dir, err := serviceDataDir(); err != nil || dir != home {
		t.Errorf("dir = %q %v", dir, err)
	}
}

func TestServiceInstallWritesMarkerOnlyOnSuccess(t *testing.T) {
	t.Setenv("GRANTPIN_HOME", t.TempDir())
	boom := errors.New("boom")
	if _, _, err := runService(t, &fakeMgr{installErr: boom}, nil, "install"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(markerPath(t)); !os.IsNotExist(err) {
		t.Errorf("failed install left a marker: %v", err)
	}
	if _, _, err := runService(t, &fakeMgr{}, service.ErrUnsupported, "install"); err == nil {
		t.Fatal("ctor error ignored")
	}
	if _, err := os.Lstat(markerPath(t)); !os.IsNotExist(err) {
		t.Errorf("unsupported install left a marker: %v", err)
	}

	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	for i := 0; i < 2; i++ { // idempotent
		if _, _, err := runService(t, m, nil, "install"); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(markerPath(t))
		if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
			t.Fatalf("marker: %v %v", fi, err)
		}
	}
}

func TestServiceInstallNotReadyStillWritesMarker(t *testing.T) {
	t.Setenv("GRANTPIN_HOME", t.TempDir())
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}, installErr: fmt.Errorf("%w within 10s", service.ErrNotReady)}
	if _, _, err := runService(t, m, nil, "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(markerPath(t)); err != nil {
		t.Errorf("no marker after installed-but-not-ready: %v", err)
	}
}

func TestServiceInstallRefusesSymlinkMarker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GRANTPIN_HOME", home)
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(outside, markerPath(t)); err != nil {
		t.Fatal(err)
	}
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err := runService(t, m, nil, "install"); err == nil {
		t.Error("install followed a symlink marker")
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Errorf("symlink target created: %v", err)
	}
}

func TestServiceUninstallRemovesMarker(t *testing.T) {
	t.Setenv("GRANTPIN_HOME", t.TempDir())
	// present
	if err := service.SetWanted(filepath.Dir(markerPath(t)), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runService(t, &fakeMgr{}, nil, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(markerPath(t)); !os.IsNotExist(err) {
		t.Errorf("marker remains: %v", err)
	}
	// absent (job missing too: the fake reports success for "not loaded")
	if _, _, err := runService(t, &fakeMgr{}, nil, "uninstall"); err != nil {
		t.Fatalf("absent: %v", err)
	}
	// the launchctl step fails: the user still no longer wants the service
	if err := service.SetWanted(filepath.Dir(markerPath(t)), true); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if _, _, err := runService(t, &fakeMgr{err: boom}, nil, "uninstall"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(markerPath(t)); !os.IsNotExist(err) {
		t.Errorf("marker remains after failed uninstall: %v", err)
	}
}

func TestServiceStatusReportsWanted(t *testing.T) {
	t.Setenv("GRANTPIN_HOME", t.TempDir())
	dir := filepath.Dir(markerPath(t))
	installed := &fakeMgr{st: service.Status{Label: "l", Installed: true, Loaded: true, Running: true, PID: 7, PlistPath: "/p", ExePath: "/e"}}

	out, code, err := runService(t, installed, nil, "status")
	if err != nil || code != 0 || !strings.HasSuffix(out, "wanted:    no\n") {
		t.Errorf("installed, not wanted: %q %v %d", out, err, code)
	}
	if err := service.SetWanted(dir, true); err != nil {
		t.Fatal(err)
	}
	out, _, _ = runService(t, installed, nil, "status")
	if !strings.HasSuffix(out, "exe:       /e\nwanted:    yes\n") {
		t.Errorf("installed, wanted: %q", out)
	}
	// Wanted but the definition is gone (the Homebrew case): still exit 3,
	// the old lines first, the new one appended.
	out, code, _ = runService(t, &fakeMgr{}, nil, "status")
	if code != 3 || out != "label:     \ninstalled: no\nwanted:    yes\n" {
		t.Errorf("not installed, wanted: %q %d", out, code)
	}
	// A symlink at the marker path does not count.
	os.Remove(markerPath(t))
	if err := os.Symlink(t.TempDir(), markerPath(t)); err != nil {
		t.Fatal(err)
	}
	out, _, _ = runService(t, installed, nil, "status")
	if !strings.HasSuffix(out, "wanted:    no\n") {
		t.Errorf("symlink: %q", out)
	}
}
