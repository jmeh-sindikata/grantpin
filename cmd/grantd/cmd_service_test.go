package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/service"
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
	out, _, err := runService(t, m, nil, "install", "--exe", "/x/grantd", "--socket", "/s.sock", "--path", "/opt/homebrew/bin:/usr/bin", "--log-dir", "/logs")
	if err != nil {
		t.Fatal(err)
	}
	if m.opts.Exe != "/x/grantd" || m.opts.Socket != "/s.sock" || m.opts.LogDir != "/logs" || m.opts.Path != "/opt/homebrew/bin:/usr/bin" {
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
	t.Setenv("GRANTD_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	m := &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	out, _, err := runService(t, m, nil, "install")
	if err != nil || m.opts.Socket != "" || strings.Contains(out, "GRANTD_SOCKET") {
		t.Errorf("default: socket=%q out=%q err=%v", m.opts.Socket, out, err)
	}

	// $GRANTD_SOCKET differing from the default is recorded and printed.
	t.Setenv("GRANTD_SOCKET", "/tmp/gd.sock")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	out, _, err = runService(t, m, nil, "install")
	if err != nil || m.opts.Socket != "/tmp/gd.sock" || !strings.Contains(out, "/tmp/gd.sock") || !strings.Contains(out, platform) {
		t.Errorf("env: socket=%q out=%q err=%v", m.opts.Socket, out, err)
	}

	// $XDG_RUNTIME_DIR likewise.
	t.Setenv("GRANTD_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install"); err != nil || m.opts.Socket != "/run/user/1/grantd.sock" {
		t.Errorf("xdg: socket=%q err=%v", m.opts.Socket, err)
	}

	// An env socket equal to the default is not recorded.
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("GRANTD_SOCKET", platform)
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install"); err != nil || m.opts.Socket != "" {
		t.Errorf("equal: socket=%q err=%v", m.opts.Socket, err)
	}

	// An explicit --socket wins and is not second-guessed.
	t.Setenv("GRANTD_SOCKET", "/tmp/other.sock")
	m = &fakeMgr{st: service.Status{Label: "l", Installed: true}}
	if _, _, err = runService(t, m, nil, "install", "--socket", "/s.sock"); err != nil || m.opts.Socket != "/s.sock" {
		t.Errorf("flag: socket=%q err=%v", m.opts.Socket, err)
	}
}
