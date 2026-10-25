package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"grantd/internal/service"
)

type fakeMgr struct {
	opts      service.Options
	st        service.Status
	err       error
	uninstall bool
}

func (f *fakeMgr) Install(_ context.Context, o service.Options) error { f.opts = o; return f.err }
func (f *fakeMgr) Uninstall(context.Context) error                    { f.uninstall = true; return f.err }
func (f *fakeMgr) Status(context.Context) (service.Status, error)     { return f.st, f.err }

func runService(t *testing.T, m *fakeMgr, mkErr error, args ...string) (string, int, error) {
	t.Helper()
	oldNew, oldExit := newServiceManager, serviceExit
	defer func() { newServiceManager, serviceExit = oldNew, oldExit }()
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
	out, _, err := runService(t, m, nil, "install", "--exe", "/x/grantd", "--socket", "/s.sock", "--log-dir", "/logs")
	if err != nil {
		t.Fatal(err)
	}
	if m.opts.Exe != "/x/grantd" || m.opts.Socket != "/s.sock" || m.opts.LogDir != "/logs" {
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
