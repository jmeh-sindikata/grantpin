package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"grantd/internal/keystore"
)

// fakeDeleter records what it was asked to delete. No test in this package may
// reach a real Keychain: every test that gets as far as opening the key store
// replaces openKeyDeleter first.
type fakeDeleter struct {
	fallbackErr, hardwareErr error
	fallback, hardware       int
}

func (f *fakeDeleter) DeleteFallbackKEK(context.Context) error {
	f.fallback++
	return f.fallbackErr
}

func (f *fakeDeleter) DeleteSecureEnclaveKey(context.Context) error {
	f.hardware++
	return f.hardwareErr
}

func useFakeDeleter(t *testing.T, f *fakeDeleter) {
	t.Helper()
	old := openKeyDeleter
	openKeyDeleter = func() (keystore.Deleter, error) { return f, nil }
	t.Cleanup(func() { openKeyDeleter = old })
}

// noDaemon points the command at a socket nobody listens on.
func noDaemon(t *testing.T) string { return shortSocket(t) }

func TestKeystoreDeleteDeletes(t *testing.T) {
	for _, tc := range []struct {
		flag               string
		wantFall, wantHard int
	}{{"--fallback", 1, 0}, {"--hardware", 0, 1}} {
		f := &fakeDeleter{}
		useFakeDeleter(t, f)
		out, errs, err := cli(t, "", "keystore", "delete", tc.flag, "--yes", "--socket", noDaemon(t))
		if err != nil {
			t.Fatalf("%s: %v", tc.flag, err)
		}
		if f.fallback != tc.wantFall || f.hardware != tc.wantHard {
			t.Errorf("%s: fallback=%d hardware=%d deletions", tc.flag, f.fallback, f.hardware)
		}
		if out != "" {
			t.Errorf("%s: stdout = %q, want nothing", tc.flag, out)
		}
		if !strings.Contains(errs, "permanently unreadable") || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: stderr = %q, want just the warning", tc.flag, errs)
		}
	}
}

func TestKeystoreDeleteReportsMissingMaterial(t *testing.T) {
	for _, flag := range []string{"--fallback", "--hardware"} {
		f := &fakeDeleter{fallbackErr: keystore.ErrNoKeyMaterial, hardwareErr: keystore.ErrNoKeyMaterial}
		useFakeDeleter(t, f)
		out, _, err := cli(t, "", "keystore", "delete", flag, "--yes", "--socket", noDaemon(t))
		if exitCodeOf(err) != 3 || err == nil || err.Error() != "" || out != "" {
			t.Errorf("%s: code=%d err=%v out=%q, want exit 3 and no output", flag, exitCodeOf(err), err, out)
		}
	}
}

func TestKeystoreDeleteOtherFailure(t *testing.T) {
	f := &fakeDeleter{fallbackErr: errors.New("OSStatus -25293")}
	useFakeDeleter(t, f)
	_, _, err := cli(t, "", "keystore", "delete", "--fallback", "--yes", "--socket", noDaemon(t))
	if exitCodeOf(err) != 1 || err == nil || !strings.Contains(err.Error(), "-25293") {
		t.Fatalf("code=%d err=%v", exitCodeOf(err), err)
	}
}

func TestKeystoreDeleteNeedsYes(t *testing.T) {
	f := &fakeDeleter{}
	useFakeDeleter(t, f)
	out, errs, err := cli(t, "", "keystore", "delete", "--fallback", "--socket", noDaemon(t))
	if exitCodeOf(err) != 2 || out != "" || f.fallback+f.hardware != 0 {
		t.Fatalf("code=%d out=%q deletions=%d/%d", exitCodeOf(err), out, f.fallback, f.hardware)
	}
	if !strings.Contains(errs, "permanently unreadable") || !strings.Contains(errs, "--yes") {
		t.Errorf("stderr = %q", errs)
	}
}

func TestKeystoreDeleteNeedsExactlyOneKind(t *testing.T) {
	f := &fakeDeleter{}
	useFakeDeleter(t, f)
	for _, args := range [][]string{
		{"keystore", "delete", "--yes"},
		{"keystore", "delete", "--yes", "--fallback", "--hardware"},
	} {
		if _, _, err := cli(t, "", args...); err == nil || exitCodeOf(err) != 1 {
			t.Errorf("%v: err=%v", args, err)
		}
	}
	if f.fallback+f.hardware != 0 {
		t.Error("deleted without a clear target")
	}
}

func TestKeystoreDeleteRefusesWhileTheDaemonRuns(t *testing.T) {
	d := startTestDaemon(t, true)
	f := &fakeDeleter{}
	useFakeDeleter(t, f)

	_, errs, err := cli(t, "", "keystore", "delete", "--hardware", "--yes", "--socket", d.sock)
	if exitCodeOf(err) != 2 || f.hardware != 0 {
		t.Fatalf("code=%d deletions=%d err=%v", exitCodeOf(err), f.hardware, err)
	}
	if !strings.Contains(errs, "daemon is running") || !strings.Contains(errs, "--force") {
		t.Errorf("stderr = %q", errs)
	}
	// The default socket is found through GRANTD_SOCKET as well.
	if _, _, err := cli(t, "", "keystore", "delete", "--fallback", "--yes"); exitCodeOf(err) != 2 || f.fallback != 0 {
		t.Errorf("default socket: code=%d deletions=%d", exitCodeOf(err), f.fallback)
	}

	// --force goes ahead.
	if _, _, err := cli(t, "", "keystore", "delete", "--hardware", "--yes", "--force", "--socket", d.sock); err != nil || f.hardware != 1 {
		t.Fatalf("--force: err=%v deletions=%d", err, f.hardware)
	}
}

func TestKeystoreDeleteUnsupported(t *testing.T) {
	old := openKeyDeleter
	openKeyDeleter = func() (keystore.Deleter, error) { return nil, errKeystoreUnsupported }
	t.Cleanup(func() { openKeyDeleter = old })
	out, _, err := cli(t, "", "keystore", "delete", "--fallback", "--yes", "--socket", noDaemon(t))
	if err == nil || err.Error() != "unsupported" || exitCodeOf(err) != 1 || out != "" {
		t.Fatalf("err=%v code=%d out=%q", err, exitCodeOf(err), out)
	}
}

func TestKeystoreCommandIsRegistered(t *testing.T) {
	c, _, err := newRootCmd().Find([]string{"keystore", "delete"})
	if err != nil || c.Name() != "delete" {
		t.Fatalf("find: %v %v", c, err)
	}
	for _, f := range []string{"fallback", "hardware", "yes", "force", "socket"} {
		if c.Flags().Lookup(f) == nil {
			t.Errorf("no --%s", f)
		}
	}
}
