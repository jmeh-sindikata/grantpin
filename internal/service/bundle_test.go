package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bundleInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>%s</string>
	<key>LSUIElement</key>
	<true/>
</dict>
</plist>
`

// makeBundle builds <root>/<name>.app with an executable inner binary and, if
// execName is non-empty, an Info.plist naming it. It returns the .app path and
// the symlink-free inner binary path.
func makeBundle(t *testing.T, root, name, binName, execName string) (app, inner string) {
	t.Helper()
	app = filepath.Join(root, name)
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	inner = filepath.Join(macos, binName)
	if err := os.WriteFile(inner, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if execName != "" {
		plist := strings.Replace(bundleInfoPlist, "%s", execName, 1)
		if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	realApp, _ := filepath.EvalSymlinks(app)
	return realApp, filepath.Join(realApp, "Contents", "MacOS", binName)
}

func TestResolveExeBundle(t *testing.T) {
	root := t.TempDir()

	app, inner := makeBundle(t, root, "grantpin.app", "grantpin", "grantpin")
	if got, err := resolveExe(app); err != nil || got != inner {
		t.Errorf("resolveExe(app) = %q, %v; want %q", got, err, inner)
	}
	// the inner binary path itself is unchanged
	if got, err := resolveExe(inner); err != nil || got != inner {
		t.Errorf("resolveExe(inner) = %q, %v; want %q", got, err, inner)
	}

	// no Info.plist: default name "grantpin"
	app2, inner2 := makeBundle(t, root, "bare.app", "grantpin", "")
	if got, err := resolveExe(app2); err != nil || got != inner2 {
		t.Errorf("no Info.plist: %q, %v; want %q", got, err, inner2)
	}

	// CFBundleExecutable names another binary
	app3, inner3 := makeBundle(t, root, "other.app", "daemon-x", "daemon-x")
	if got, err := resolveExe(app3); err != nil || got != inner3 {
		t.Errorf("custom CFBundleExecutable: %q, %v; want %q", got, err, inner3)
	}

	// a symlink to the bundle (e.g. /Applications/grantpin.app -> dist/...) resolves
	link := filepath.Join(root, "link.app")
	if err := os.Symlink(app, link); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveExe(link); err != nil || got != inner {
		t.Errorf("symlinked bundle: %q, %v; want %q", got, err, inner)
	}
}

func TestResolveExeBundleErrors(t *testing.T) {
	root := t.TempDir()

	// bundle without its inner binary
	empty := filepath.Join(root, "empty.app")
	if err := os.MkdirAll(filepath.Join(empty, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExe(empty); err == nil || !strings.Contains(err.Error(), "no executable") {
		t.Errorf("empty bundle: %v", err)
	}

	// CFBundleExecutable must be a plain file name
	for _, bad := range []string{"../../../bin/sh", "sub/grantpin", ".."} {
		app, _ := makeBundle(t, root, "bad"+strings.NewReplacer("/", "_", ".", "_").Replace(bad)+".app", "grantpin", bad)
		if _, err := resolveExe(app); err == nil || !strings.Contains(err.Error(), "invalid CFBundleExecutable") {
			t.Errorf("CFBundleExecutable %q: %v", bad, err)
		}
	}

	// an inner binary that is a symlink out of the bundle is refused
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	app, inner := makeBundle(t, root, "escape.app", "grantpin", "grantpin")
	os.Remove(inner)
	if err := os.Symlink(outside, inner); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExe(app); err == nil || !strings.Contains(err.Error(), "outside the app bundle") {
		t.Errorf("escaping symlink: %v", err)
	}

	// a plain directory that is not a .app is still not an executable
	dir := filepath.Join(root, "plain")
	os.MkdirAll(dir, 0o755)
	l, _ := newTest(t, &fakeRunner{})
	if err := l.Install(context.Background(), Options{Exe: dir}); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Errorf("plain dir: %v", err)
	}
}

// Installing from a bundle writes the inner binary into ProgramArguments, from
// the .app path and from the inner path alike.
func TestInstallFromBundleGoldenPlist(t *testing.T) {
	for _, viaApp := range []bool{true, false} {
		f := &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}}}
		l, _ := newTest(t, f)
		app, inner := makeBundle(t, l.home, "grantpin.app", "grantpin", "grantpin")
		arg := inner
		if viaApp {
			arg = app
		}
		logs := filepath.Join(l.home, "logs")
		err := l.Install(context.Background(), Options{Exe: arg, Socket: "/run/g.sock", LogDir: logs, Path: "/opt/homebrew/bin:/usr/bin:/bin"})
		if err != nil {
			t.Fatalf("viaApp=%v: %v", viaApp, err)
		}
		got, err := os.ReadFile(l.plistPath())
		if err != nil {
			t.Fatal(err)
		}
		want := strings.NewReplacer("/opt/g &amp; co/grantpin", inner, "/logs/", logs+"/").Replace(wantPlist)
		if string(got) != want {
			t.Errorf("viaApp=%v: plist mismatch\n got: %s\nwant: %s", viaApp, got, want)
		}
		if exe, _ := plistExe(got); exe != inner || !strings.HasSuffix(exe, ".app/Contents/MacOS/grantpin") {
			t.Errorf("viaApp=%v: ProgramArguments[0] = %q", viaApp, exe)
		}
	}
}

func TestInstallBundleRefusesTempDir(t *testing.T) {
	f := &fakeRunner{}
	l, _ := newTest(t, f)
	app, _ := makeBundle(t, l.home, "grantpin.app", "grantpin", "grantpin")
	realHome, _ := filepath.EvalSymlinks(l.home)
	l.tempRoots = []string{realHome}
	err := l.Install(context.Background(), Options{Exe: app})
	if err == nil || !strings.Contains(err.Error(), "temporary directory") {
		t.Fatalf("bundle under a temp root: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("launchctl called: %q", f.calls)
	}
}

// makeAppWithHelper builds the menu-bar app layout under root:
//
//	<name>.app/Contents/MacOS/grantpin-app                       the UI
//	<name>.app/Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin
//
// and returns the outer .app, the helper .app and the helper's binary, all
// symlink-free.
func makeAppWithHelper(t *testing.T, root, name string) (app, helper, daemon string) {
	t.Helper()
	app, _ = makeBundle(t, root, name, "grantpin-app", "grantpin-app")
	helperDir := filepath.Join(app, "Contents", "Helpers", "grantpin-daemon.app")
	if err := os.MkdirAll(filepath.Join(helperDir, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	daemon = filepath.Join(helperDir, "Contents", "MacOS", "grantpin")
	if err := os.WriteFile(daemon, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := strings.Replace(bundleInfoPlist, "%s", "grantpin", 1)
	if err := os.WriteFile(filepath.Join(helperDir, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	return app, helperDir, daemon
}

func TestResolveExeAppWithHelper(t *testing.T) {
	root := t.TempDir()
	app, helper, daemon := makeAppWithHelper(t, root, "grantpin.app")

	// the outer .app resolves to the helper's Go binary, not the UI
	if got, err := resolveExe(app); err != nil || got != daemon {
		t.Errorf("resolveExe(outer app) = %q, %v; want %q", got, err, daemon)
	}
	// the helper .app directly
	if got, err := resolveExe(helper); err != nil || got != daemon {
		t.Errorf("resolveExe(helper app) = %q, %v; want %q", got, err, daemon)
	}
	// the inner path itself is unchanged
	if got, err := resolveExe(daemon); err != nil || got != daemon {
		t.Errorf("resolveExe(inner) = %q, %v; want %q", got, err, daemon)
	}
	// a symlink to the outer app resolves the same way
	link := filepath.Join(root, "link.app")
	if err := os.Symlink(app, link); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveExe(link); err != nil || got != daemon {
		t.Errorf("symlinked outer app: %q, %v; want %q", got, err, daemon)
	}
	// the legacy single-bundle layout still resolves to Contents/MacOS/grantpin
	legacy, legacyInner := makeBundle(t, root, "legacy.app", "grantpin", "grantpin")
	if got, err := resolveExe(legacy); err != nil || got != legacyInner {
		t.Errorf("legacy bundle: %q, %v; want %q", got, err, legacyInner)
	}
}

func TestResolveExeAppNeverUI(t *testing.T) {
	root := t.TempDir()
	app, _, daemon := makeAppWithHelper(t, root, "grantpin.app")
	ui := filepath.Join(app, "Contents", "MacOS", "grantpin-app")

	// the UI executable itself is refused, with a pointer to the right path
	if _, err := resolveExe(ui); err == nil || !strings.Contains(err.Error(), "menu-bar app") || !strings.Contains(err.Error(), daemon) {
		t.Errorf("UI executable path: %v", err)
	}
	// an outer app whose helper is missing is refused, not run as the daemon
	bare, _ := makeBundle(t, root, "bare.app", "grantpin-app", "grantpin-app")
	if _, err := resolveExe(bare); err == nil || !strings.Contains(err.Error(), "refusing to run the UI") {
		t.Errorf("outer app without helper: %v", err)
	}
	// a helper whose Info.plist names the UI executable is refused
	app2, helper2, _ := makeAppWithHelper(t, root, "other.app")
	if err := os.WriteFile(filepath.Join(helper2, "Contents", "MacOS", "grantpin-app"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper2, "Contents", "Info.plist"), []byte(strings.Replace(bundleInfoPlist, "%s", "grantpin-app", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExe(app2); err == nil || !strings.Contains(err.Error(), "UI executable") {
		t.Errorf("helper naming the UI: %v", err)
	}
}

func TestResolveExeAppHelperErrors(t *testing.T) {
	root := t.TempDir()

	// a helper whose CFBundleExecutable escapes the bundle
	for _, bad := range []string{"../../../../../bin/sh", "sub/grantpin", ".."} {
		app, helper, _ := makeAppWithHelper(t, root, "bad"+strings.NewReplacer("/", "_", ".", "_").Replace(bad)+".app")
		if err := os.WriteFile(filepath.Join(helper, "Contents", "Info.plist"), []byte(strings.Replace(bundleInfoPlist, "%s", bad, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveExe(app); err == nil || !strings.Contains(err.Error(), "invalid CFBundleExecutable") {
			t.Errorf("helper CFBundleExecutable %q: %v", bad, err)
		}
	}

	// a helper bundle that is a symlink out of the app is refused
	outsideApp, _, _ := makeAppWithHelper(t, root, "outside-helper.app")
	app, helper, _ := makeAppWithHelper(t, root, "escape.app")
	if err := os.RemoveAll(helper); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outsideApp, "Contents", "Helpers", "grantpin-daemon.app"), helper); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExe(app); err == nil || !strings.Contains(err.Error(), "outside the app bundle") {
		t.Errorf("helper symlinked out of the bundle: %v", err)
	}

	// a helper bundle without its binary
	app3, helper3, daemon3 := makeAppWithHelper(t, root, "nobinary.app")
	_ = helper3
	if err := os.Remove(daemon3); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExe(app3); err == nil || !strings.Contains(err.Error(), "no executable") {
		t.Errorf("helper without binary: %v", err)
	}
}

// The golden plist for an install from the outer menu-bar app names the
// helper's Go binary, from the outer .app, the helper .app and the inner path.
func TestInstallFromAppWithHelperGoldenPlist(t *testing.T) {
	for _, via := range []string{"outer", "helper", "inner"} {
		f := &fakeRunner{results: map[string][]Result{"print": {{ExitCode: 113}}}}
		l, _ := newTest(t, f)
		app, helper, daemon := makeAppWithHelper(t, l.home, "grantpin.app")
		arg := map[string]string{"outer": app, "helper": helper, "inner": daemon}[via]
		logs := filepath.Join(l.home, "logs")
		if err := l.Install(context.Background(), Options{Exe: arg, Socket: "/run/g.sock", LogDir: logs, Path: "/opt/homebrew/bin:/usr/bin:/bin"}); err != nil {
			t.Fatalf("%s: %v", via, err)
		}
		got, err := os.ReadFile(l.plistPath())
		if err != nil {
			t.Fatal(err)
		}
		want := strings.NewReplacer("/opt/g &amp; co/grantpin", daemon, "/logs/", logs+"/").Replace(wantPlist)
		if string(got) != want {
			t.Errorf("%s: plist mismatch\n got: %s\nwant: %s", via, got, want)
		}
		if exe, _ := plistExe(got); exe != daemon || !strings.HasSuffix(exe, "/Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin") {
			t.Errorf("%s: ProgramArguments[0] = %q", via, exe)
		}
	}
}

func TestInstallAppWithHelperRefusesTempDir(t *testing.T) {
	f := &fakeRunner{}
	l, _ := newTest(t, f)
	app, _, _ := makeAppWithHelper(t, l.home, "grantpin.app")
	realHome, _ := filepath.EvalSymlinks(l.home)
	l.tempRoots = []string{realHome}
	err := l.Install(context.Background(), Options{Exe: app})
	if err == nil || !strings.Contains(err.Error(), "temporary directory") {
		t.Fatalf("app with helper under a temp root: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("launchctl called: %q", f.calls)
	}
}

// Installing the UI executable by path never reaches launchctl.
func TestInstallRefusesUIExecutable(t *testing.T) {
	f := &fakeRunner{}
	l, _ := newTest(t, f)
	app, _, _ := makeAppWithHelper(t, l.home, "grantpin.app")
	err := l.Install(context.Background(), Options{Exe: filepath.Join(app, "Contents", "MacOS", "grantpin-app")})
	if err == nil || !strings.Contains(err.Error(), "menu-bar app") {
		t.Fatalf("UI executable: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("launchctl called: %q", f.calls)
	}
}
