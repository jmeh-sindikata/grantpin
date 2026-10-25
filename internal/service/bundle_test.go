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

	app, inner := makeBundle(t, root, "grantd.app", "grantd", "grantd")
	if got, err := resolveExe(app); err != nil || got != inner {
		t.Errorf("resolveExe(app) = %q, %v; want %q", got, err, inner)
	}
	// the inner binary path itself is unchanged
	if got, err := resolveExe(inner); err != nil || got != inner {
		t.Errorf("resolveExe(inner) = %q, %v; want %q", got, err, inner)
	}

	// no Info.plist: default name "grantd"
	app2, inner2 := makeBundle(t, root, "bare.app", "grantd", "")
	if got, err := resolveExe(app2); err != nil || got != inner2 {
		t.Errorf("no Info.plist: %q, %v; want %q", got, err, inner2)
	}

	// CFBundleExecutable names another binary
	app3, inner3 := makeBundle(t, root, "other.app", "daemon-x", "daemon-x")
	if got, err := resolveExe(app3); err != nil || got != inner3 {
		t.Errorf("custom CFBundleExecutable: %q, %v; want %q", got, err, inner3)
	}

	// a symlink to the bundle (e.g. /Applications/grantd.app -> dist/...) resolves
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
	for _, bad := range []string{"../../../bin/sh", "sub/grantd", ".."} {
		app, _ := makeBundle(t, root, "bad"+strings.NewReplacer("/", "_", ".", "_").Replace(bad)+".app", "grantd", bad)
		if _, err := resolveExe(app); err == nil || !strings.Contains(err.Error(), "invalid CFBundleExecutable") {
			t.Errorf("CFBundleExecutable %q: %v", bad, err)
		}
	}

	// an inner binary that is a symlink out of the bundle is refused
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	app, inner := makeBundle(t, root, "escape.app", "grantd", "grantd")
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
		app, inner := makeBundle(t, l.home, "grantd.app", "grantd", "grantd")
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
		want := strings.NewReplacer("/opt/g &amp; co/grantd", inner, "/logs/", logs+"/").Replace(wantPlist)
		if string(got) != want {
			t.Errorf("viaApp=%v: plist mismatch\n got: %s\nwant: %s", viaApp, got, want)
		}
		if exe, _ := plistExe(got); exe != inner || !strings.HasSuffix(exe, ".app/Contents/MacOS/grantd") {
			t.Errorf("viaApp=%v: ProgramArguments[0] = %q", viaApp, exe)
		}
	}
}

func TestInstallBundleRefusesTempDir(t *testing.T) {
	f := &fakeRunner{}
	l, _ := newTest(t, f)
	app, _ := makeBundle(t, l.home, "grantd.app", "grantd", "grantd")
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
