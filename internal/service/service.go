// Package service installs, removes and inspects the per-user background
// service that runs "grantd daemon". Only macOS (launchd) is implemented; on
// other platforms New returns ErrUnsupported.
//
// The service always runs as the logged-in user (a LaunchAgent in the gui
// domain), never as root, and its definition never contains secret material.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Label is the launchd label of the grantd agent.
const Label = "dev.grantd.daemon"

// ErrUnsupported is returned by New on platforms without a service backend.
var ErrUnsupported = errors.New("service: not supported on this platform")

// Options configure Install.
type Options struct {
	// Exe is the grantd binary to run. Empty means the current executable.
	// It is resolved through symlinks and must be absolute, executable and
	// not inside a temporary directory. It may also name a macOS app bundle
	// (a directory ending in ".app"); the service then runs the bundle's
	// daemon binary, which is what the bundle's signature and provisioning
	// profile apply to: for the menu-bar app that is
	// Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd (never the
	// app's own UI executable), for a plain bundle Contents/MacOS/<CFBundleExecutable>.
	Exe string
	// Socket, if set, is exported to the daemon as GRANTD_SOCKET. Must be
	// absolute.
	Socket string
	// LogDir receives daemon.out.log and daemon.err.log. Empty means the
	// platform default (~/Library/Logs/grantd on macOS).
	LogDir string
	// Path is the PATH recorded in the service definition. Empty means the
	// PATH of the process running Install. Only absolute entries are kept.
	// PATH is the only variable besides GRANTD_SOCKET the service defines.
	Path string
	// ReadyTimeout bounds how long Install waits for the daemon socket to
	// accept connections after launchd started it. Zero means
	// DefaultReadyTimeout.
	ReadyTimeout time.Duration
}

// DefaultReadyTimeout is how long Install waits for the daemon socket.
const DefaultReadyTimeout = 10 * time.Second

// readyPollInterval is how often Install retries the socket.
const readyPollInterval = 100 * time.Millisecond

// ErrNotReady is returned (wrapped) by Install when the service was
// installed and started but the daemon socket did not become connectable
// within the ReadyTimeout. The launchd part succeeded; callers should warn,
// not fail.
var ErrNotReady = errors.New("service installed, but the daemon did not become ready")

// ReadyFunc reports nil once the daemon on socket accepts connections.
type ReadyFunc func(ctx context.Context, socket string) error

// sanitizePath keeps the absolute, non-empty entries of a PATH value, in
// order and without duplicates. It returns "" if nothing is left or the value
// contains control characters (which a plist cannot carry).
func sanitizePath(p string) string {
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	var keep []string
	seen := map[string]bool{}
	for _, e := range filepath.SplitList(p) {
		if e == "" || !filepath.IsAbs(e) || seen[e] {
			continue
		}
		seen[e] = true
		keep = append(keep, e)
	}
	return strings.Join(keep, string(filepath.ListSeparator))
}

// Status describes the installed service.
type Status struct {
	Label      string
	PlistPath  string
	Installed  bool   // the service definition file exists
	Loaded     bool   // the service manager knows the job
	Running    bool   // a process is currently running
	PID        int    // valid when Running
	State      string // raw manager state, e.g. "running", "not running"
	ExePath    string // program recorded in the definition, if installed
	ExeMissing bool   // ExePath no longer exists on disk
}

// Manager manages the background service.
type Manager interface {
	// Install writes the service definition and (re)starts the service. It is
	// idempotent: running it again picks up a new binary path.
	Install(ctx context.Context, opts Options) error
	// Uninstall stops the service and removes its definition. Not being
	// installed is not an error.
	Uninstall(ctx context.Context) error
	// Status reports the current state. A missing service is not an error.
	Status(ctx context.Context) (Status, error)
}

// resolveExe returns the absolute, symlink-free path of the binary to run.
func resolveExe(exe string) (string, error) {
	if exe == "" {
		p, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("service: locate current executable: %w", err)
		}
		exe = p
	}
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("service: executable path %q must be absolute", exe)
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("service: resolve executable %q: %w", exe, err)
	}
	if fi, err := os.Stat(real); err == nil && fi.IsDir() && strings.HasSuffix(real, ".app") {
		return bundleExe(real)
	}
	if err := refuseUIExecutable(real); err != nil {
		return "", err
	}
	return real, nil
}

// helperBundle is the nested bundle inside the menu-bar app that holds the Go
// daemon binary (Contents/Helpers/grantd-daemon.app). uiExecutable is the
// outer app's own main executable, the SwiftUI app, which must never be what
// the service runs.
const (
	helperBundle = "grantd-daemon.app"
	uiExecutable = "grantd-app"
)

// bundleExe returns the daemon binary of the app bundle at dir.
//
// For the menu-bar app layout, where dir contains
// Contents/Helpers/grantd-daemon.app, that is the helper's
// Contents/MacOS/<CFBundleExecutable>: the outer bundle's own executable is the
// UI and is never returned. For a plain bundle (the helper bundle itself, or
// the older single-bundle layout) it is dir's Contents/MacOS/<CFBundleExecutable>.
func bundleExe(dir string) (string, error) {
	helper := filepath.Join(dir, "Contents", "Helpers", helperBundle)
	if fi, err := os.Stat(helper); err == nil && fi.IsDir() {
		real, err := filepath.EvalSymlinks(helper)
		if err != nil {
			return "", fmt.Errorf("service: resolve helper bundle %s: %w", helper, err)
		}
		if !within(real, dir) {
			return "", fmt.Errorf("service: helper bundle %s resolves outside the app bundle %s", helper, dir)
		}
		exe, name, err := plainBundleExe(real)
		if err != nil {
			return "", err
		}
		if name == uiExecutable {
			return "", fmt.Errorf("service: helper bundle %s names the UI executable %q", real, name)
		}
		return exe, nil
	}
	exe, name, err := plainBundleExe(dir)
	if err != nil {
		return "", err
	}
	if name == uiExecutable {
		return "", fmt.Errorf("service: %s is the grantd menu-bar app and has no %s inside; refusing to run the UI as the daemon", dir, helperBundle)
	}
	return exe, nil
}

// plainBundleExe returns the inner binary of the app bundle at dir,
// Contents/MacOS/<CFBundleExecutable> (default "grantd"), and that name. The
// name must be a plain file name so a crafted Info.plist cannot point outside
// the bundle.
func plainBundleExe(dir string) (exe, name string, err error) {
	name = "grantd"
	if data, err := os.ReadFile(filepath.Join(dir, "Contents", "Info.plist")); err == nil {
		if m, perr := parsePlist(data); perr == nil {
			if n, _ := m["CFBundleExecutable"].(string); n != "" {
				name = n
			}
		}
	}
	if name != filepath.Base(name) || name == "." || name == ".." {
		return "", "", fmt.Errorf("service: %s: invalid CFBundleExecutable %q", dir, name)
	}
	inner := filepath.Join(dir, "Contents", "MacOS", name)
	real, err := filepath.EvalSymlinks(inner)
	if err != nil {
		return "", "", fmt.Errorf("service: app bundle %s has no executable at %s: %w", dir, inner, err)
	}
	if !within(real, dir) {
		return "", "", fmt.Errorf("service: %s resolves outside the app bundle %s", inner, dir)
	}
	return real, name, nil
}

// refuseUIExecutable rejects a path that is the menu-bar app's own main
// executable (<x>.app/Contents/MacOS/grantd-app), which would otherwise be
// accepted as "an executable file" and installed as the daemon.
func refuseUIExecutable(real string) error {
	if filepath.Base(real) != uiExecutable {
		return nil
	}
	macos := filepath.Dir(real)
	contents := filepath.Dir(macos)
	app := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(app, ".app") {
		return nil
	}
	return fmt.Errorf("service: %s is the grantd menu-bar app, not the daemon; use %s or the app bundle itself",
		real, filepath.Join(app, "Contents", "Helpers", helperBundle, "Contents", "MacOS", "grantd"))
}

// checkExe refuses binaries that are unsuitable for a long-lived service: not
// a regular executable file, or located under one of tempRoots (which may be
// cleaned up, or writable by anything, so a service pointing there is
// fragile and a hijack risk).
func checkExe(exe string, tempRoots []string) error {
	fi, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("service: stat executable: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("service: %s is not an executable file", exe)
	}
	for _, root := range tempRoots {
		if root != "" && within(exe, root) {
			return fmt.Errorf("service: refusing to install %s: it is under temporary directory %s; install grantd to a permanent location (or pass --exe)", exe, root)
		}
	}
	return nil
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// defaultTempRoots lists directories whose contents are considered temporary.
func defaultTempRoots() []string {
	roots := []string{os.TempDir(), "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders"}
	out := make([]string, 0, len(roots)*2)
	for _, r := range roots {
		out = append(out, filepath.Clean(r))
		if real, err := filepath.EvalSymlinks(r); err == nil {
			out = append(out, real)
		}
	}
	return out
}
