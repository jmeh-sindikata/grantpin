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
)

// Label is the launchd label of the grantd agent.
const Label = "dev.grantd.daemon"

// ErrUnsupported is returned by New on platforms without a service backend.
var ErrUnsupported = errors.New("service: not supported on this platform")

// Options configure Install.
type Options struct {
	// Exe is the grantd binary to run. Empty means the current executable.
	// It is resolved through symlinks and must be absolute, executable and
	// not inside a temporary directory.
	Exe string
	// Socket, if set, is exported to the daemon as GRANTD_SOCKET. Must be
	// absolute.
	Socket string
	// LogDir receives daemon.out.log and daemon.err.log. Empty means the
	// platform default (~/Library/Logs/grantd on macOS).
	LogDir string
	// KeychainFallback adds --keychain-fallback to the daemon's arguments, so
	// the macOS keystore may use a Keychain-resident key when the Secure
	// Enclave is unavailable. It must match how the vault was created.
	KeychainFallback bool
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
	// KeychainFallback: the recorded daemon arguments include
	// --keychain-fallback.
	KeychainFallback bool
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
	return real, nil
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
