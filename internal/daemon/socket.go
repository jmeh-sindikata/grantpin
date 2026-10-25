package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// SocketEnv overrides the socket path (used by tests and unusual setups).
const SocketEnv = "GRANTD_SOCKET"

// socketName is the file name of the daemon socket.
const socketName = "grantd.sock"

// DefaultSocketPath returns where the daemon listens and the CLI connects:
//
//  1. $GRANTD_SOCKET, if set;
//  2. $XDG_RUNTIME_DIR/grantd.sock, if XDG_RUNTIME_DIR is set;
//  3. macOS: ~/Library/Application Support/grantd/grantd.sock;
//  4. otherwise $XDG_DATA_HOME/grantd/grantd.sock (default
//     ~/.local/share/grantd/grantd.sock).
func DefaultSocketPath() (string, error) {
	if p := os.Getenv(SocketEnv); p != "" {
		return p, nil
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, socketName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("daemon: locate socket: %w", err)
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "grantd", socketName), nil
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(data, "grantd", socketName), nil
}

// maxSocketPath is the longest usable sun_path (excluding the NUL).
func maxSocketPath() int {
	if runtime.GOOS == "linux" {
		return 107
	}
	return 103 // darwin and BSDs: sun_path is 104 bytes
}

// ErrAlreadyRunning is returned when another daemon answers on the socket.
var ErrAlreadyRunning = errors.New("daemon: another daemon is already listening on the socket")

// listenUnix creates the parent directory (0700 if we create it), removes a
// stale socket (only if it is a socket and nothing answers on it), and listens
// with the socket file restricted to 0600. warn is called for non-fatal
// observations such as a pre-existing loose parent directory.
func listenUnix(path string, warn func(msg string, args ...any)) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("daemon: empty socket path")
	}
	if len(path) > maxSocketPath() {
		return nil, fmt.Errorf("daemon: socket path %q is %d bytes, over the %d-byte unix socket limit", path, len(path), maxSocketPath())
	}
	dir := filepath.Dir(path)
	if fi, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("daemon: create socket dir: %w", err)
		}
		// MkdirAll is subject to umask and only creates; make sure of the leaf.
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("daemon: chmod socket dir: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("daemon: stat socket dir: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("daemon: socket dir %q is not a directory", dir)
	} else if fi.Mode().Perm()&0o077 != 0 {
		// Not ours to chmod (could be /tmp via GRANTD_SOCKET). The 0600 socket
		// plus the peer-UID check still apply.
		warn("socket directory is accessible by group/other", "dir", dir, "mode", fi.Mode().Perm().String())
	}

	if err := removeStale(path); err != nil {
		return nil, err
	}

	restore := restrictiveUmask()
	ln, err := net.Listen("unix", path)
	restore()
	if err != nil {
		return nil, fmt.Errorf("daemon: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("daemon: chmod socket: %w", err)
	}
	return ln, nil
}

// removeStale deletes path if it is a unix socket that refuses connections.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("daemon: stat socket: %w", err)
	}
	if fi.Mode().Type()&os.ModeSocket == 0 {
		return fmt.Errorf("daemon: %q exists and is not a socket; refusing to remove it", path)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = c.Close()
		return ErrAlreadyRunning
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
		// Timeout or anything else: we cannot prove it is dead.
		return fmt.Errorf("daemon: socket %q exists and could not be probed: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("daemon: remove stale socket: %w", err)
	}
	return nil
}
