package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WantedFile is the name of the marker that records "the user wants the
// background service". It lives in the grantpin data directory (next to
// vault.db and the socket), is empty and has mode 0600.
//
// Package managers may delete the launchd definition during an upgrade; the
// marker is not theirs to touch, so it survives and tells the CLI and the
// menu-bar app that the service should be restored. "service install" creates
// it after the job is installed and loaded; "service uninstall" removes it.
const WantedFile = "service.wanted"

func wantedPath(dataDir string) (string, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return "", fmt.Errorf("service: data directory %q must be absolute", dataDir)
	}
	return filepath.Join(dataDir, WantedFile), nil
}

// Wanted reports whether the marker exists in dataDir. Only a regular file
// counts: a symlink (which is never followed), a directory or a missing or
// unreadable path means "not wanted".
func Wanted(dataDir string) bool {
	p, err := wantedPath(dataDir)
	if err != nil {
		return false
	}
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// SetWanted creates (want) or removes (!want) the marker in dataDir. Both are
// idempotent.
//
// Creating makes dataDir (mode 0700) if it is missing and writes the empty
// marker with mode 0600 using O_EXCL, which never follows a symlink; an
// existing symlink or non-regular file at the marker path is an error and is
// left alone. An existing regular marker is kept (its mode is tightened to
// 0600). Removing deletes whatever file or symlink sits at the marker path
// (the symlink itself, never its target); a directory there is an error.
func SetWanted(dataDir string, want bool) error {
	p, err := wantedPath(dataDir)
	if err != nil {
		return err
	}
	if !want {
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("service: remove marker: %w", err)
		}
		if fi.IsDir() {
			return fmt.Errorf("service: remove marker: %s is a directory", p)
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("service: remove marker: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("service: create data directory: %w", err)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := f.Close(); err != nil {
			return fmt.Errorf("service: write marker: %w", err)
		}
		// The umask can only remove bits, but be explicit.
		return os.Chmod(p, 0o600)
	}
	if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("service: write marker: %w", err)
	}
	fi, lerr := os.Lstat(p)
	if lerr != nil {
		return fmt.Errorf("service: write marker: %w", lerr)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("service: refusing to use %s: it is not a regular file", p)
	}
	if fi.Mode().Perm() != 0o600 {
		if err := os.Chmod(p, 0o600); err != nil {
			return fmt.Errorf("service: write marker: %w", err)
		}
	}
	return nil
}
