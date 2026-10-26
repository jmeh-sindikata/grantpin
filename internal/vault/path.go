package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultPath returns where the vault lives, in order of precedence:
//
//  1. $GRANTPIN_HOME/vault.db (tests, relocation)
//  2. $XDG_DATA_HOME/grantpin/vault.db (if set and absolute)
//  3. macOS: ~/Library/Application Support/grantpin/vault.db
//  4. otherwise ~/.local/share/grantpin/vault.db
func DefaultPath() (string, error) {
	if h := os.Getenv("GRANTPIN_HOME"); h != "" {
		return filepath.Join(h, "vault.db"), nil
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "grantpin", "vault.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("vault: locate home directory: %w", err)
	}
	if home == "" {
		return "", errors.New("vault: empty home directory")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "grantpin", "vault.db"), nil
	}
	return filepath.Join(home, ".local", "share", "grantpin", "vault.db"), nil
}
