//go:build !grantd_dev

package main

import (
	"fmt"
	"runtime"

	"grantd/internal/keystore"
)

// openKeyStore selects the platform KeyStore for production builds. The real
// backends land in later milestone steps (§11 step 7 for macOS).
func openKeyStore() (keystore.KeyStore, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("macOS keystore not yet implemented")
	}
	return nil, fmt.Errorf("no keystore backend for %s yet", runtime.GOOS)
}
