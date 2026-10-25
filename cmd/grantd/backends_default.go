//go:build !grantd_dev

package main

import (
	"fmt"
	"runtime"

	"grantd/internal/approve"
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

// openApprover selects the platform Approver for production builds. Until the
// real backend is wired in, the daemon refuses to start rather than run
// without a human in the loop.
func openApprover() (approve.Approver, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("macOS approver not yet implemented")
	}
	return nil, fmt.Errorf("no approver backend for %s yet", runtime.GOOS)
}
