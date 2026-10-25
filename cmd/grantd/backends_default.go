//go:build !grantd_dev && !(darwin && cgo)

package main

import (
	"fmt"
	"runtime"

	"grantd/internal/approve"
	"grantd/internal/keystore"
)

// openKeyStore has no production backend on this platform/build: macOS needs
// cgo (see backends_darwin.go); Linux and Windows land in later milestones.
func openKeyStore(backendConfig) (keystore.KeyStore, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("the macOS keystore needs a cgo build (CGO_ENABLED=1)")
	}
	return nil, fmt.Errorf("no keystore backend for %s yet", runtime.GOOS)
}

// openApprover has no production backend on this platform/build. The daemon
// refuses to start rather than run without a human in the loop.
func openApprover(backendConfig) (approve.Approver, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("the macOS approver needs a cgo build (CGO_ENABLED=1)")
	}
	return nil, fmt.Errorf("no approver backend for %s yet", runtime.GOOS)
}
