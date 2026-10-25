//go:build grantd_dev

package main

import (
	"os"

	"grantd/internal/approve"
	devap "grantd/internal/approve/dev"
	"grantd/internal/keystore"
	devks "grantd/internal/keystore/dev"
)

// devApproveEnv, when set to "allow", makes the dev approver auto-allow
// (allow-once). Any other value, or unset, auto-denies.
const devApproveEnv = "GRANTD_DEV_APPROVE"

// openKeyStore returns the INSECURE TierNone dev keystore. It only exists in
// grantd_dev builds (tests); never ship such a binary.
func openKeyStore(backendConfig) (keystore.KeyStore, error) { return devks.Open() }

// openApprover returns the INSECURE TierNone dev approver: auto-deny unless
// GRANTD_DEV_APPROVE=allow. It only exists in grantd_dev builds.
func openApprover(backendConfig) (approve.Approver, error) {
	return devap.New(os.Getenv(devApproveEnv) == "allow"), nil
}
