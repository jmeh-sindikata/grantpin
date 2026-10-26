//go:build grantpin_dev

package main

import (
	"os"

	"github.com/jmeh-sindikata/grantpin/internal/approve"
	devap "github.com/jmeh-sindikata/grantpin/internal/approve/dev"
	"github.com/jmeh-sindikata/grantpin/internal/keystore"
	devks "github.com/jmeh-sindikata/grantpin/internal/keystore/dev"
)

// devApproveEnv, when set to "allow", makes the dev approver auto-allow
// (allow-once). "allow-no-standing" does the same but denies standing-grant
// requests (`grants add`) specifically. Any other value, or unset, auto-denies.
const devApproveEnv = "GRANTPIN_DEV_APPROVE"

// openKeyStore returns the INSECURE TierNone dev keystore. It only exists in
// grantpin_dev builds (tests); never ship such a binary.
func openKeyStore(backendConfig) (keystore.KeyStore, error) { return devks.Open() }

// openApprover returns the INSECURE TierNone dev approver: auto-deny unless
// GRANTPIN_DEV_APPROVE=allow[-no-standing]. It only exists in grantpin_dev builds.
func openApprover() (approve.Approver, error) {
	mode := os.Getenv(devApproveEnv)
	a := devap.New(mode == "allow" || mode == "allow-no-standing")
	a.DenyStanding = mode == "allow-no-standing"
	return a, nil
}
