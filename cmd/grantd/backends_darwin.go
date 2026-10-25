//go:build !grantd_dev && darwin && cgo

package main

import (
	"fmt"

	"grantd/internal/approve"
	approvedarwin "grantd/internal/approve/darwin"
	"grantd/internal/keystore"
	keystoredarwin "grantd/internal/keystore/darwin"
)

// Constructors, replaceable in tests so they can check the wiring without
// touching the Keychain, the Secure Enclave or any prompt.
var (
	newDarwinKeyStore = keystoredarwin.New
	newDarwinApprover = approvedarwin.New
)

// openKeyStore returns the Secure Enclave keystore (TierHardware). With
// cfg.KeychainFallback it may fall back to a Keychain-resident KEK (TierDialog)
// when the Secure Enclave is unusable; by default it refuses to.
func openKeyStore(cfg backendConfig) (keystore.KeyStore, error) {
	ks, err := newDarwinKeyStore(keystoredarwin.WithAllowKeychainFallback(cfg.KeychainFallback))
	if err != nil {
		return nil, fmt.Errorf("macOS keystore: %w", err)
	}
	return ks, nil
}

// openApprover returns the LocalAuthentication approver (Touch ID with
// password fallback) with the Allow once / Allow for N / Deny chooser, which is
// on by default.
func openApprover(backendConfig) (approve.Approver, error) {
	ap, err := newDarwinApprover()
	if err != nil {
		return nil, fmt.Errorf("macOS approver: %w", err)
	}
	return ap, nil
}
