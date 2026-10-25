//go:build grantd_dev

package main

import (
	"grantd/internal/keystore"
	devks "grantd/internal/keystore/dev"
)

// openKeyStore returns the INSECURE TierNone dev keystore. It only exists in
// grantd_dev builds (tests); never ship such a binary.
func openKeyStore() (keystore.KeyStore, error) { return devks.Open() }
