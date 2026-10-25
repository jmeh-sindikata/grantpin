// Package keystore defines the KeyStore seam: OS-protected wrapping of the
// vault data key.
//
// Platform implementations live in subpackages (darwin today; windows and linux
// slot in later without touching core). The dev subpackage is a TierNone test
// backend compiled only under the grantd_dev build tag.
package keystore
