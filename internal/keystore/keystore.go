package keystore

import (
	"context"
	"errors"

	"github.com/jmeh-sindikata/grantd/internal/presence"
)

// KeyStore wraps and unwraps the vault data key using OS-protected storage.
//
// The data key must never be written to disk, an env var, or a config file in
// plaintext; only the wrapped form returned by Wrap may be persisted.
//
// Platform backends: darwin (Keychain + Secure Enclave, TierHardware) now;
// windows (DPAPI/CNG, TierHardware) and linux (Secret Service, TierDialog)
// slot in later as sibling subpackages without touching core.
type KeyStore interface {
	// Wrap protects dataKey and returns an opaque blob suitable for storing in
	// the vault file.
	Wrap(ctx context.Context, dataKey []byte) ([]byte, error)
	// Unwrap recovers the data key from a blob produced by Wrap. It may block
	// on human presence according to Tier.
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
	// Tier reports what Unwrap requires of the human.
	Tier() presence.PresenceTier
}

// Transient is implemented by keystore errors that mean "the key material is
// temporarily out of reach, retry later" rather than "this vault can never be
// opened with this keystore". The typical case is a locked session, where the
// OS refuses to use the protected key until the user unlocks.
type Transient interface {
	Transient() bool
}

// IsTransient reports whether err (or any error it wraps) is a transient
// keystore failure that a later attempt may overcome without any change of
// configuration. Callers keep running and retry; every other keystore error
// (wrong mode, malformed blob, downgraded tier, missing key) is permanent.
func IsTransient(err error) bool {
	var t Transient
	return errors.As(err, &t) && t.Transient()
}

// ErrNoKeyMaterial is returned by Deleter methods when the key material they
// were asked to delete does not exist.
var ErrNoKeyMaterial = errors.New("keystore: no such key material")

// Deleter is implemented by key stores that can destroy the key material that
// protects a vault. After either call succeeds the vault that used that
// material can never be opened again: this exists for uninstalling, behind an
// explicit confirmation (`grantd keystore delete`). Each method returns
// ErrNoKeyMaterial, and changes nothing, when there was nothing to delete.
type Deleter interface {
	// DeleteFallbackKEK removes the Keychain item that holds the key-encryption
	// key of a vault protected without the Secure Enclave.
	DeleteFallbackKEK(ctx context.Context) error
	// DeleteSecureEnclaveKey removes the hardware-bound key (its reference item;
	// the private key itself never left the chip).
	DeleteSecureEnclaveKey(ctx context.Context) error
}
