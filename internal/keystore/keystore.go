package keystore

import (
	"context"
	"errors"

	"grantd/internal/presence"
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
