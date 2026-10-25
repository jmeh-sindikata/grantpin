package darwin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Mode identifies how a wrapped blob was protected.
type Mode byte

const (
	// ModeSecureEnclave: ECIES to a Secure Enclave P-256 key.
	ModeSecureEnclave Mode = 1
	// ModeKeychain: AES-256-GCM under a KEK held in a Keychain generic-password item.
	ModeKeychain Mode = 2
)

// FormatVersion is the current blob format version (second header byte).
const FormatVersion byte = 1

// Names reported by Store.Mode.
const (
	ModeNameSecureEnclave = "secure-enclave"
	ModeNameKeychain      = "keychain-fallback"
	ModeNameUnresolved    = "unresolved"
)

// Keychain identifiers. Exported so the manual-test doc and tooling agree.
const (
	// KeyTag is the application tag of the Secure Enclave key.
	KeyTag = "dev.grantd.vault-kek"
	// KeychainService / KeychainAccount identify the fallback KEK item.
	KeychainService = "dev.grantd"
	KeychainAccount = "vault-kek"
)

// String returns the canonical mode name.
func (m Mode) String() string {
	switch m {
	case ModeSecureEnclave:
		return ModeNameSecureEnclave
	case ModeKeychain:
		return ModeNameKeychain
	default:
		return fmt.Sprintf("mode(%d)", byte(m))
	}
}

// Errors.
var (
	// ErrSecureEnclaveUnavailable means the Secure Enclave could not be used
	// and the keychain fallback was not enabled (or also failed).
	ErrSecureEnclaveUnavailable = errors.New("darwin keystore: Secure Enclave unavailable (VM, no SE, or binary lacks keychain entitlements); pass WithAllowKeychainFallback(true) to accept the weaker Keychain fallback")
	// ErrModeMismatch means a wrapped blob was produced in a different mode
	// than the one this store can unwrap.
	ErrModeMismatch = errors.New("darwin keystore: wrapped blob mode does not match this store")
	// ErrBadBlob means the blob is malformed (too short, unknown version/mode).
	ErrBadBlob = errors.New("darwin keystore: malformed wrapped blob")
	// ErrKeyNotFound means no key to unwrap with exists in the Keychain/SE
	// (e.g. vault restored onto another machine). Unwrap never creates a key.
	ErrKeyNotFound = errors.New("darwin keystore: vault key not found on this machine")
	// ErrEmptyKey is returned when asked to wrap an empty data key.
	ErrEmptyKey = errors.New("darwin keystore: empty data key")
)

// encodeBlob prepends the 2-byte header to payload.
func encodeBlob(m Mode, payload []byte) []byte {
	out := make([]byte, 0, 2+len(payload))
	out = append(out, byte(m), FormatVersion)
	return append(out, payload...)
}

// decodeBlob parses the header and returns the mode and payload (aliasing b).
func decodeBlob(b []byte) (Mode, []byte, error) {
	if len(b) < 3 {
		return 0, nil, ErrBadBlob
	}
	m := Mode(b[0])
	if m != ModeSecureEnclave && m != ModeKeychain {
		return 0, nil, fmt.Errorf("%w: unknown mode %d", ErrBadBlob, b[0])
	}
	if b[1] != FormatVersion {
		return 0, nil, fmt.Errorf("%w: unsupported version %d", ErrBadBlob, b[1])
	}
	return m, b[2:], nil
}

// KEKSize is the fallback KEK length (AES-256).
const KEKSize = 32

// sealKEK encrypts plaintext under kek with AES-256-GCM. Output is
// nonce || ciphertext||tag. aad (the blob header) is authenticated.
func sealKEK(kek, plaintext, aad []byte) ([]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("darwin keystore: KEK must be %d bytes", KEKSize)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("darwin keystore: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// openKEK reverses sealKEK. The returned error never contains key material.
func openKEK(kek, sealed, aad []byte) ([]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("darwin keystore: KEK must be %d bytes", KEKSize)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(sealed) < n+gcm.Overhead() {
		return nil, ErrBadBlob
	}
	out, err := gcm.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, errors.New("darwin keystore: unwrap failed (wrong key or tampered blob)")
	}
	return out, nil
}

// zero overwrites b.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
