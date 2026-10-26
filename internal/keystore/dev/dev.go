//go:build grantpin_dev

package dev

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/jmeh-sindikata/grantpin/internal/keystore"
	"github.com/jmeh-sindikata/grantpin/internal/presence"
)

// Enabled reports whether the dev backend is compiled in. True in this build.
const Enabled = true

// insecureKey is a CONSTANT, PUBLIC key. Anyone can unwrap anything wrapped by
// this store. It exists only so core logic is testable headless.
// DO NOT USE FOR REAL SECRETS.
var insecureKey = []byte("grantpin-dev-INSECURE-testonly-0") // 32 bytes -> AES-256

// Store is an INSECURE, TierNone keystore for tests. Wrapped blobs are
// AES-256-GCM(nonce || ciphertext) under a hard-coded key.
type Store struct {
	aead cipher.AEAD
}

var _ keystore.KeyStore = (*Store)(nil)

// New returns the insecure dev keystore. It exists only under the grantpin_dev
// build tag, so calling it from a normal build fails to compile.
func New() *Store {
	block, err := aes.NewCipher(insecureKey)
	if err != nil {
		panic(err) // key length is a constant; cannot happen
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &Store{aead: aead}
}

var _ keystore.Deleter = (*Store)(nil)

// DeleteFallbackKEK and DeleteSecureEnclaveKey: the dev keystore keeps its key
// in the source, so there is never any key material to delete and both report
// keystore.ErrNoKeyMaterial. They let the `grantpin keystore delete` plumbing be
// tested without touching a Keychain.
func (s *Store) DeleteFallbackKEK(context.Context) error { return keystore.ErrNoKeyMaterial }

// DeleteSecureEnclaveKey: see DeleteFallbackKEK.
func (s *Store) DeleteSecureEnclaveKey(context.Context) error { return keystore.ErrNoKeyMaterial }

// Open is the build-agnostic constructor for backend selection code; under
// grantpin_dev it returns the dev store.
func Open() (keystore.KeyStore, error) { return New(), nil }

// Wrap encrypts dataKey under the constant key.
func (s *Store) Wrap(ctx context.Context, dataKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("dev keystore: nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, dataKey, nil), nil
}

// Unwrap reverses Wrap.
func (s *Store) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(wrapped) < n+s.aead.Overhead() {
		return nil, errors.New("dev keystore: wrapped blob too short")
	}
	out, err := s.aead.Open(nil, wrapped[:n], wrapped[n:], nil)
	if err != nil {
		return nil, fmt.Errorf("dev keystore: unwrap: %w", err)
	}
	return out, nil
}

// Tier is always TierNone.
func (s *Store) Tier() presence.PresenceTier { return presence.TierNone }
