//go:build grantd_dev

package dev

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"grantd/internal/keystore"
	"grantd/internal/presence"
)

// Enabled reports whether the dev backend is compiled in. True in this build.
const Enabled = true

// insecureKey is a CONSTANT, PUBLIC key. Anyone can unwrap anything wrapped by
// this store. It exists only so core logic is testable headless.
// DO NOT USE FOR REAL SECRETS.
var insecureKey = []byte("grantd-dev-INSECURE-test-only-32") // 32 bytes -> AES-256

// Store is an INSECURE, TierNone keystore for tests. Wrapped blobs are
// AES-256-GCM(nonce || ciphertext) under a hard-coded key.
type Store struct {
	aead cipher.AEAD
}

var _ keystore.KeyStore = (*Store)(nil)

// New returns the insecure dev keystore. It exists only under the grantd_dev
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

// Open is the build-agnostic constructor for backend selection code; under
// grantd_dev it returns the dev store.
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
