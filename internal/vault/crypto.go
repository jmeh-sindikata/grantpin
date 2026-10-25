package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"grantd/internal/presence"
	"io"
)

// seal encrypts plaintext with AES-256-GCM under key and a fresh random nonce.
// The additional data is aad(name, tier), so a ciphertext cannot be moved to a
// different name, nor its min_tier column altered, without failing
// authentication.
func seal(key []byte, name string, tier presence.PresenceTier, plaintext []byte) (ct, nonce []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, errors.New("vault: nonce generation failed")
	}
	return aead.Seal(nil, nonce, plaintext, aad(name, tier)), nonce, nil
}

// open reverses seal. Errors never include any plaintext.
func open(key []byte, name string, tier presence.PresenceTier, ct, nonce []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ct, aad(name, tier))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// aadPrefix versions the additional-data encoding.
const aadPrefix = "grantd.secret.v1\x00"

// aad is the GCM additional data: "grantd.secret.v1\x00" || name || "\x00" ||
// byte(tier). Names cannot contain NUL, so the encoding is unambiguous. A tier
// outside 0..255 yields a marker that never authenticates.
func aad(name string, tier presence.PresenceTier) []byte {
	b := make([]byte, 0, len(aadPrefix)+len(name)+2)
	b = append(b, aadPrefix...)
	b = append(b, name...)
	b = append(b, 0)
	if tier < 0 || tier > 255 {
		return append(b, 0xff, 0xff)
	}
	return append(b, byte(tier))
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("vault: bad data key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("vault: cipher setup failed")
	}
	return aead, nil
}
