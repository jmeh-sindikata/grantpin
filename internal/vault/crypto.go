package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// seal encrypts plaintext with AES-256-GCM under key and a fresh random nonce.
// The secret name is the GCM additional data, so a ciphertext cannot be moved
// to a different name without failing authentication.
func seal(key []byte, name string, plaintext []byte) (ct, nonce []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, errors.New("vault: nonce generation failed")
	}
	return aead.Seal(nil, nonce, plaintext, []byte(name)), nonce, nil
}

// open reverses seal. Errors never include any plaintext.
func open(key []byte, name string, ct, nonce []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
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
