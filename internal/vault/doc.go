// Package vault stores secrets in SQLite, encrypted with AES-256-GCM under a
// per-vault data key. The data key is wrapped by a keystore.KeyStore and is
// never persisted in plaintext.
package vault
