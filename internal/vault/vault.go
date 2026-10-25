package vault

import (
	"context"
	"errors"
	"time"

	"grantd/internal/keystore"
	"grantd/internal/presence"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Meta is a secret's non-sensitive metadata (§6).
type Meta struct {
	Name      string
	Tags      []string
	URL       string
	Notes     string
	ExpiresAt *time.Time
	MinTier   presence.PresenceTier
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Vault is the encrypted secret store.
type Vault struct{}

// Init creates a new vault file at path, generating a data key and wrapping it
// with ks.
func Init(ctx context.Context, path string, ks keystore.KeyStore) (*Vault, error) {
	return nil, ErrNotImplemented
}

// Open opens an existing vault, unwrapping the data key via ks.
func Open(ctx context.Context, path string, ks keystore.KeyStore) (*Vault, error) {
	return nil, ErrNotImplemented
}

// Close releases the database and zeroes the data key.
func (v *Vault) Close() error { return ErrNotImplemented }

// Set stores or replaces a secret value and its metadata.
func (v *Vault) Set(ctx context.Context, m Meta, value []byte, overwrite bool) error {
	return ErrNotImplemented
}

// List returns metadata only; never values.
func (v *Vault) List(ctx context.Context) ([]Meta, error) { return nil, ErrNotImplemented }

// Exists reports whether name is stored.
func (v *Vault) Exists(ctx context.Context, name string) (bool, error) {
	return false, ErrNotImplemented
}

// Masked returns the masked form of the value (last 4 chars; fully masked if
// shorter than 12).
func (v *Vault) Masked(ctx context.Context, name string) (string, error) {
	return "", ErrNotImplemented
}

// Delete removes a secret.
func (v *Vault) Delete(ctx context.Context, name string) error { return ErrNotImplemented }

// Resolve decrypts the named secrets for injection by the runner. It is
// INTERNAL: its result must only flow to runner and (for OpShow) the
// presence-gated show path, never into a Response, log or error message.
func (v *Vault) Resolve(ctx context.Context, names []string) (map[string][]byte, error) {
	return nil, ErrNotImplemented
}

// DataKey returns a copy of the unwrapped data key for deriving the audit HMAC
// key. INTERNAL.
func (v *Vault) DataKey() ([]byte, error) { return nil, ErrNotImplemented }
