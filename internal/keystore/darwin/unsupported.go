//go:build !(darwin && cgo)

package darwin

import (
	"errors"

	"grantd/internal/keystore"
)

// ErrUnsupported is returned by New when the package is built without cgo or
// for a non-macOS target.
var ErrUnsupported = errors.New("darwin keystore: requires macOS with cgo enabled")

// New always fails on this build configuration.
func New(opts ...Option) (keystore.KeyStore, error) { return nil, ErrUnsupported }
