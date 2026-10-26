//go:build !grantpin_dev

package dev

import (
	"errors"

	"github.com/jmeh-sindikata/grantpin/internal/keystore"
)

// Enabled reports whether the dev backend is compiled in. False in this build.
const Enabled = false

// ErrDisabled is returned by Open in builds without the grantpin_dev tag.
var ErrDisabled = errors.New("dev keystore is not compiled in (build with -tags grantpin_dev; test-only, insecure)")

// Open always fails in normal builds. The concrete constructor New exists only
// under the grantpin_dev tag, so any code calling it fails to compile without the
// tag; backend-selection code that must compile everywhere uses Open and gets
// ErrDisabled at runtime.
func Open() (keystore.KeyStore, error) { return nil, ErrDisabled }
