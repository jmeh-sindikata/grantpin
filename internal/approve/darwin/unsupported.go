//go:build !(darwin && cgo)

package darwin

import (
	"errors"

	"github.com/jmeh-sindikata/grantd/internal/approve"
)

// ErrUnsupported is returned by New when the package is built without cgo or
// for a non-macOS target.
var ErrUnsupported = errors.New("darwin approver: requires macOS with cgo enabled")

// New always fails on this build configuration.
func New(opts ...Option) (approve.Approver, error) { return nil, ErrUnsupported }
