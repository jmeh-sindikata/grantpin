//go:build !grantd_dev

package dev

import (
	"errors"

	"github.com/jmeh-sindikata/grantd/internal/approve"
)

// Enabled reports whether the dev backend is compiled in. False in this build.
const Enabled = false

// ErrDisabled is returned by Open in builds without the grantd_dev tag.
var ErrDisabled = errors.New("dev approver is not compiled in (build with -tags grantd_dev; test-only, never asks a human)")

// Open always fails in normal builds. The concrete constructor New exists only
// under the grantd_dev tag, so any code calling it fails to compile without the
// tag; backend-selection code that must compile everywhere uses Open and gets
// ErrDisabled at runtime.
func Open() (approve.Approver, error) { return nil, ErrDisabled }
