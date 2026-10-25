//go:build !unix

package mcp

import (
	"context"
	"errors"
)

// ExecStarter is not supported on this platform; the shim reports that the
// daemon is not running instead.
func ExecStarter(string) Starter {
	return func(context.Context) error {
		return errors.New("auto-start is not supported on this platform")
	}
}
