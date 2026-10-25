package mcp

import (
	"context"
	"errors"
	"io"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Serve runs the stdio MCP server, forwarding tool calls to the daemon at
// socketPath. Exposed tools (names fixed): secret_list, secret_exists,
// secret_masked, secret_run. There is deliberately no tool returning a value.
func Serve(ctx context.Context, socketPath string, in io.Reader, out io.Writer) error {
	return ErrNotImplemented
}
