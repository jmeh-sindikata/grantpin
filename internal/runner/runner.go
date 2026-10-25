package runner

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Spec describes one command execution.
type Spec struct {
	Argv    []string
	Cwd     string
	Env     map[string]string // injected env var name -> value (SECRET)
	Timeout time.Duration     // 0 = none
}

// Result is the outcome of a finished command.
type Result struct {
	ExitCode int
	TimedOut bool
	Duration time.Duration
}

// Run executes spec with a clean copy of the parent env plus spec.Env. Output
// is written to stdout/stderr with every injected value replaced by
// [REDACTED:NAME]. Signals/ctx cancellation are forwarded to the child.
func Run(ctx context.Context, spec Spec, stdout, stderr io.Writer) (Result, error) {
	return Result{}, ErrNotImplemented
}

// NewRedactingWriter wraps w, replacing exact matches of any value in secrets
// (name -> value) with [REDACTED:NAME], correctly across Write boundaries.
func NewRedactingWriter(w io.Writer, secrets map[string]string) io.WriteCloser {
	return notImplementedWriter{}
}

type notImplementedWriter struct{}

func (notImplementedWriter) Write([]byte) (int, error) { return 0, ErrNotImplemented }
func (notImplementedWriter) Close() error              { return ErrNotImplemented }
