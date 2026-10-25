package audit

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Entry is one audit row (§6). It never contains secret values.
type Entry struct {
	ID       string
	TS       time.Time
	Caller   string
	Cwd      string
	Argv     []string
	Secrets  []string // names requested
	Decision string   // e.g. "allow_once", "allow_grant", "grant_match", "deny", "refused"
	GrantID  string
	ExitCode *int
	Duration time.Duration
}

// VerifyResult reports the outcome of walking the HMAC chain.
type VerifyResult struct {
	OK         bool
	Entries    int
	FirstBadID string
}

// Log is the append-only, HMAC-chained audit log.
type Log struct{}

// Append adds an entry, chaining it to the previous row, and returns its ID.
func (l *Log) Append(ctx context.Context, e Entry) (string, error) {
	return "", ErrNotImplemented
}

// List returns the most recent entries (limit 0 = default).
func (l *Log) List(ctx context.Context, limit int) ([]Entry, error) {
	return nil, ErrNotImplemented
}

// Verify walks the whole chain.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	return VerifyResult{}, ErrNotImplemented
}
