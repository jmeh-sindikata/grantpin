package grant

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Grant is the unit that makes approvals reusable (§6). A request matches only
// if caller, cwd, every requested secret and the argv prefix all satisfy a
// non-expired grant.
type Grant struct {
	ID            string
	Caller        string
	CwdPrefix     string   // absolute; request cwd must be under it
	Secrets       []string // globs
	CmdPrefix     []string // request argv must start with this
	ExpiresAt     time.Time
	UsesRemaining *int // nil = unlimited within TTL
	CreatedAt     time.Time
}

// Query is what a run request is matched against.
type Query struct {
	Caller  string
	Cwd     string
	Secrets []string // concrete names (globs already expanded)
	Argv    []string
	Now     time.Time
}

// Store persists grants.
type Store struct{}

// Match returns the first non-expired grant satisfying q, or (nil, nil).
func (s *Store) Match(ctx context.Context, q Query) (*Grant, error) { return nil, ErrNotImplemented }

// Add stores a new grant and returns it with ID set.
func (s *Store) Add(ctx context.Context, g Grant) (*Grant, error) { return nil, ErrNotImplemented }

// List returns all non-expired grants.
func (s *Store) List(ctx context.Context) ([]Grant, error) { return nil, ErrNotImplemented }

// Revoke removes one grant.
func (s *Store) Revoke(ctx context.Context, id string) error { return ErrNotImplemented }

// RevokeAll removes every grant.
func (s *Store) RevokeAll(ctx context.Context) error { return ErrNotImplemented }
