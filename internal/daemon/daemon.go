package daemon

import (
	"context"
	"errors"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/grant"
	"grantd/internal/keystore"
	"grantd/internal/vault"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// Config wires the daemon's dependencies. Platform backends are injected so the
// core is testable with the dev backends.
type Config struct {
	SocketPath string
	VaultPath  string
	KeyStore   keystore.KeyStore
	Approver   approve.Approver

	// Set by New from the above; exposed for tests that want to pre-populate.
	Vault  *vault.Vault
	Grants *grant.Store
	Audit  *audit.Log
}

// Server is the daemon.
type Server struct{}

// New builds a Server from cfg.
func New(cfg Config) (*Server, error) { return nil, ErrNotImplemented }

// Serve listens on the socket (same-UID peers only) until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error { return ErrNotImplemented }
