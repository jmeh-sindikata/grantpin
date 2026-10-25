package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/broker"
	"grantd/internal/daemon"
	"grantd/internal/grant"
	"grantd/internal/keystore"
	"grantd/internal/proto"
	"grantd/internal/vault"
)

// backends are the platform seams the daemon runs on.
type backends struct {
	ks keystore.KeyStore
	ap approve.Approver
}

// backendConfig carries the user-facing backend options from the command line.
type backendConfig struct {
	// KeychainFallback lets the macOS keystore fall back to a Keychain-resident
	// key (TierDialog) when the Secure Enclave is unusable. Default false.
	KeychainFallback bool
}

// addBackendFlags adds the flags that configure the backends to c.
func addBackendFlags(c *cobra.Command, cfg *backendConfig) {
	c.Flags().BoolVar(&cfg.KeychainFallback, "keychain-fallback", false,
		"macOS: allow a Keychain-resident key (dialog tier) when the Secure Enclave is unavailable; the vault must be opened with the same setting")
}

// openBackends selects the keystore and approver for this build. Tests replace
// it to run the daemon with fakes.
var openBackends = func(cfg backendConfig) (backends, error) {
	ks, err := openKeyStore(cfg)
	if err != nil {
		return backends{}, err
	}
	ap, err := openApprover(cfg)
	if err != nil {
		return backends{}, err
	}
	return backends{ks: ks, ap: ap}, nil
}

// errVaultMissing means the vault file does not exist yet (`grantd init` has
// not run).
var errVaultMissing = errors.New("vault not initialized")

// brokerHolder lazily opens the vault and builds the broker, so that a daemon
// started before `grantd init` picks the vault up as soon as it exists,
// without a restart.
type brokerHolder struct {
	be     backends
	path   string
	logger *slog.Logger
	socket string

	mu sync.Mutex
	v  *vault.Vault
	b  *broker.Broker
}

func newBrokerHolder(be backends, socket string, logger *slog.Logger) (*brokerHolder, error) {
	path, err := vault.DefaultPath()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &brokerHolder{be: be, path: path, logger: logger, socket: socket}, nil
}

// get returns the broker, opening the vault on first use. A vault that exists
// but cannot be opened is an error (it is not silently treated as missing).
func (h *brokerHolder) get(ctx context.Context) (*broker.Broker, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.b != nil {
		return h.b, nil
	}
	if _, err := os.Stat(h.path); errors.Is(err, os.ErrNotExist) {
		return nil, errVaultMissing
	}
	v, err := vault.Open(ctx, h.path, h.be.ks)
	if err != nil {
		return nil, err
	}
	closeVault := func() { _ = v.Close() }
	if err := grant.Migrate(ctx, v.DB()); err != nil {
		closeVault()
		return nil, err
	}
	if err := audit.Migrate(ctx, v.DB()); err != nil {
		closeVault()
		return nil, err
	}
	alog, err := audit.New(ctx, v.DB(), v.DeriveKey("audit-hmac"))
	if err != nil {
		closeVault()
		return nil, err
	}
	grants := grant.NewStore(v.DB(), v.DeriveKey("grant-mac"))
	grants.SetLogger(h.logger)
	b, err := broker.New(broker.Deps{
		Vault: v, Grants: grants, Audit: alog,
		Approver: h.be.ap, KeyStoreTier: h.be.ks.Tier(),
		DefaultGrantTTL: time.Hour, Logger: h.logger,
	})
	if err != nil {
		closeVault()
		return nil, err
	}
	h.v, h.b = v, b
	return b, nil
}

// loaded returns the broker if it has been built, without opening anything.
func (h *brokerHolder) loaded() *broker.Broker {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.b
}

func (h *brokerHolder) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.v != nil {
		_ = h.v.Close()
		h.v, h.b = nil, nil
	}
}

// handle serves one request, failing cleanly while the vault is unavailable.
func (h *brokerHolder) handle(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	b, err := h.get(ctx)
	switch {
	case errors.Is(err, errVaultMissing):
		r := daemon.Failure(proto.ErrFailed, proto.ReasonVaultNotInitialized)
		r.Message = "vault not initialized; run `grantd init`"
		_ = w.Finish(r)
	case err != nil:
		// The cause (wrong keystore, bad permissions, ...) goes to the log.
		h.logger.Error("opening vault failed", "err", err.Error())
		r := daemon.Failure(proto.ErrFailed, proto.ReasonInternal)
		r.Message = "vault could not be opened (see daemon log)"
		_ = w.Finish(r)
	default:
		b.Handle(ctx, req, w)
	}
}

// buildRouter returns the op router the daemon serves. The built-in status op
// is provided by the daemon itself (see statusFunc).
func (h *brokerHolder) buildRouter() *daemon.Router {
	r := daemon.NewRouter()
	for _, op := range broker.Ops {
		r.Register(op, daemon.HandlerFunc(h.handle))
	}
	return r
}

// statusFunc fills the status reply: backend tiers and socket always, vault and
// grant details once the vault is open. It never opens the vault itself.
func (h *brokerHolder) statusFunc() daemon.StatusFunc {
	return func(ctx context.Context, st *proto.StatusResult) {
		st.Socket = h.socket
		st.KeyStoreTier = h.be.ks.Tier()
		st.ApproverTier = h.be.ap.Tier()
		if _, err := os.Stat(h.path); err == nil {
			st.VaultInitialized = true
		}
		if b := h.loaded(); b != nil {
			b.StatusFunc()(ctx, st)
		}
	}
}
