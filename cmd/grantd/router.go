package main

import (
	"context"
	"errors"
	"fmt"
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

// backendConfig carries the options of `grantd init` that configure the
// keystore. The daemon needs none: the macOS keystore opens a wrapped key by
// the mode recorded in the blob itself.
type backendConfig struct {
	// KeychainFallback lets the macOS keystore create a Keychain-resident key
	// (TierDialog) when the Secure Enclave is unusable. Default false. Only
	// meaningful when a vault is created.
	KeychainFallback bool
}

// addInitFlags adds the keystore flags of `grantd init` to c.
func addInitFlags(c *cobra.Command, cfg *backendConfig) {
	c.Flags().BoolVar(&cfg.KeychainFallback, "keychain-fallback", false,
		"macOS: if the Secure Enclave is unavailable, protect the vault key with a Keychain item (dialog tier, weaker) instead of failing; recorded in the vault, so later commands need no flag")
}

// openBackends selects the keystore and approver for this build. Tests replace
// it to run the daemon with fakes.
var openBackends = func() (backends, error) {
	ks, err := openKeyStore(backendConfig{})
	if err != nil {
		return backends{}, err
	}
	ap, err := openApprover()
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

	// Locked state: the vault file exists but the keystore transiently refuses
	// to unwrap the data key (screen locked, session not unlocked yet).
	lockedErr string         // last transient error; "" when not locked
	retrying  bool           // a background retry goroutine is running
	wg        sync.WaitGroup // background retry goroutines

	bg                     context.Context // ends the background retry (close)
	stopBG                 context.CancelFunc
	backoffMin, backoffMax time.Duration
}

// Background retry schedule while the keystore is unavailable.
var (
	retryBackoffMin = time.Second
	retryBackoffMax = 30 * time.Second
)

// errVaultLocked means the vault exists but the keystore is temporarily
// unavailable. It wraps the keystore's error for the log and status.
type errVaultLocked struct{ cause error }

func (e *errVaultLocked) Error() string { return "vault keystore unavailable: " + e.cause.Error() }
func (e *errVaultLocked) Unwrap() error { return e.cause }

func newBrokerHolder(be backends, socket string, logger *slog.Logger) (*brokerHolder, error) {
	path, err := vault.DefaultPath()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	bg, stopBG := context.WithCancel(context.Background())
	return &brokerHolder{be: be, path: path, logger: logger, socket: socket,
		bg: bg, stopBG: stopBG, backoffMin: retryBackoffMin, backoffMax: retryBackoffMax}, nil
}

// get returns the broker, opening the vault on first use. A vault that exists
// but cannot be opened is an error (it is not silently treated as missing). If
// the keystore is only transiently unavailable the error is an *errVaultLocked
// and the next call tries again.
func (h *brokerHolder) get(ctx context.Context) (*broker.Broker, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.b != nil {
		return h.b, nil
	}
	if _, err := os.Stat(h.path); errors.Is(err, os.ErrNotExist) {
		h.lockedErr = ""
		return nil, errVaultMissing
	}
	v, err := vault.Open(ctx, h.path, h.be.ks)
	if err != nil {
		if keystore.IsTransient(err) && h.bg.Err() == nil {
			h.markLocked(err)
			return nil, &errVaultLocked{cause: err}
		}
		return nil, err
	}
	closeVault := func() { _ = v.Close() }
	// vault.Open checks the keystore tier before it unwraps the key; a keystore
	// that resolves its mode while unwrapping (macOS) can report a different
	// tier afterwards. Never run a vault on a weaker keystore than it was made for.
	if t := h.be.ks.Tier(); !t.Meets(v.Info().KeystoreTier) {
		closeVault()
		return nil, fmt.Errorf("keystore tier %s is weaker than the %s the vault was created with; refusing to downgrade", t, v.Info().KeystoreTier)
	}
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
	if h.lockedErr != "" {
		h.lockedErr = ""
		h.logger.Info("vault keystore available again; vault opened")
	}
	return b, nil
}

// markLocked records a transient keystore failure. The caller holds h.mu. It
// logs once when the vault becomes locked; later failures only update the
// message shown by status.
func (h *brokerHolder) markLocked(err error) {
	if h.lockedErr == "" {
		h.logger.Warn("vault keystore unavailable (screen locked?); retrying in the background", "err", err.Error())
	}
	h.lockedErr = err.Error()
}

// lockedState returns the last transient error, or "" if the vault is not locked.
func (h *brokerHolder) lockedState() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lockedErr
}

// startRetry begins retrying the vault open in the background with exponential
// backoff until it succeeds, fails permanently, or ctx ends. Requests retry on
// their own as well; this makes the vault usable (and status accurate) without
// waiting for one. At most one retry loop runs. close stops it.
func (h *brokerHolder) startRetry() {
	ctx := h.bg
	h.mu.Lock()
	if h.retrying || h.b != nil {
		h.mu.Unlock()
		return
	}
	h.retrying = true
	h.wg.Add(1)
	h.mu.Unlock()
	go func() {
		defer h.wg.Done()
		defer func() { h.mu.Lock(); h.retrying = false; h.mu.Unlock() }()
		delay := h.backoffMin
		for {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			_, err := h.get(ctx)
			var locked *errVaultLocked
			switch {
			case err == nil, errors.Is(err, errVaultMissing), ctx.Err() != nil:
				return
			case errors.As(err, &locked):
				delay = min(delay*2, h.backoffMax)
			default:
				// Permanent now (for example the file changed): stop retrying;
				// requests report it as they always did.
				h.logger.Error("opening vault failed", "err", err.Error())
				return
			}
		}
	}()
}

// loaded returns the broker if it has been built, without opening anything.
func (h *brokerHolder) loaded() *broker.Broker {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.b
}

// close stops the background retry and releases the vault.
func (h *brokerHolder) close() {
	h.stopBG()
	h.wg.Wait()
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
	var locked *errVaultLocked
	switch {
	case errors.As(err, &locked):
		// Already logged when the state changed; one line per request would
		// flood the log while the Mac stays locked.
		h.startRetry()
		r := daemon.Failure(proto.ErrFailed, proto.ReasonVaultLocked)
		r.Message = "vault keystore unavailable (screen locked?); retrying"
		_ = w.Finish(r)
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
		} else if msg := h.lockedState(); msg != "" {
			st.VaultLocked, st.VaultLockedError = true, msg
		}
	}
}
