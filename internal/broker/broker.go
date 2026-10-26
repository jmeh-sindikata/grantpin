package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/grant"
	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/vault"
)

// DefaultCaller is used when a request carries no caller label.
const DefaultCaller = "cli"

// DefaultGrantTTL is the "Allow for N" suggestion when Deps leaves it zero and
// no policy applies (a policy offers its max_grant_ttl, at most
// grant.MaxDialogGrantTTL).
const DefaultGrantTTL = time.Hour

const (
	maxCallerLen  = 64
	maxSecrets    = 256
	maxArgv       = 4096
	maxArgvBytes  = 256 << 10 // total bytes of argv; keeps one audit row far below a protocol line
	maxValueBytes = 1 << 20
	maxURLBytes   = 2 << 10 // stored secret url and notes, each
	maxNotesBytes = 2 << 10
	maxAuditList  = 1000
	auditTimeout  = 10 * time.Second

	// maxResultBytes is the largest Response.Result the broker will send: one
	// protocol line (proto.MaxLineBytes) minus room for the rest of the
	// response. It is measured on the JSON-encoded result, so escaping counts.
	maxResultBytes = proto.MaxLineBytes - 64<<10
)

// Deps are the broker's collaborators.
type Deps struct {
	Vault  *vault.Vault
	Grants *grant.Store
	Audit  *audit.Log
	// Approver asks the human. All calls are serialised by the broker.
	Approver approve.Approver
	// KeyStoreTier is the tier the keystore provides; a secret whose min_tier
	// is higher than this (or than Approver.Tier()) is refused.
	KeyStoreTier presence.PresenceTier
	// DefaultGrantTTL is offered as "Allow for N" (default 1h) when no policy
	// applies. With a policy the dialog offers min(max_grant_ttl,
	// grant.MaxDialogGrantTTL) instead.
	DefaultGrantTTL time.Duration
	// Logger receives operational errors (never values). nil discards.
	Logger *slog.Logger
	// Now overrides time.Now (tests).
	Now func() time.Time
}

// Broker handles every daemon op except the built-in status (see StatusFunc).
type Broker struct {
	d      Deps
	log    *slog.Logger
	now    func() time.Time
	askSem chan struct{} // capacity 1: serialises Approver.Ask

	// afterReleased, if set, runs right after a run's released audit row is
	// written (tests use it to interleave a concurrent change).
	afterReleased func()
}

// New validates deps and returns a Broker.
func New(d Deps) (*Broker, error) {
	switch {
	case d.Vault == nil:
		return nil, errors.New("broker: nil Vault")
	case d.Grants == nil:
		return nil, errors.New("broker: nil Grants")
	case d.Audit == nil:
		return nil, errors.New("broker: nil Audit")
	case d.Approver == nil:
		return nil, errors.New("broker: nil Approver")
	}
	if d.DefaultGrantTTL <= 0 {
		d.DefaultGrantTTL = DefaultGrantTTL
	}
	b := &Broker{d: d, log: d.Logger, now: d.Now, askSem: make(chan struct{}, 1)}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b, nil
}

// Ops lists the ops the broker serves (everything but status).
var Ops = []string{
	proto.OpRun, proto.OpList, proto.OpExists, proto.OpMasked, proto.OpSet,
	proto.OpDelete, proto.OpUpdate, proto.OpShow, proto.OpGrants, proto.OpAudit,
}

// Register installs the broker's handlers on r.
func (b *Broker) Register(r *daemon.Router) {
	for _, op := range Ops {
		r.Register(op, daemon.HandlerFunc(b.Handle))
	}
}

// Handle dispatches one request by op. It satisfies daemon.Handler's contract:
// exactly one Finish.
func (b *Broker) Handle(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	switch req.Op {
	case proto.OpRun:
		b.handleRun(ctx, req, w)
	case proto.OpList:
		b.handleList(ctx, req, w)
	case proto.OpExists:
		b.handleExists(ctx, req, w)
	case proto.OpMasked:
		b.handleMasked(ctx, req, w)
	case proto.OpSet:
		b.handleSet(ctx, req, w)
	case proto.OpDelete:
		b.handleDelete(ctx, req, w)
	case proto.OpUpdate:
		b.handleUpdate(ctx, req, w)
	case proto.OpShow:
		b.handleShow(ctx, req, w)
	case proto.OpGrants:
		b.handleGrants(ctx, req, w)
	case proto.OpAudit:
		b.handleAudit(ctx, req, w)
	default:
		fail(w, proto.ErrBadRequest, proto.ReasonUnknownOp, "")
	}
}

// StatusFunc fills the vault/backend/grant parts of the status reply.
func (b *Broker) StatusFunc() daemon.StatusFunc {
	return func(ctx context.Context, st *proto.StatusResult) {
		st.VaultInitialized = true
		st.KeyStoreTier = b.d.KeyStoreTier
		st.ApproverTier = b.d.Approver.Tier()
		if metas, err := b.d.Vault.List(ctx); err == nil {
			st.Secrets = len(metas)
		}
		if gs, err := b.d.Grants.List(ctx); err == nil {
			for _, g := range gs {
				switch {
				case g.Tampered:
					st.TamperedGrants++
				case !g.Expired && g.ExpiresAt.After(b.now()):
					st.ActiveGrants++
				}
			}
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func fail(w daemon.ResponseWriter, category, reason, msg string) {
	r := daemon.Failure(category, reason)
	r.Message = msg
	_ = w.Finish(r)
}

func (b *Broker) internal(w daemon.ResponseWriter, op string, err error) {
	// The error text is logged, not sent: it may carry file paths and the
	// caller only needs to know that it was not their fault.
	b.log.Error("internal error", "op", op, "err", err.Error())
	fail(w, proto.ErrFailed, proto.ReasonInternal, "internal error")
}

func ok(w daemon.ResponseWriter, result any) {
	raw, err := proto.NewResult(result)
	if err != nil {
		fail(w, proto.ErrFailed, proto.ReasonInternal, "internal error")
		return
	}
	okRaw(w, raw)
}

// okRaw sends an already-encoded result, or a clean failure if it would not
// fit in one protocol line (the daemon would otherwise have to drop it).
func okRaw(w daemon.ResponseWriter, raw json.RawMessage) {
	if len(raw) > maxResultBytes {
		fail(w, proto.ErrFailed, proto.ReasonResponseTooLarge, "response too large")
		return
	}
	_ = w.Finish(&proto.Response{OK: true, Result: raw})
}

// CtxFailure maps a done context to the failure reason the caller should get:
// timeout if its deadline passed, canceled otherwise. The daemon router uses it
// too, so a request ends the same way wherever it is cut short.
func CtxFailure(ctx context.Context) (reason string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return proto.ReasonTimeout
	}
	return proto.ReasonCanceled
}

// record appends e to the audit log. It uses a context detached from the
// request's cancellation so that a client that hung up still leaves a trace.
// It returns the audit ID, or "" if the write failed (logged).
func (b *Broker) record(ctx context.Context, e audit.Entry) string {
	id, err := b.recordStrict(ctx, e)
	if err != nil {
		b.log.Error("audit append failed", "decision", e.Decision, "err", err.Error())
		return ""
	}
	return id
}

func (b *Broker) recordStrict(ctx context.Context, e audit.Entry) (string, error) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if e.TS.IsZero() {
		e.TS = b.now()
	}
	return b.d.Audit.Append(actx, e)
}

// callerOf returns the caller label or DefaultCaller; the bool is false when
// the label is unusable (too long or containing control characters, which
// could spoof the approval prompt).
func callerOf(req *proto.Request) (string, bool) {
	c := strings.TrimSpace(req.Caller)
	if c == "" {
		return DefaultCaller, true
	}
	return labelOf(c)
}

// labelOf validates a non-empty, trimmed caller label.
func labelOf(c string) (string, bool) {
	if len(c) > maxCallerLen {
		return DefaultCaller, false
	}
	for _, r := range c {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return DefaultCaller, false
		}
	}
	return c, true
}

// tierMet reports whether both the approver and the keystore meet required.
func (b *Broker) tierMet(required presence.PresenceTier) (bool, string) {
	at, kt := b.d.Approver.Tier(), b.d.KeyStoreTier
	if at.Meets(required) && kt.Meets(required) {
		return true, ""
	}
	return false, fmt.Sprintf("requires %s; approver=%s keystore=%s", required, at, kt)
}

// ask serialises Approver.Ask. Waiting for the lock honours ctx.
func (b *Broker) ask(ctx context.Context, req approve.ApprovalRequest) (approve.Decision, error) {
	select {
	case b.askSem <- struct{}{}:
	case <-ctx.Done():
		return approve.Decision{}, ctx.Err()
	}
	defer func() { <-b.askSem }()
	if err := ctx.Err(); err != nil {
		return approve.Decision{}, err
	}
	return b.d.Approver.Ask(ctx, req)
}
