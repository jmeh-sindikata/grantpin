package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/grant"
	"github.com/jmeh-sindikata/grantd/internal/proto"
)

func (b *Broker) handleGrants(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	switch req.Action {
	case "", proto.ActionList:
		gs, err := b.d.Grants.List(ctx)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		out := make([]proto.GrantInfo, 0, len(gs))
		for _, g := range gs {
			if !g.Tampered && (g.Expired || !g.ExpiresAt.After(b.now())) {
				continue
			}
			out = append(out, grantInfo(g))
		}
		ok(w, out)
	case proto.ActionAdd:
		b.handleGrantAdd(ctx, req, w)
	case proto.ActionRevoke:
		if req.GrantID == "" {
			fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "grant_id is required")
			return
		}
		switch err := b.d.Grants.Revoke(ctx, req.GrantID); {
		case err == nil:
			id := b.record(ctx, b.revokeEntry(req, "grants revoke", req.GrantID))
			_ = w.Finish(&proto.Response{OK: true, GrantID: req.GrantID, AuditID: id})
		case errors.Is(err, grant.ErrNotFound):
			fail(w, proto.ErrNotFound, proto.ReasonGrantNotFound, "")
		default:
			b.internal(w, req.Op, err)
		}
	case proto.ActionRevokeAll:
		// One audit row per grant that was there (a single row with no grant
		// ID when there were none), so each revocation is traceable by ID.
		gs, err := b.d.Grants.List(ctx)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		if err := b.d.Grants.RevokeAll(ctx); err != nil {
			b.internal(w, req.Op, err)
			return
		}
		var id string
		for _, g := range gs {
			id = b.record(ctx, b.revokeEntry(req, "grants revoke_all", g.ID))
		}
		if len(gs) == 0 {
			id = b.record(ctx, b.revokeEntry(req, "grants revoke_all", ""))
		}
		_ = w.Finish(&proto.Response{OK: true, AuditID: id})
	default:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "unknown grants action")
	}
}

// revokeEntry is the audit entry for revoking a standing or dialog grant. Like
// the secret lifecycle verbs it is recorded as allowed_once with the verb as
// the reason, since these ops are not presence-gated (so the row only proves
// that it happened and who claimed to do it, not that the human did). grantID
// is empty for a revoke_all that found nothing to revoke.
func (b *Broker) revokeEntry(req *proto.Request, verb, grantID string) audit.Entry {
	caller, ok := callerOf(req)
	if !ok {
		caller = "(invalid)"
	}
	argv := []string{"grantd", "grants", "revoke"}
	if req.Action == proto.ActionRevokeAll {
		argv = append(argv, "--all")
	}
	if grantID != "" {
		argv = append(argv, grantID)
	}
	return audit.Entry{
		TS: b.now(), Caller: caller, Cwd: audit.CapString(req.Cwd, audit.MaxCwd),
		Argv: argv, GrantID: grantID,
		Decision: audit.DecisionAllowedOnce, Reason: verb,
	}
}

func (b *Broker) handleAudit(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	switch req.Action {
	case "", proto.ActionList:
		limit := req.Limit
		if limit <= 0 {
			limit = 100
		}
		limit = min(limit, maxAuditList)
		var before int64
		if req.BeforeID != "" {
			n, err := strconv.ParseInt(req.BeforeID, 10, 64)
			if err != nil || n <= 0 {
				fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "before_id must be an audit entry ID")
				return
			}
			before = n
		}
		es, err := b.d.Audit.ListBefore(ctx, limit, before)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		// Rows are free-form enough (argv, reason) that a page can outgrow one
		// protocol line, and rows written before Append bounded its fields can
		// be megabytes each. A row over maxAuditRowBytes is sent in its
		// shortened form (the Append caps, which mark what they cut); one that
		// is still too large is skipped and counted. Neither stops the walk.
		// When the page itself is full the rest is cut off and Truncated says
		// so; NextBeforeID is where the next page starts.
		// Each row is encoded once, here, and the page is the slice of those
		// encodings (same wire form as proto.AuditListResult).
		res := auditListWire{Entries: make([]json.RawMessage, 0, len(es))}
		size := len(`{"entries":[],"truncated":true,"skipped":1000,"next_before_id":"9223372036854775807"}`)
		for _, e := range es {
			enc, err := auditRow(e)
			if err != nil {
				b.internal(w, req.Op, err)
				return
			}
			if len(enc) > maxAuditRowBytes {
				if enc, err = auditRow(audit.Capped(e)); err != nil {
					b.internal(w, req.Op, err)
					return
				}
			}
			if len(enc) > maxAuditRowBytes {
				res.Skipped++
				res.NextBeforeID = e.ID
				continue
			}
			if size += len(enc) + 1; size > maxResultBytes {
				res.Truncated = true
				break
			}
			res.Entries = append(res.Entries, enc)
			res.NextBeforeID = e.ID
		}
		ok(w, res)
	case proto.ActionVerify:
		res, err := b.d.Audit.Verify(ctx)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		ok(w, proto.AuditVerifyResult{OK: res.OK, Entries: res.Entries, FirstBadID: res.FirstBadID})
	case proto.ActionExport:
		// The CSV travels as a JSON string, so what must fit is its encoded
		// length (quotes and newlines escape to two bytes). Raw bytes already
		// over the limit cannot fit once encoded, so stop collecting there.
		buf := &cappedBuffer{limit: maxResultBytes}
		err := b.d.Audit.ExportCSV(ctx, buf)
		tooBig := buf.over || errors.Is(err, errCapExceeded)
		if err != nil && !tooBig {
			b.internal(w, req.Op, err)
			return
		}
		var raw json.RawMessage
		if !tooBig {
			if raw, err = proto.NewResult(proto.AuditExportResult{CSV: buf.String()}); err != nil {
				b.internal(w, req.Op, err)
				return
			}
			tooBig = len(raw) > maxResultBytes
		}
		if tooBig {
			fail(w, proto.ErrFailed, proto.ReasonResponseTooLarge, "audit log too large to export over the socket; use `audit list --limit`")
			return
		}
		okRaw(w, raw)
	default:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "unknown audit action")
	}
}

// maxAuditRowBytes is the most one entry may take in an audit list page (its
// encoded size). A variable so that tests can reach the skip path.
var maxAuditRowBytes = 256 << 10

// auditListWire is proto.AuditListResult with its entries already encoded; the
// two must keep the same JSON shape.
type auditListWire struct {
	Entries      []json.RawMessage `json:"entries"`
	Truncated    bool              `json:"truncated,omitempty"`
	Skipped      int               `json:"skipped,omitempty"`
	NextBeforeID string            `json:"next_before_id,omitempty"`
}

// auditRow returns the JSON encoding of e as a proto.AuditInfo.
func auditRow(e audit.Entry) (json.RawMessage, error) {
	info := proto.AuditInfo{
		ID: e.ID, TS: e.TS, Caller: e.Caller, Cwd: e.Cwd, Argv: e.Argv, Secrets: e.Secrets, Expanded: e.Expanded,
		Decision: e.Decision, GrantID: e.GrantID, ExitCode: e.ExitCode,
		DurationMS: e.Duration.Milliseconds(), Reason: e.Reason,
	}
	return json.Marshal(info)
}

var errCapExceeded = errors.New("broker: output exceeds the response limit")

// cappedBuffer collects up to limit bytes and then refuses more.
type cappedBuffer struct {
	bytes.Buffer
	limit int
	over  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.limit {
		c.over = true
		return 0, errCapExceeded
	}
	return c.Buffer.Write(p)
}
