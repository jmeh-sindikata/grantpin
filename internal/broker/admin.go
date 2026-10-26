package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"grantd/internal/audit"
	"grantd/internal/daemon"
	"grantd/internal/grant"
	"grantd/internal/proto"
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
			_ = w.Finish(&proto.Response{OK: true, GrantID: req.GrantID})
		case errors.Is(err, grant.ErrNotFound):
			fail(w, proto.ErrNotFound, proto.ReasonGrantNotFound, "")
		default:
			b.internal(w, req.Op, err)
		}
	case proto.ActionRevokeAll:
		if err := b.d.Grants.RevokeAll(ctx); err != nil {
			b.internal(w, req.Op, err)
			return
		}
		_ = w.Finish(&proto.Response{OK: true})
	default:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "unknown grants action")
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
		res := proto.AuditListResult{Entries: make([]proto.AuditInfo, 0, len(es))}
		size := len(`{"entries":[],"truncated":true,"skipped":1000,"next_before_id":"9223372036854775807"}`)
		for _, e := range es {
			enc, info, err := auditRow(e)
			if err != nil {
				b.internal(w, req.Op, err)
				return
			}
			if len(enc) > maxAuditRowBytes {
				if enc, info, err = auditRow(audit.Capped(e)); err != nil {
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
			res.Entries = append(res.Entries, info)
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

// auditRow converts e and returns its encoding.
func auditRow(e audit.Entry) ([]byte, proto.AuditInfo, error) {
	info := proto.AuditInfo{
		ID: e.ID, TS: e.TS, Caller: e.Caller, Cwd: e.Cwd, Argv: e.Argv, Secrets: e.Secrets, Expanded: e.Expanded,
		Decision: e.Decision, GrantID: e.GrantID, ExitCode: e.ExitCode,
		DurationMS: e.Duration.Milliseconds(), Reason: e.Reason,
	}
	enc, err := json.Marshal(info)
	return enc, info, err
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
