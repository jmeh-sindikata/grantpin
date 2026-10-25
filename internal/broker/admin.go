package broker

import (
	"bytes"
	"context"
	"errors"

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
		es, err := b.d.Audit.List(ctx, limit, 0)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		out := make([]proto.AuditInfo, 0, len(es))
		for _, e := range es {
			info := proto.AuditInfo{
				ID: e.ID, TS: e.TS, Caller: e.Caller, Cwd: e.Cwd, Argv: e.Argv, Secrets: e.Secrets,
				Decision: e.Decision, GrantID: e.GrantID, ExitCode: e.ExitCode,
				DurationMS: e.Duration.Milliseconds(), Reason: e.Reason,
			}
			out = append(out, info)
		}
		ok(w, out)
	case proto.ActionVerify:
		res, err := b.d.Audit.Verify(ctx)
		if err != nil {
			b.internal(w, req.Op, err)
			return
		}
		ok(w, proto.AuditVerifyResult{OK: res.OK, Entries: res.Entries, FirstBadID: res.FirstBadID})
	case proto.ActionExport:
		var buf bytes.Buffer
		if err := b.d.Audit.ExportCSV(ctx, &buf); err != nil {
			b.internal(w, req.Op, err)
			return
		}
		if buf.Len() > maxExportBytes {
			fail(w, proto.ErrFailed, proto.ReasonInternal, "audit log too large to export over the socket; use `audit list --limit`")
			return
		}
		ok(w, proto.AuditExportResult{CSV: buf.String()})
	default:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "unknown audit action")
	}
}
