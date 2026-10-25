package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/daemon"
	"grantd/internal/proto"
	"grantd/internal/vault"
)

func infoOf(m vault.Meta) proto.SecretInfo {
	return proto.SecretInfo{
		Name: m.Name, Tags: m.Tags, URL: m.URL, Notes: m.Notes, ExpiresAt: m.ExpiresAt,
		MinTier: m.MinTier, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

// nameFail answers a request whose Name is unusable. It reports whether it
// responded.
func nameFail(w daemon.ResponseWriter, name string) bool {
	if err := vault.ValidateName(name); err != nil {
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
		return true
	}
	return false
}

// vaultFail maps a vault error to a response.
func (b *Broker) vaultFail(ctx context.Context, w daemon.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		fail(w, proto.ErrNotFound, proto.ReasonSecretNotFound, "")
	case errors.Is(err, vault.ErrExists):
		fail(w, proto.ErrBadRequest, proto.ReasonSecretExists, "secret already exists (overwrite to replace)")
	case errors.Is(err, vault.ErrExpired):
		fail(w, proto.ErrRefused, proto.ReasonSecretExpired, "")
	case errors.Is(err, vault.ErrInvalidName), errors.Is(err, vault.ErrInvalidTag):
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
	case ctx.Err() != nil:
		fail(w, proto.ErrFailed, ctxFailure(ctx), "")
	default:
		b.internal(w, op, err)
	}
}

func (b *Broker) handleList(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	var opts []vault.ListOption
	if req.Tag != "" {
		opts = append(opts, vault.ByTag(req.Tag))
	}
	if req.ExpiringWithinS > 0 {
		opts = append(opts, vault.ExpiringWithin(time.Duration(req.ExpiringWithinS)*time.Second))
	}
	metas, err := b.d.Vault.List(ctx, opts...)
	if err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	out := make([]proto.SecretInfo, 0, len(metas))
	for _, m := range metas {
		out = append(out, infoOf(m))
	}
	ok(w, out)
}

func (b *Broker) handleExists(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	e, err := b.d.Vault.Exists(ctx, req.Name)
	if err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	ok(w, proto.ExistsResult{Exists: e})
}

func (b *Broker) handleMasked(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	m, err := b.d.Vault.Masked(ctx, req.Name)
	if err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	ok(w, proto.MaskedResult{Masked: m})
}

// lifecycleEntry is the audit entry for a set/delete/update/show of one secret. The
// audit vocabulary has no decision for these, so they are recorded as
// allowed_once with the verb as the reason (argv shows the equivalent CLI).
func (b *Broker) lifecycleEntry(req *proto.Request, verb string) audit.Entry {
	caller, ok := callerOf(req)
	if !ok {
		caller = "(invalid)"
	}
	return audit.Entry{
		TS: b.now(), Caller: caller, Cwd: req.Cwd,
		Argv: []string{"grantd", verb, req.Name}, Secrets: []string{req.Name},
		Decision: audit.DecisionAllowedOnce, Reason: verb,
	}
}

func (b *Broker) handleSet(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	switch {
	case req.Value == "":
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "value must not be empty")
		return
	case len(req.Value) > maxValueBytes:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "value too large")
		return
	case len(req.URL) > maxURLBytes:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, fmt.Sprintf("url too long (max %d bytes)", maxURLBytes))
		return
	case len(req.Notes) > maxNotesBytes:
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, fmt.Sprintf("notes too long (max %d bytes)", maxNotesBytes))
		return
	case req.MinTier != nil && !req.MinTier.Valid():
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "invalid min_tier")
		return
	case req.Expires != nil && !req.Expires.After(b.now()):
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "expires must be in the future")
		return
	}
	m := vault.Meta{Name: req.Name, Tags: req.Tags, URL: req.URL, Notes: req.Notes, ExpiresAt: req.Expires}
	if req.MinTier != nil {
		// TierNone is the zero value and means "vault default" to vault.Set,
		// so a secret can never be stored with TierNone by accident.
		m.MinTier = *req.MinTier
	}
	val := []byte(req.Value)
	err := b.d.Vault.Set(ctx, m, val, req.Overwrite)
	zero(val)
	if err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	id := b.record(ctx, b.lifecycleEntry(req, "set"))
	_ = w.Finish(&proto.Response{OK: true, AuditID: id})
}

func (b *Broker) handleDelete(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	if err := b.d.Vault.Delete(ctx, req.Name); err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	id := b.record(ctx, b.lifecycleEntry(req, "delete"))
	_ = w.Finish(&proto.Response{OK: true, AuditID: id})
}

// handleUpdate changes the metadata of an existing secret and never touches
// its value: any subset of tags, url, notes, expires and min_tier, plus Clear
// to reset tags, url, notes or the expiry. Same validation as set. Not
// presence-gated (the same class as set and delete), audited as allowed_once
// with reason "update". A min_tier change re-encrypts inside the vault because
// the tier is bound into the ciphertext's additional data.
func (b *Broker) handleUpdate(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	bad := func(msg string) { fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, msg) }
	var patch vault.MetaPatch
	clr := map[string]bool{}
	for _, f := range req.Clear {
		switch f {
		case "tags", "url", "notes", "expires":
			clr[f] = true
		default:
			bad("unknown field to clear (want tags, url, notes or expires)")
			return
		}
	}
	switch {
	case req.Value != "":
		bad("update does not change the value; use set with overwrite")
		return
	case req.Overwrite:
		bad("overwrite does not apply to update")
		return
	case clr["tags"] && req.Tags != nil, clr["url"] && req.URL != "", clr["notes"] && req.Notes != "", clr["expires"] && req.Expires != nil:
		bad("a field cannot be both set and cleared")
		return
	case len(req.URL) > maxURLBytes:
		bad(fmt.Sprintf("url too long (max %d bytes)", maxURLBytes))
		return
	case len(req.Notes) > maxNotesBytes:
		bad(fmt.Sprintf("notes too long (max %d bytes)", maxNotesBytes))
		return
	case req.MinTier != nil && !req.MinTier.Valid():
		bad("invalid min_tier")
		return
	case req.Expires != nil && !req.Expires.After(b.now()):
		bad("expires must be in the future")
		return
	}
	switch {
	case clr["tags"]:
		patch.Tags = &[]string{}
	case req.Tags != nil:
		patch.Tags = &req.Tags
	}
	switch {
	case clr["url"]:
		patch.URL = new(string)
	case req.URL != "":
		patch.URL = &req.URL
	}
	switch {
	case clr["notes"]:
		patch.Notes = new(string)
	case req.Notes != "":
		patch.Notes = &req.Notes
	}
	patch.ClearExpires = clr["expires"]
	patch.ExpiresAt = req.Expires
	patch.MinTier = req.MinTier
	if patch.Empty() {
		bad("nothing to update")
		return
	}
	if err := b.d.Vault.UpdateMeta(ctx, req.Name, patch); err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	id := b.record(ctx, b.lifecycleEntry(req, "update"))
	_ = w.Finish(&proto.Response{OK: true, AuditID: id})
}

// handleShow is the only path on which a plaintext value is returned. It is
// presence-gated on every call (grants are neither consulted nor created) and
// audited before the value leaves the process: if the audit write fails the
// value is not sent.
func (b *Broker) handleShow(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	if nameFail(w, req.Name) {
		return
	}
	caller, callerOK := callerOf(req)
	if !callerOK {
		fail(w, proto.ErrBadRequest, proto.ReasonBadRequest, "invalid caller label")
		return
	}
	entry := b.lifecycleEntry(req, "show")
	refuse := func(decision, category, reason, msg string) {
		e := entry
		e.Decision, e.Reason = decision, reason
		if msg != "" {
			e.Reason += ": " + msg
		}
		r := daemon.Failure(category, reason)
		r.Message = msg
		r.AuditID = b.record(ctx, e)
		_ = w.Finish(r)
	}

	m, err := b.d.Vault.Get(ctx, req.Name)
	switch {
	case errors.Is(err, vault.ErrNotFound):
		refuse(audit.DecisionError, proto.ErrNotFound, proto.ReasonSecretNotFound, "")
		return
	case err != nil:
		b.vaultFail(ctx, w, req.Op, err)
		return
	case m.Expired(b.now()):
		refuse(audit.DecisionError, proto.ErrRefused, proto.ReasonSecretExpired, "")
		return
	}
	if met, why := b.tierMet(m.MinTier); !met {
		refuse(audit.DecisionRefusedTier, proto.ErrRefused, proto.ReasonTierUnmet, why)
		return
	}

	dec, err := b.ask(ctx, approve.ApprovalRequest{
		Kind:   approve.KindShow,
		Caller: caller, Cwd: req.Cwd, Argv: []string{"grantd", "show", req.Name},
		Secrets: []string{req.Name}, Expanded: []string{req.Name},
	})
	switch {
	case err != nil && ctx.Err() != nil:
		refuse(audit.DecisionError, proto.ErrFailed, ctxFailure(ctx), "while waiting for approval")
		return
	case err != nil:
		b.log.Warn("approver failed", "err", err.Error())
		refuse(audit.DecisionError, proto.ErrDenied, proto.ReasonApproverUnavailable, "")
		return
	case !dec.Allow:
		reason := dec.Reason
		if reason == "" {
			reason = "denied"
		}
		e := entry
		e.Decision, e.Reason = audit.DecisionDeniedUser, "show: "+reason
		r := daemon.Failure(proto.ErrDenied, proto.ReasonUserDenied)
		r.AuditID = b.record(ctx, e)
		_ = w.Finish(r)
		return
	}
	// dec.TTL is deliberately ignored: show never creates or uses grants.

	values, err := b.d.Vault.Resolve(ctx, []string{req.Name})
	if err != nil {
		b.vaultFail(ctx, w, req.Op, err)
		return
	}
	v := values[req.Name]
	defer func() {
		for _, pt := range values {
			zero(pt)
		}
	}()
	id, err := b.recordStrict(ctx, entry)
	if err != nil {
		b.log.Error("audit append failed; refusing to show", "err", err.Error())
		fail(w, proto.ErrFailed, proto.ReasonInternal, "audit log unavailable")
		return
	}
	raw, err := proto.NewResult(proto.ShowResult{Value: string(v)})
	if err != nil {
		fail(w, proto.ErrFailed, proto.ReasonInternal, "internal error")
		return
	}
	if len(raw) > maxResultBytes { // a 1 MiB value of control characters escapes to ~6 MiB
		fail(w, proto.ErrFailed, proto.ReasonResponseTooLarge, "value too large to show over the socket")
		return
	}
	_ = w.Finish(&proto.Response{OK: true, AuditID: id, Result: raw})
}
