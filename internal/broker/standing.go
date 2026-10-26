package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/daemon"
	"grantd/internal/grant"
	"grantd/internal/policy"
	"grantd/internal/proto"
)

// ReasonStanding is the audit reason of the allowed_new_grant row written when
// a standing grant is created. The releases it later authorises are ordinary
// allowed_grant rows.
const ReasonStanding = "standing"

// handleGrantAdd creates a standing grant: `grants` with action "add".
//
// A standing grant is created by the human on purpose (`grantd grants add`),
// but the daemon cannot tell who sent the request: any socket client, an agent
// included, can. So the request is validated like a run, refused if the repo
// policy forbids what it names, and then goes to the approver as
// KindStandingGrant, whose prompt says "standing grant", states the duration
// and tells the human to continue only if they asked for it. Nothing is
// stored before the human says yes, and the dialog's "Allow for N" can never
// produce one.
//
// Order: validate, policy, names, tier, ceiling, approval, store, audit. The
// audit row is written after the grant exists, and if that write fails the
// grant is revoked again (no standing grant without a trail).
func (b *Broker) handleGrantAdd(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	label := strings.TrimSpace(req.GrantCaller)
	// Capped copies of the raw request, as in handleRun.
	rc := &runCtx{b: b, w: w, started: b.now(), entry: audit.Capped(audit.Entry{
		TS: b.now(), Caller: label, Cwd: req.Cwd, Argv: req.Argv, Secrets: req.Secrets,
	})}
	refuse := func(decision, category, reason, msg string) {
		rc.refuse(ctx, decision, category, reason, "standing grant: "+msg)
	}
	badRequest := func(msg string) {
		refuse(audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, msg)
	}

	// 1. Validate, like a run. The grant caller has no default: the human has
	// to say who the grant is for.
	var callerOK bool
	switch {
	case label == "":
		rc.entry.Caller = "(none)"
		badRequest("grant_caller is required")
		return
	default:
		_, callerOK = labelOf(label)
	}
	if !callerOK {
		rc.entry.Caller = "(invalid)"
	}
	cwd, msg := validateRun(req, callerOK)
	if msg != "" {
		badRequest(msg)
		return
	}
	rc.entry.Cwd = cwd
	if slices.Contains(req.Argv, "") {
		badRequest("the command prefix must not contain empty elements")
		return
	}
	if req.TTLS <= 0 {
		badRequest("ttl is required and must be positive")
		return
	}
	if req.Uses < 0 {
		badRequest("uses must not be negative")
		return
	}

	// 2. Policy: it can forbid what the grant would cover, as for a run.
	pol, err := policy.Load(cwd)
	if err != nil {
		refuse(audit.DecisionRefusedPolicy, proto.ErrRefused, proto.ReasonPolicyRefused, err.Error())
		return
	}
	if pol.Present() {
		if err := pol.Check(req.Secrets, req.Argv); err != nil {
			refuse(audit.DecisionRefusedPolicy, proto.ErrRefused, proto.ReasonPolicyRefused, policyItem(err))
			return
		}
	}

	// 3. Names, expiry, tier: the secrets must exist now and be releasable.
	names, err := b.d.Vault.ExpandNames(ctx, req.Secrets)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	rc.entry.Expanded = names
	required, err := b.d.Vault.CheckNames(ctx, names, b.now())
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	if met, why := b.tierMet(required); !met {
		refuse(audit.DecisionRefusedTier, proto.ErrRefused, proto.ReasonTierUnmet, why)
		return
	}

	// 4. Ceiling. Above it is an error, never a silent clamp: what the human
	// is asked to approve must be what they typed. max_grant_ttl does not
	// apply here (see the policy package); max_standing_grant_ttl does.
	ceiling, source := standingCeiling(pol)
	if req.TTLS > int64(ceiling/time.Second) {
		badRequest(fmt.Sprintf("ttl %s exceeds the maximum standing grant lifetime of %s (%s)",
			spanText(req.TTLS), spanText(int64(ceiling/time.Second)), source))
		return
	}
	ttl := time.Duration(req.TTLS) * time.Second

	// 5. The human.
	areq := approve.ApprovalRequest{
		Kind:           approve.KindStandingGrant,
		Caller:         label,
		Cwd:            cwd,
		Argv:           slices.Clone(req.Argv),
		Secrets:        slices.Clone(req.Secrets),
		Expanded:       slices.Clone(names),
		PolicyPresent:  pol.Present(),
		GrantCmdPrefix: slices.Clone(req.Argv),
		GrantCwdPrefix: cwd,
		RequestedTTL:   ttl,
		RequestedUses:  req.Uses,
	}
	dec, err := b.ask(ctx, areq)
	switch {
	case err != nil && ctx.Err() != nil:
		refuse(audit.DecisionError, proto.ErrFailed, ctxFailure(ctx), "while waiting for approval")
		return
	case err != nil:
		b.log.Warn("approver failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrDenied, proto.ReasonApproverUnavailable, "")
		return
	case dec.Allow && dec.TTL != ttl:
		// Only the exact grant that was shown may be created.
		b.log.Warn("approver answered a standing grant with a different duration", "asked", ttl.String(), "got", dec.TTL.String())
		dec = approve.Decision{Reason: "approver did not confirm the requested duration"}
	}
	if !dec.Allow {
		reason := dec.Reason
		if reason == "" {
			reason = "denied"
		}
		e := rc.entry
		e.Decision, e.Reason, e.Duration = audit.DecisionDeniedUser, "standing grant: "+reason, b.now().Sub(rc.started)
		r := daemon.Failure(proto.ErrDenied, proto.ReasonUserDenied)
		r.AuditID = b.record(ctx, e)
		_ = w.Finish(r)
		return
	}

	// 6. Store what was shown, then audit it.
	stored, err := b.d.Grants.Add(ctx, grant.NewStanding(areq, b.now()))
	switch {
	case errors.Is(err, grant.ErrInvalidGrant):
		badRequest(err.Error())
		return
	case err != nil:
		b.log.Error("storing standing grant failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, proto.ReasonInternal, "")
		return
	}
	e := rc.entry
	e.Decision, e.Reason, e.GrantID, e.Duration = audit.DecisionAllowedNewGrant, ReasonStanding, stored.ID, b.now().Sub(rc.started)
	id, err := b.recordStrict(ctx, e)
	if err != nil {
		b.log.Error("audit append failed; revoking the new standing grant", "err", err.Error())
		if rerr := b.d.Grants.Revoke(context.WithoutCancel(ctx), stored.ID); rerr != nil {
			b.log.Error("could not revoke unaudited standing grant", "grant_id", stored.ID, "err", rerr.Error())
		}
		fail(w, proto.ErrFailed, proto.ReasonInternal, "audit log unavailable")
		return
	}
	raw, err := proto.NewResult(grantInfo(*stored))
	if err != nil {
		fail(w, proto.ErrFailed, proto.ReasonInternal, "internal error")
		return
	}
	_ = w.Finish(&proto.Response{OK: true, GrantID: stored.ID, AuditID: id, Result: raw})
}

// standingCeiling is the longest standing grant allowed under pol and where
// that limit comes from, for the error message. A policy can only lower the
// global ceiling.
func standingCeiling(pol *policy.Policy) (time.Duration, string) {
	ceiling, source := grant.MaxStandingGrantTTL, "daemon maximum"
	if d, ok := pol.MaxStandingGrantTTL(); ok && d < ceiling {
		ceiling, source = d, "max_standing_grant_ttl in "+pol.Path()
	}
	return ceiling, source
}

// spanText renders whole seconds as days, hours, minutes and seconds ("90d",
// "1d12h", "45m", "30s"); zero units are omitted.
func spanText(secs int64) string {
	const day = 24 * 60 * 60
	var sb strings.Builder
	if d := secs / day; d > 0 {
		fmt.Fprintf(&sb, "%dd", d)
	}
	secs %= day
	if h := secs / 3600; h > 0 {
		fmt.Fprintf(&sb, "%dh", h)
	}
	secs %= 3600
	if m := secs / 60; m > 0 {
		fmt.Fprintf(&sb, "%dm", m)
	}
	if s := secs % 60; s > 0 || sb.Len() == 0 {
		fmt.Fprintf(&sb, "%ds", s)
	}
	return sb.String()
}

// grantInfo is the wire form of a stored grant.
func grantInfo(g grant.Grant) proto.GrantInfo {
	return proto.GrantInfo{
		ID: g.ID, Caller: g.Caller, CwdPrefix: g.CwdPrefix, Secrets: g.Secrets,
		CmdPrefix: g.CmdPrefix, ExpiresAt: g.ExpiresAt, UsesRemaining: g.UsesRemaining,
		CreatedAt: g.CreatedAt, Standing: g.Standing, Tampered: g.Tampered,
	}
}
