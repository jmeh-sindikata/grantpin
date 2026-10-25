package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	"grantd/internal/approve"
	"grantd/internal/audit"
	"grantd/internal/daemon"
	"grantd/internal/grant"
	"grantd/internal/policy"
	"grantd/internal/proto"
	"grantd/internal/runner"
	"grantd/internal/vault"
)

// killGrace is the SIGTERM->SIGKILL delay. It is shorter than the daemon's
// default handler grace (5s) so that a command that ignores SIGTERM after a
// timeout is still reported by us (exit 124) and not abandoned.
const killGrace = 2 * time.Second

// runCtx is the per-request state of a run, used to write audit entries.
type runCtx struct {
	b       *Broker
	w       daemon.ResponseWriter
	entry   audit.Entry // identity part of the audit entry
	redact  *runner.Redactor
	started time.Time
}

// refuse audits and sends a non-OK response for a run that never released
// anything.
func (rc *runCtx) refuse(ctx context.Context, decision, category, reason, msg string) {
	msg = rc.scrub(msg)
	e := rc.entryNow()
	e.Decision = decision
	e.Reason = reason
	if msg != "" {
		e.Reason = reason + ": " + msg
	}
	e.Duration = rc.b.now().Sub(rc.started)
	id := rc.b.record(ctx, e)
	r := daemon.Failure(category, reason)
	r.Message = msg
	r.AuditID = id
	_ = rc.w.Finish(r)
}

func (b *Broker) handleRun(ctx context.Context, req *proto.Request, w daemon.ResponseWriter) {
	caller, callerOK := callerOf(req)
	rc := &runCtx{b: b, w: w, started: b.now(), entry: audit.Entry{
		TS: b.now(), Caller: caller, Cwd: req.Cwd, Argv: req.Argv, Secrets: req.Secrets,
	}}
	if !callerOK {
		rc.entry.Caller = "(invalid)"
	}

	// 1. Validate.
	cwd, msg := validateRun(req, callerOK)
	if msg != "" {
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, msg)
		return
	}
	rc.entry.Cwd = cwd

	// 2. Policy.
	pol, err := policy.Load(cwd)
	if err != nil {
		rc.refuse(ctx, audit.DecisionRefusedPolicy, proto.ErrRefused, proto.ReasonPolicyRefused, err.Error())
		return
	}
	if pol.Present() {
		if err := pol.Check(req.Secrets, req.Argv); err != nil {
			rc.refuse(ctx, audit.DecisionRefusedPolicy, proto.ErrRefused, proto.ReasonPolicyRefused, policyItem(err))
			return
		}
	}

	// 3. Names, env names, expiry, tier.
	names, err := b.d.Vault.ExpandNames(ctx, req.Secrets)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	if _, err := runner.EnvNames(names, req.EnvPrefix); err != nil {
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
		return
	}
	for _, n := range names {
		m, err := b.d.Vault.Get(ctx, n)
		if err != nil {
			b.runLookupFailure(ctx, rc, err)
			return
		}
		if m.Expired(b.now()) {
			rc.refuse(ctx, audit.DecisionError, proto.ErrRefused, proto.ReasonSecretExpired, n)
			return
		}
	}
	required, err := b.d.Vault.MinTierFor(ctx, names)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	if met, why := b.tierMet(required); !met {
		rc.refuse(ctx, audit.DecisionRefusedTier, proto.ErrRefused, proto.ReasonTierUnmet, why)
		return
	}

	// 4. Existing grant? Matched on the textual secrets list.
	decision := ""
	grantID := ""
	switch g, err := b.d.Grants.Match(ctx, grant.Query{
		Caller: caller, Cwd: cwd, Secrets: req.Secrets, Argv: req.Argv, Now: b.now(),
	}); {
	case err == nil:
		decision, grantID = audit.DecisionAllowedGrant, g.ID
	case errors.Is(err, grant.ErrNoMatch):
		// 5. Ask the human.
		decision, grantID = b.approveRun(ctx, rc, req, pol, caller, cwd)
		if decision == "" {
			return // approveRun already responded
		}
	default:
		b.log.Error("grant match failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, proto.ReasonInternal, "")
		return
	}

	// 6. Release.
	b.release(ctx, rc, req, cwd, names, decision, grantID)
}

// runLookupFailure maps a vault lookup error during a run to a response.
func (b *Broker) runLookupFailure(ctx context.Context, rc *runCtx, err error) {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		rc.refuse(ctx, audit.DecisionError, proto.ErrNotFound, proto.ReasonSecretNotFound, err.Error())
	case errors.Is(err, vault.ErrExpired):
		rc.refuse(ctx, audit.DecisionError, proto.ErrRefused, proto.ReasonSecretExpired, "")
	case errors.Is(err, vault.ErrInvalidName):
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
	case ctx.Err() != nil:
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, ctxFailure(ctx), "")
	default:
		b.log.Error("vault lookup failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, proto.ReasonInternal, "")
	}
}

// validateRun checks the structural requirements of a run request and returns
// the cleaned, symlink-resolved working directory. A non-empty message means
// the request is malformed.
func validateRun(req *proto.Request, callerOK bool) (cwd, msg string) {
	switch {
	case req.V != proto.Version:
		return "", "unsupported protocol version"
	case !callerOK:
		return "", "invalid caller label"
	case len(req.Argv) == 0 || req.Argv[0] == "":
		return "", "argv must not be empty"
	case len(req.Argv) > maxArgv:
		return "", "argv too long"
	case len(req.Secrets) == 0:
		return "", "secrets must not be empty"
	case len(req.Secrets) > maxSecrets:
		return "", "too many secrets"
	case !filepath.IsAbs(req.Cwd):
		return "", "cwd must be an absolute path"
	}
	for _, s := range req.Secrets {
		if s == "" {
			return "", "empty secret name"
		}
	}
	// Resolve symlinks so that policy lookup, grants and the prompt all see the
	// directory the command will really run in.
	real, err := filepath.EvalSymlinks(filepath.Clean(req.Cwd))
	if err != nil {
		return "", "cwd does not exist"
	}
	if st, err := os.Stat(real); err != nil || !st.IsDir() {
		return "", "cwd is not a directory"
	}
	return real, ""
}

// policyItem names what a policy refused, never a value.
func policyItem(err error) string {
	var se *policy.SecretNotAllowedError
	var ce *policy.CommandNotAllowedError
	switch {
	case errors.As(err, &se):
		return "secret not allowed by policy: " + se.Secret
	case errors.As(err, &ce):
		cmd := ""
		if len(ce.Argv) > 0 {
			cmd = ce.Argv[0]
		}
		return "command not allowed by policy: " + cmd
	default:
		return err.Error()
	}
}

// approveRun asks the human (serialised). It returns the audit decision and
// grant ID to proceed with, or an empty decision after having responded.
func (b *Broker) approveRun(ctx context.Context, rc *runCtx, req *proto.Request, pol *policy.Policy, caller, cwd string) (decision, grantID string) {
	suggested := b.d.DefaultGrantTTL
	maxTTL := b.d.DefaultGrantTTL
	if pol.Present() {
		suggested = min(suggested, pol.MaxGrantTTL())
		maxTTL = pol.MaxGrantTTL()
	}
	areq := approve.ApprovalRequest{
		Caller:        caller,
		Cwd:           cwd,
		Argv:          slices.Clone(req.Argv),
		Secrets:       slices.Clone(req.Secrets),
		PolicyPresent: pol.Present(),
		SuggestedTTL:  suggested,
	}
	dec, err := b.ask(ctx, areq)
	switch {
	case err != nil && ctx.Err() != nil:
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, ctxFailure(ctx), "while waiting for approval")
		return "", ""
	case err != nil:
		b.log.Warn("approver failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrDenied, proto.ReasonApproverUnavailable, "")
		return "", ""
	case !dec.Allow:
		reason := dec.Reason
		if reason == "" {
			reason = "denied"
		}
		e := rc.entry
		e.Decision, e.Reason, e.Duration = audit.DecisionDeniedUser, reason, b.now().Sub(rc.started)
		id := b.record(ctx, e)
		r := daemon.Failure(proto.ErrDenied, proto.ReasonUserDenied)
		r.AuditID = id
		_ = rc.w.Finish(r)
		return "", ""
	case dec.TTL <= 0:
		return audit.DecisionAllowedOnce, ""
	}
	g := grant.FromDecision(areq, dec.TTL, maxTTL, matchedPrefix(pol, req.Argv), b.now())
	stored, err := b.d.Grants.Add(ctx, g)
	if err != nil {
		b.log.Error("storing grant failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, proto.ReasonInternal, "")
		return "", ""
	}
	return audit.DecisionAllowedNewGrant, stored.ID
}

// matchedPrefix returns the longest policy command prefix that argv starts
// with, or nil (grant.FromDecision then scopes the grant to the full argv).
func matchedPrefix(pol *policy.Policy, argv []string) []string {
	if !pol.Present() {
		return nil
	}
	var best []string
	for _, c := range pol.Commands() {
		if len(c) > len(best) && len(c) <= len(argv) && slices.Equal(c, argv[:len(c)]) {
			best = c
		}
	}
	return best
}

// release resolves the secrets, runs the command and answers.
func (b *Broker) release(ctx context.Context, rc *runCtx, req *proto.Request, cwd string, names []string, decision, grantID string) {
	rc.entry.GrantID = grantID
	values, err := b.d.Vault.Resolve(ctx, names)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	defer func() {
		for _, v := range values {
			zero(v)
		}
	}()
	envNames, err := runner.EnvNames(names, req.EnvPrefix)
	if err != nil {
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
		return
	}
	// Plaintext as strings is required by runner.Spec; Go cannot zero these.
	env := make(map[string]string, len(values))
	labels := make(map[string]string, len(values))
	byName := make(map[string]string, len(values))
	for name, v := range values {
		env[envNames[name]] = string(v)
		labels[envNames[name]] = name
		byName[name] = string(v)
	}
	rc.redact = runner.NewRedactor(byName)

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	so := &frameWriter{w: rc.w, stream: proto.StreamStdout, onErr: cancelRun}
	se := &frameWriter{w: rc.w, stream: proto.StreamStderr, onErr: cancelRun}
	rso := runner.NewRedactingWriter(so, byName)
	rse := runner.NewRedactingWriter(se, byName)

	spec := runner.Spec{
		Argv:      req.Argv,
		Cwd:       cwd,
		Env:       env,
		Labels:    labels,
		Timeout:   time.Duration(req.TimeoutS) * time.Second,
		KillGrace: killGrace,
	}
	res, runErr := runner.Run(runCtx, spec, rso, rse)
	// Flush withheld bytes (redacting writers first, then partial runes).
	_ = rso.Close()
	_ = rse.Close()
	_ = so.Close()
	_ = se.Close()

	e := rc.entryNow()
	e.Decision = decision
	e.Duration = res.Duration
	exit := res.ExitCode
	resp := &proto.Response{OK: true, GrantID: grantID}
	switch {
	case exit == runner.ExitNotStarted:
		e.Decision = audit.DecisionError
		e.Reason = rc.scrub("run failed: " + errText(runErr))
		e.Duration = b.now().Sub(rc.started)
		resp = daemon.Failure(proto.ErrFailed, proto.ReasonInternal)
		resp.Message = "command could not be started"
		if ctx.Err() != nil {
			resp.Reason = ctxFailure(ctx)
		}
		resp.AuditID = b.record(ctx, e)
		resp.GrantID = grantID
		_ = rc.w.Finish(resp)
		return
	case res.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded):
		exit = runner.ExitTimeout
		e.Reason = proto.ReasonTimeout
		resp.Reason = proto.ReasonTimeout
	case ctx.Err() != nil || runCtx.Err() != nil:
		e.Reason = proto.ReasonCanceled
	case errors.Is(runErr, runner.ErrCommandNotFound):
		e.Reason = "command not found"
		resp.Message = "command not found: " + rc.scrub(req.Argv[0])
	case errors.Is(runErr, runner.ErrCannotExecute):
		e.Reason = "cannot execute command"
		resp.Message = "cannot execute command: " + rc.scrub(req.Argv[0])
	}
	e.ExitCode = &exit
	resp.ExitCode = proto.IntPtr(exit)
	resp.AuditID = b.record(ctx, e)
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// Client went away or the daemon is stopping: tell whoever is left.
		f := daemon.Failure(proto.ErrFailed, proto.ReasonCanceled)
		f.AuditID, f.GrantID = resp.AuditID, grantID
		_ = rc.w.Finish(f)
		return
	}
	_ = rc.w.Finish(resp)
}

// entryNow returns the audit identity with injected values removed from argv
// (a caller could have put one there), once a redactor exists.
func (rc *runCtx) entryNow() audit.Entry {
	e := rc.entry
	if rc.redact != nil {
		e.Argv = make([]string, len(rc.entry.Argv))
		for i, a := range rc.entry.Argv {
			e.Argv[i] = rc.redact.RedactString(a)
		}
	}
	return e
}

// scrub removes injected values from text that is about to leave the process.
func (rc *runCtx) scrub(s string) string {
	if rc.redact == nil {
		return s
	}
	return rc.redact.RedactString(s)
}

func errText(err error) string {
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

// frameWriter forwards redacted output as stream frames. It holds back an
// incomplete trailing UTF-8 sequence so that a multibyte character split across
// reads is not mangled by JSON encoding. A failed write (client gone) cancels
// the run via onErr and is sticky.
type frameWriter struct {
	w      daemon.ResponseWriter
	stream string
	carry  []byte
	err    error
	onErr  func()
}

func (f *frameWriter) Write(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	buf := append(f.carry, p...)
	cut := len(buf) - incompleteTail(buf)
	f.carry = append([]byte(nil), buf[cut:]...)
	if cut > 0 {
		if err := f.w.Stream(f.stream, buf[:cut]); err != nil {
			f.err = err
			f.onErr()
			return 0, err
		}
	}
	return len(p), nil
}

// Close flushes any held-back bytes.
func (f *frameWriter) Close() error {
	if f.err != nil || len(f.carry) == 0 {
		return f.err
	}
	c := f.carry
	f.carry = nil
	if err := f.w.Stream(f.stream, c); err != nil {
		f.err = err
		return err
	}
	return nil
}

// incompleteTail returns how many trailing bytes of b form the start of a
// multibyte rune that is not complete yet.
func incompleteTail(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax+1; i-- {
		if utf8.RuneStart(b[i]) {
			if utf8.FullRune(b[i:]) {
				return 0
			}
			return len(b) - i
		}
	}
	return 0
}
