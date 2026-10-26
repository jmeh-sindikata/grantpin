package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jmeh-sindikata/grantd/internal/approve"
	"github.com/jmeh-sindikata/grantd/internal/audit"
	"github.com/jmeh-sindikata/grantd/internal/daemon"
	"github.com/jmeh-sindikata/grantd/internal/grant"
	"github.com/jmeh-sindikata/grantd/internal/policy"
	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/runner"
	"github.com/jmeh-sindikata/grantd/internal/vault"
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
	// The entry is built from the raw request, which is untrusted and may be
	// megabytes (validateRun has not run yet): record capped copies, so that a
	// request refused as too large does not make the audit log carry it.
	rc := &runCtx{b: b, w: w, started: b.now(), entry: audit.Capped(audit.Entry{
		TS: b.now(), Caller: caller, Cwd: req.Cwd, Argv: req.Argv, Secrets: req.Secrets,
	})}
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

	// 3. Names (one expansion, nothing decrypted), env names, then expiry and
	// tier. CheckNames decrypts each secret once to authenticate its metadata
	// and discards the plaintext: values are decrypted again, for the release,
	// only after a grant or the human has approved (see release).
	names, err := b.d.Vault.ExpandNames(ctx, req.Secrets)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	rc.entry.Expanded = names // every row from here on records what the globs meant
	envNames, err := runner.EnvNames(names, req.EnvPrefix)
	if err != nil {
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
		return
	}
	required, err := b.d.Vault.CheckNames(ctx, names, b.now())
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
		decision, grantID = b.approveRun(ctx, rc, req, pol, caller, cwd, names)
		if decision == "" {
			return // approveRun already responded
		}
	default:
		b.log.Error("grant match failed", "err", err.Error())
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, proto.ReasonInternal, "")
		return
	}

	// 6. Release.
	b.release(ctx, rc, req, cwd, names, envNames, decision, grantID)
}

// runLookupFailure maps a vault lookup error during a run to a response.
func (b *Broker) runLookupFailure(ctx context.Context, rc *runCtx, err error) {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		rc.refuse(ctx, audit.DecisionError, proto.ErrNotFound, proto.ReasonSecretNotFound, err.Error())
	case errors.Is(err, vault.ErrExpired):
		rc.refuse(ctx, audit.DecisionError, proto.ErrRefused, proto.ReasonSecretExpired,
			strings.TrimPrefix(err.Error(), vault.ErrExpired.Error()+": "))
	case errors.Is(err, vault.ErrInvalidName):
		rc.refuse(ctx, audit.DecisionError, proto.ErrBadRequest, proto.ReasonBadRequest, err.Error())
	case ctx.Err() != nil:
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, CtxFailure(ctx), "")
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
	case !callerOK:
		return "", "invalid caller label"
	case len(req.Argv) == 0 || req.Argv[0] == "":
		return "", "argv must not be empty"
	case len(req.Argv) > maxArgv:
		return "", "argv too long"
	case argvBytes(req.Argv) > maxArgvBytes:
		return "", "argv too large"
	case hasControl(true, req.Argv...):
		return "", "argv must not contain control characters other than newline, carriage return and tab"
	case hasControl(false, req.Cwd, req.Caller):
		return "", "cwd and caller must not contain control characters"
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

// hasControl reports whether any string contains a byte below 0x20 other than
// a tab (or, with allowNL, a newline or carriage return, which multi-line
// `sh -c` scripts legitimately carry). Such bytes could forge lines in the
// audit listing and logs; the approval prompt and `grantd audit` sanitise what
// they print, and the daemon log no longer contains argv.
func hasControl(allowNL bool, ss ...string) bool {
	for _, s := range ss {
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 && c != '\t' && !(allowNL && (c == '\n' || c == '\r')) {
				return true
			}
		}
	}
	return false
}

func argvBytes(argv []string) int {
	n := 0
	for _, a := range argv {
		n += len(a)
	}
	return n
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
func (b *Broker) approveRun(ctx context.Context, rc *runCtx, req *proto.Request, pol *policy.Policy, caller, cwd string, names []string) (decision, grantID string) {
	// The dialog offers the repo policy's max_grant_ttl, but never more than
	// grant.MaxDialogGrantTTL: it is the prompt an agent can trigger at will.
	// Without a policy it offers the daemon default (1h). The same value caps
	// the grant the answer creates. Standing grants are a different path
	// (handleGrantAdd) and are not limited by max_grant_ttl.
	suggested := min(b.d.DefaultGrantTTL, grant.MaxDialogGrantTTL)
	if pol.Present() {
		suggested = min(pol.MaxGrantTTL(), grant.MaxDialogGrantTTL)
	}
	maxTTL := suggested
	areq := approve.ApprovalRequest{
		Kind:          approve.KindRelease,
		Caller:        caller,
		Cwd:           cwd,
		Argv:          slices.Clone(req.Argv),
		Secrets:       slices.Clone(req.Secrets),
		Expanded:      slices.Clone(names),
		PolicyPresent: pol.Present(),
		SuggestedTTL:  suggested,
	}
	// Show exactly what "Allow for N" will store, taken from the same function
	// that builds the grant.
	scope := grant.FromDecision(areq, suggested, maxTTL, matchedPrefix(pol, req.Argv), b.now())
	areq.GrantCmdPrefix = slices.Clone(scope.CmdPrefix)
	areq.GrantCwdPrefix = scope.CwdPrefix
	dec, err := b.ask(ctx, areq)
	switch {
	case err != nil && ctx.Err() != nil:
		rc.refuse(ctx, audit.DecisionError, proto.ErrFailed, CtxFailure(ctx), "while waiting for approval")
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

// ReasonReleased marks the audit row written once plaintext has left the vault
// and before the command is started.
const ReasonReleased = "released"

// release resolves the secrets, writes the pre-spawn audit row, runs the
// command and answers. A started release is bracketed in the audit log: an
// allowed_* row (reason "released", no exit code) written after the secrets
// are decrypted but before the command is spawned, then exactly one
// "completed" row when the command ends. Both rows are scrubbed with the
// redactor built from the resolved values. A failure before the released row
// (resolve) leaves a single "error" row; if the released row cannot be written
// the plaintext is zeroed, nothing is spawned and no completed row follows. A
// release under a finite-use grant takes its use (Grants.Consume) right after
// the released row is written; if the use is gone by then (a concurrent run
// took it, or the grant was revoked) a completed row closes the bracket and
// nothing is spawned.
//
// Secrets are decrypted twice per run, on purpose: CheckNames (before any
// grant or prompt) decrypts and discards each value to authenticate its tier
// and expiry, and release decrypts again only once the release is approved, so
// no plaintext exists while a human is deciding.
func (b *Broker) release(ctx context.Context, rc *runCtx, req *proto.Request, cwd string, names []string, envNames map[string]string, decision, grantID string) {
	rc.entry.GrantID = grantID
	values, err := b.d.Vault.ResolveNames(ctx, names)
	if err != nil {
		b.runLookupFailure(ctx, rc, err)
		return
	}
	defer func() {
		for _, v := range values {
			vault.Zero(v)
		}
	}()
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

	rel := rc.entryNow()
	rel.Decision, rel.Reason = decision, ReasonReleased
	if _, err := b.recordStrict(ctx, rel); err != nil {
		b.log.Error("audit append failed; not starting command", "err", err.Error())
		fail(rc.w, proto.ErrFailed, proto.ReasonInternal, "audit log unavailable")
		return
	}

	if b.afterReleased != nil {
		b.afterReleased()
	}
	// A finite-use grant pays for this release only now that the released row
	// is on record and nothing has been spawned yet: a request that matched but
	// failed to resolve above costs no use. If a concurrent run took the last
	// use (or the grant was revoked) since Match, close the bracket and stop.
	if decision == audit.DecisionAllowedGrant {
		switch err := b.d.Grants.Consume(ctx, grantID); {
		case err == nil:
		case errors.Is(err, grant.ErrExhausted), errors.Is(err, grant.ErrNotFound):
			rc.completeFailure(ctx, grantID, proto.ErrDenied, proto.ReasonNoGrant, "grant no longer usable")
			return
		case ctx.Err() != nil:
			rc.completeFailure(ctx, grantID, proto.ErrFailed, CtxFailure(ctx), "")
			return
		default:
			b.log.Error("consuming grant use failed", "err", err.Error())
			rc.completeFailure(ctx, grantID, proto.ErrFailed, proto.ReasonInternal, "")
			return
		}
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	so := &frameWriter{w: rc.w, stream: proto.StreamStdout, onErr: cancelRun}
	se := &frameWriter{w: rc.w, stream: proto.StreamStderr, onErr: cancelRun}

	spec := runner.Spec{
		Argv:      req.Argv,
		Cwd:       cwd,
		Env:       env,
		Labels:    labels,
		Timeout:   commandTimeout(ctx, req),
		KillGrace: killGrace,
	}
	// The runner redacts the output (Spec.Env + Labels); the frame writers get
	// already-redacted bytes and only hold back split UTF-8 sequences.
	res, runErr := runner.Run(runCtx, spec, so, se)
	// Flush withheld partial runes (the runner has flushed its redactors).
	_ = so.Close()
	_ = se.Close()

	exit := res.ExitCode
	resp := &proto.Response{OK: true, GrantID: grantID}
	reason := ""
	switch {
	case exit == runner.ExitNotStarted:
		// The context ending before the process existed is the caller's doing
		// (hang-up, shutdown, deadline), not an internal fault.
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(runErr, context.DeadlineExceeded):
			rc.completeFailure(ctx, grantID, proto.ErrFailed, proto.ReasonTimeout, "")
		case ctx.Err() != nil, errors.Is(runErr, context.Canceled):
			rc.completeFailure(ctx, grantID, proto.ErrFailed, proto.ReasonCanceled, "")
		default:
			rc.completeFailure(ctx, grantID, proto.ErrFailed, proto.ReasonInternal, "command could not be started: "+errText(runErr))
		}
		return
	case res.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded):
		exit = runner.ExitTimeout
		reason = proto.ReasonTimeout
		resp.Reason = proto.ReasonTimeout
	case ctx.Err() != nil || runCtx.Err() != nil:
		reason = proto.ReasonCanceled
	case errors.Is(runErr, runner.ErrCommandNotFound):
		reason = "command not found"
		resp.Message = "command not found: " + rc.scrub(req.Argv[0])
	case errors.Is(runErr, runner.ErrCannotExecute):
		reason = "cannot execute command"
		resp.Message = "cannot execute command: " + rc.scrub(req.Argv[0])
	}
	e := rc.entryNow()
	e.Decision, e.Reason, e.Duration, e.ExitCode = audit.DecisionCompleted, reason, res.Duration, &exit
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

// completeFailure closes the audit bracket for a release whose command could
// not be started: a completed row with no exit code and the cause as its
// reason ("canceled" or "timeout" when the context ended first, otherwise
// "not started: <reason>").
func (rc *runCtx) completeFailure(ctx context.Context, grantID, category, reason, msg string) {
	msg = rc.scrub(msg)
	e := rc.entryNow()
	e.Decision = audit.DecisionCompleted
	e.Reason = "not started: " + reason
	if reason == proto.ReasonCanceled || reason == proto.ReasonTimeout {
		e.Reason = reason
	}
	if msg != "" {
		e.Reason += ": " + msg
	}
	e.Duration = rc.b.now().Sub(rc.started)
	r := daemon.Failure(category, reason)
	r.Message = msg
	r.GrantID = grantID
	r.AuditID = rc.b.record(ctx, e)
	_ = rc.w.Finish(r)
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

// frameWriter forwards output that the runner has already redacted as stream
// frames. It holds back an
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

// commandTimeout is the budget for the command alone. The daemon's connection
// deadline also covers the wait for human approval (ApprovalGrace), so the
// command's timeout comes from CommandTimeout, which excludes it. Without a
// daemon context (unit tests) the request's own timeout_s is used.
func commandTimeout(ctx context.Context, req *proto.Request) time.Duration {
	if d, ok := daemon.CommandTimeout(ctx); ok {
		return d
	}
	return time.Duration(req.TimeoutS) * time.Second
}
