package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"grantd/internal/approve"
)

// osascriptPath is absolute on purpose: no PATH lookup, so nothing the agent
// puts earlier on PATH can substitute for it.
const osascriptPath = "/usr/bin/osascript"

// Button labels. Exact-string compared when parsing the dialog result.
const (
	buttonDeny      = "Deny"
	buttonAllowOnce = "Allow once"
	dialogTitle     = "grantd"
)

// chooserScript is a CONSTANT. Nothing from the request is ever interpolated
// into AppleScript source (the dialog gives up after 120s, which parses as Deny): the text and the optional third button label arrive
// as run-handler arguments (argv items 1 and 2).
const chooserScript = `on run argv
	set theText to item 1 of argv
	set forLabel to item 2 of argv
	set btns to {"Deny", "Allow once"}
	if forLabel is not "" then set btns to {"Deny", "Allow once", forLabel}
	set r to display dialog theText with title "grantd" buttons btns default button "Deny" cancel button "Deny" with icon caution giving up after 120
	return r
end run`

// choice is what the human picked in the chooser dialog.
type choice int

const (
	choiceDeny choice = iota // also: timeout, cancel, anything unparseable
	choiceOnce
	choiceFor
)

// ErrChooserFailed means the dialog process failed for a reason other than the
// user cancelling (osascript missing, no window server, killed, ...). No
// decision was made; Ask never treats this as an allow.
var ErrChooserFailed = errors.New("darwin approver: choice dialog failed")

// execFunc runs a program and returns its stdout, stderr and exit code. err is
// non-nil only when the program could not be run or was killed (a non-zero exit
// is reported through the code, with err == nil).
type execFunc func(ctx context.Context, path string, args []string) (stdout, stderr []byte, code int, err error)

// chooser shows the three-way dialog via osascript.
type chooser struct {
	exec execFunc
}

func newChooser() *chooser { return &chooser{exec: realExec} }

// allowForLabel is the third button's label, or "" when there is no TTL to offer.
func allowForLabel(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	return "Allow for " + formatTTL(ttl)
}

// dialogArgs builds the osascript argument vector. The `--` ends option
// parsing, and the text starts with trusted fixed words, so an untrusted caller
// string such as "-e" can never be read as an osascript option.
func dialogArgs(req approve.ApprovalRequest, ttl time.Duration) []string {
	text := "An agent is asking grantd to release secrets:\n\n" + BuildReason(req, 0)
	if scope := GrantScope(req, ttl); scope != "" {
		text += "\n\n" + scope + "."
	} else if ttl > 0 {
		text += "\n\n\"" + allowForLabel(ttl) + "\" lets the same request run again for that long."
	}
	return []string{"-e", chooserScript, "--", text, allowForLabel(ttl)}
}

// ask shows the dialog and returns the human's choice. ttl is the duration the
// third button offers (0 = no third button). A user cancel, timeout or any
// unexpected output is choiceDeny with a nil error.
func (c *chooser) ask(ctx context.Context, req approve.ApprovalRequest, ttl time.Duration) (choice, error) {
	if err := ctx.Err(); err != nil {
		return choiceDeny, err
	}
	stdout, stderr, code, err := c.exec(ctx, osascriptPath, dialogArgs(req, ttl))
	if cerr := ctx.Err(); cerr != nil {
		return choiceDeny, cerr
	}
	if err != nil {
		return choiceDeny, fmt.Errorf("%w: %v", ErrChooserFailed, err)
	}
	if code != 0 {
		if strings.Contains(string(stderr), "(-128)") { // errAEUserCanceled: the Deny/cancel button
			return choiceDeny, nil
		}
		return choiceDeny, fmt.Errorf("%w: osascript exit %d: %s", ErrChooserFailed, code, clean(truncateMiddle(string(stderr), 200)))
	}
	return parseChoice(string(stdout), allowForLabel(ttl)), nil
}

// parseChoice parses osascript's rendering of the display-dialog record,
//
//	button returned:Allow once, gave up:false
//
// Only an exact "button returned" label with "gave up:false" allows; every
// other shape is a Deny.
func parseChoice(stdout, forLabel string) choice {
	s := strings.TrimRight(stdout, "\r\n")
	const prefix = "button returned:"
	const sep = ", gave up:"
	if !strings.HasPrefix(s, prefix) {
		return choiceDeny
	}
	rest := s[len(prefix):]
	i := strings.LastIndex(rest, sep)
	if i < 0 || rest[i+len(sep):] != "false" {
		return choiceDeny
	}
	switch button := rest[:i]; {
	case button == buttonAllowOnce:
		return choiceOnce
	case forLabel != "" && button == forLabel:
		return choiceFor
	}
	return choiceDeny
}

// limitedBuffer keeps at most max bytes (the dialog output is tiny; this just
// bounds a misbehaving child).
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil // never fail the child on output size
}

// realExec runs path with a minimal environment; ctx cancellation kills it.
func realExec(ctx context.Context, path string, args []string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = minimalEnv()
	cmd.Stdin = nil
	out, errb := &limitedBuffer{max: 4096}, &limitedBuffer{max: 4096}
	cmd.Stdout, cmd.Stderr = out, errb
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ctx.Err() == nil {
		return out.buf.Bytes(), errb.buf.Bytes(), ee.ExitCode(), nil
	}
	return out.buf.Bytes(), errb.buf.Bytes(), 0, err
}

func minimalEnv() []string {
	env := []string{"PATH=/usr/bin:/bin"}
	for _, k := range []string{"HOME", "USER", "LOGNAME", "LANG", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}
