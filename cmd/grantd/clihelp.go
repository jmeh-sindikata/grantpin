package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"grantd/internal/client"
	"grantd/internal/proto"
)

// Exit codes (sysexits.h flavoured). A command run through `grantd run` exits
// with the child's own code, so these can collide with a child that happens to
// exit 77, 78 or 69; scripts that care should look at stderr.
const (
	exitDenied     = 77 // EX_NOPERM: a human or a missing grant said no
	exitRefused    = 78 // EX_CONFIG: a hard rule said no (policy, tier, tty)
	exitNotRunning = 69 // EX_UNAVAILABLE: the daemon is not running
	exitGeneric    = 1
)

// exitError makes main exit with a specific code. An empty message prints
// nothing (used to relay a child's exit status).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// exitCodeOf maps an error returned from the command tree to a process exit
// code.
func exitCodeOf(err error) int {
	var ee *exitError
	switch {
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, client.ErrNotRunning):
		return exitNotRunning
	default:
		return exitGeneric
	}
}

// addSocketFlag adds the --socket flag shared by every daemon-talking verb.
func addSocketFlag(c *cobra.Command, dst *string) {
	c.Flags().StringVar(dst, "socket", "", "socket path (default: $GRANTD_SOCKET or the platform default)")
}

// callDaemon sends req and returns the final response. A daemon that is not
// running yields an error wrapping client.ErrNotRunning with the start hint.
// A not-OK response is returned (with a nil error) so callers can inspect it;
// most callers pass it through okOrExit.
func callDaemon(ctx context.Context, socketFlag string, req *proto.Request, onStream func(proto.StreamFrame)) (*proto.Response, string, error) {
	path, err := resolveSocket(socketFlag)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Call(ctx, path, req, onStream)
	if errors.Is(err, client.ErrNotRunning) {
		return nil, path, fmt.Errorf("%w (socket %s); start it with `grantd daemon`", client.ErrNotRunning, path)
	}
	return resp, path, err
}

// failureError converts a not-OK response to an *exitError with the exit code
// for its category.
func failureError(resp *proto.Response) error {
	code := exitGeneric
	switch {
	case resp.Error == proto.ErrDenied:
		code = exitDenied
	case resp.Error == proto.ErrRefused:
		code = exitRefused
	case resp.Error == proto.ErrFailed && resp.Reason == proto.ReasonTimeout:
		code = 124
	}
	msg := resp.Error
	if resp.Reason != "" && resp.Reason != resp.Error {
		msg += " (" + resp.Reason + ")"
	}
	if resp.Message != "" {
		msg += ": " + resp.Message
	}
	return &exitError{code: code, msg: msg}
}

// simpleCall is callDaemon for ops with a plain request/response shape: a
// not-OK response becomes an error.
func simpleCall(ctx context.Context, socketFlag string, req *proto.Request) (*proto.Response, error) {
	resp, _, err := callDaemon(ctx, socketFlag, req, nil)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, failureError(resp)
	}
	return resp, nil
}

// decodeResult unmarshals resp.Result into v.
func decodeResult(resp *proto.Response, v any) error {
	if len(resp.Result) == 0 {
		return errors.New("daemon response carried no result")
	}
	return json.Unmarshal(resp.Result, v)
}

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

var durationRE = regexp.MustCompile(`^(\d+)([dw])$`)

// parseDuration is time.ParseDuration plus "Nd" (days) and "Nw" (weeks).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if m := durationRE.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n > 36500 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		unit := 24 * time.Hour
		if m[2] == "w" {
			unit = 7 * 24 * time.Hour
		}
		return time.Duration(n) * unit, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (examples: 30d, 12h, 90m)", s)
	}
	return d, nil
}

// readValue reads a secret value for `set`: a hidden prompt on a terminal,
// otherwise stdin (one trailing newline is stripped).
func readValue(in io.Reader, prompt io.Writer, name string) ([]byte, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(prompt, "Value for %s (input hidden): ", name)
		v, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(prompt)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	v, err := io.ReadAll(io.LimitReader(in, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(v) > 1<<20 {
		return nil, errors.New("value too large (limit 1 MiB)")
	}
	v = []byte(strings.TrimSuffix(strings.TrimSuffix(string(v), "\n"), "\r"))
	return v, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
