package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"

	"grantd/internal/proto"
)

func newRunCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "run --secrets A,b/* [flags] -- cmd args...",
		Short: "Run a command with secrets injected as env vars (output redacted)",
		Long: `Run a command with secrets injected as environment variables. Output is
streamed back with every injected value replaced by [REDACTED:NAME].

Exit status: the command's own exit status; 124 on timeout; 77 when the
request was denied; 78 when it was refused (policy, presence tier); 69 when the
daemon is not running; 128+N when interrupted by signal N. Interrupting
grantd (SIGINT/SIGTERM) closes the connection, which makes the daemon stop the
command.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			secrets, _ := f.GetStringSlice("secrets")
			var clean []string
			for _, s := range secrets {
				if s = strings.TrimSpace(s); s != "" {
					clean = append(clean, s)
				}
			}
			if len(clean) == 0 {
				return errors.New("--secrets is required (names or globs, comma-separated)")
			}
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			req := &proto.Request{Op: proto.OpRun, Cwd: cwd, Argv: args, Secrets: clean}
			req.Caller, _ = f.GetString("caller")
			if req.Caller == "" {
				req.Caller = "cli"
			}
			req.EnvPrefix, _ = f.GetString("env-prefix")
			timeout, _ := f.GetDuration("timeout")
			if timeout < 0 {
				return errors.New("--timeout must not be negative")
			}
			if timeout > 0 {
				req.TimeoutS = int(math.Ceil(timeout.Seconds()))
			}
			return runRemote(cmd.Context(), socket, req, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	c.Flags().SetInterspersed(false) // everything after the first non-flag is the command
	c.Flags().StringSlice("secrets", nil, "secret names or globs to inject (comma-separated)")
	c.Flags().String("caller", "", "caller label recorded in grants and audit (informational)")
	c.Flags().String("env-prefix", "", "prefix for injected env var names")
	c.Flags().Duration("timeout", 0, "kill the command after this duration, e.g. 10m")
	addSocketFlag(c, &socket)
	return c
}

// runRemote performs a run op, streams output to stdout/stderr and returns an
// *exitError carrying the process exit status (nil for status 0).
//
// SIGNALS (v0.1): SIGINT/SIGTERM are not forwarded to the child as signals.
// Instead they cancel the request context, which closes the connection; the
// daemon notices the client has gone, cancels the run and the runner stops the
// child's process group (SIGTERM, then SIGKILL after a grace period). This
// satisfies the "signals forwarded" line of §8 for the interrupt/terminate case
// only; other signals (SIGHUP, SIGUSR1, SIGWINCH...) are not relayed.
func runRemote(parent context.Context, socket string, req *proto.Request, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigc)
	var got atomic.Int32
	go func() {
		select {
		case s := <-sigc:
			if ss, ok := s.(syscall.Signal); ok {
				got.Store(int32(ss))
			}
			cancel()
		case <-ctx.Done():
		}
	}()

	resp, _, err := callDaemon(ctx, socket, req, func(fr proto.StreamFrame) {
		switch fr.Stream {
		case proto.StreamStdout:
			_, _ = io.WriteString(stdout, fr.Data)
		case proto.StreamStderr:
			_, _ = io.WriteString(stderr, fr.Data)
		}
	})
	if err != nil {
		if s := got.Load(); s != 0 {
			return &exitError{code: 128 + int(s)}
		}
		return err
	}
	if !resp.OK {
		return failureError(resp)
	}
	if resp.Message != "" {
		fmt.Fprintln(stderr, "grantd:", resp.Message)
	}
	if resp.ExitCode == nil {
		return errors.New("daemon response carried no exit code")
	}
	if code := *resp.ExitCode; code != 0 {
		return &exitError{code: code}
	}
	return nil
}
