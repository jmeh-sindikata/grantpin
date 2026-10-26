//go:build unix

package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ExecStarter returns a Starter that spawns `<this executable> daemon
// [--socket path]` detached in its own session, with stdin/stdout/stderr on
// /dev/null. When socketPath is non-empty it is passed as --socket (never via
// the environment).
//
// The child gets a minimal, allow-listed environment (locating HOME and PATH
// only). Nothing from the shim's environment that could carry secrets or
// configuration, notably GRANTD_*, is forwarded.
func ExecStarter(socketPath string) Starter {
	return func(ctx context.Context) error {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		args := []string{"daemon"}
		if socketPath != "" {
			args = append(args, "--socket", socketPath)
		}
		_, err = spawnDetached(exe, args)
		return err
	}
}

// spawnDetached starts exe in its own session with stdio on /dev/null and the
// allow-listed environment, and returns its pid. The shim is long-lived, so
// the child is reaped in the background: without that, a daemon that exits
// stays a zombie until the shim does, one more per retry.
func spawnDetached(exe string, args []string) (int, error) {
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devnull.Close()
	// Not CommandContext: the daemon must outlive this tool call.
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.Env = daemonEnv(os.Getenv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn daemon: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}
