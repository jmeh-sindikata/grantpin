//go:build unix

package runner

import (
	"errors"
	"os"
	"syscall"
)

const supported = true

// sysProcAttr puts the child in its own process group (pgid == pid) so that
// timeouts, cancellation and forwarded signals reach the whole process tree.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// signalGroup sends sig to every process in the child's process group.
func signalGroup(pid int, sig os.Signal) error {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("runner: unsupported signal type")
	}
	return syscall.Kill(-pid, s)
}

func sigTerm() os.Signal { return syscall.SIGTERM }
func sigKill() os.Signal { return syscall.SIGKILL }

// exitStatus decodes a finished process into the shell-style exit code.
func exitStatus(ps *os.ProcessState) (code int, signaled bool) {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true
	}
	return ps.ExitCode(), false
}
