//go:build !unix

package runner

import (
	"errors"
	"os"
	"syscall"
)

// Process groups and POSIX signals are not implemented off Unix in v0.1
// (HANDOFF §2); Run reports ErrUnsupported there.
const supported = false

func sysProcAttr() *syscall.SysProcAttr { return nil }

func signalGroup(pid int, sig os.Signal) error { return errors.New("runner: unsupported platform") }

func sigTerm() os.Signal { return os.Interrupt }
func sigKill() os.Signal { return os.Kill }

func exitStatus(ps *os.ProcessState) (int, bool) { return ps.ExitCode(), false }
