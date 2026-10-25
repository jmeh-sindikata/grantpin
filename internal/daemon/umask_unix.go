//go:build !windows

package daemon

import (
	"sync"
	"syscall"
)

// umaskMu serialises the process-wide umask change around Listen.
var umaskMu sync.Mutex

// restrictiveUmask sets umask 0177 (so the socket is created 0600) and returns
// the function that restores the previous value.
func restrictiveUmask() (restore func()) {
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	return func() {
		syscall.Umask(old)
		umaskMu.Unlock()
	}
}
