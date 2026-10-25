//go:build darwin

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION from <sys/ucred.h>; x/sys does not export it.
const xucredVersion = 0

// peerUID returns the effective UID of the process that connected c, via
// LOCAL_PEERCRED.
func peerUID(c *net.UnixConn) (uint32, error) {
	var uid uint32
	err := controlFD(c, func(fd int) error {
		cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return err
		}
		if cred.Version != xucredVersion {
			return fmt.Errorf("unexpected xucred version %d", cred.Version)
		}
		uid = cred.Uid
		return nil
	})
	return uid, err
}
