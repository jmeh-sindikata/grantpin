//go:build linux

package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective UID of the process that connected c, via
// SO_PEERCRED.
func peerUID(c *net.UnixConn) (uint32, error) {
	var uid uint32
	err := controlFD(c, func(fd int) error {
		cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return err
		}
		uid = cred.Uid
		return nil
	})
	return uid, err
}
