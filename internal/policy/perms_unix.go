//go:build unix

package policy

import (
	"os"
	"syscall"
)

// checkOwnerAndMode refuses policy files that someone else could have
// planted or edited: owned by another uid, or writable by "other".
// DECISION (conservative): ownership is required even if the file is
// otherwise safe. Group-writable files are allowed.
func checkOwnerAndMode(path string, info os.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != currentUID() {
		return &InsecurePolicyError{Path: path, Reason: "not owned by the current user"}
	}
	if info.Mode().Perm()&0o002 != 0 {
		return &InsecurePolicyError{Path: path, Reason: "world-writable"}
	}
	return nil
}
