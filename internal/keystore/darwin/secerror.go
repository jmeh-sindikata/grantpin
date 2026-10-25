package darwin

import (
	"errors"
	"fmt"
)

// OSStatus values from Security/SecBase.h that this package reasons about.
const (
	statusUnimplemented        = -4
	statusItemNotFound         = -25300
	statusDuplicateItem        = -25299
	statusNotAvailable         = -25291
	statusMissingEntitlement   = -34018
	statusInteractionNotAllowd = -25308
)

// SecError is a Security.framework failure. It carries only the operation, the
// numeric code and Apple's description; never key material.
type SecError struct {
	Op   string
	Code int
	Msg  string
}

func (e *SecError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("darwin keystore: %s: OSStatus %d", e.Op, e.Code)
	}
	return fmt.Sprintf("darwin keystore: %s: %s (OSStatus %d)", e.Op, e.Msg, e.Code)
}

// seUnavailable reports whether code means "the Secure Enclave cannot be used
// by this process" (as opposed to a transient or data error).
func seUnavailable(code int) bool {
	switch code {
	case statusUnimplemented, statusNotAvailable, statusMissingEntitlement:
		return true
	}
	return false
}

// isSEUnavailable reports whether err is a SecError with an SE-unavailable code.
func isSEUnavailable(err error) bool {
	var se *SecError
	return errors.As(err, &se) && seUnavailable(se.Code)
}
