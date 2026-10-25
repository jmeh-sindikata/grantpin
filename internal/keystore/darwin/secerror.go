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
	statusInteractionRequired  = -25315
	statusInDarkWake           = -25320
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

// transientStatus reports whether code means the keychain is unavailable right
// now but will work again without any change by the user other than unlocking
// or waking the Mac:
//
//   - -25308 errSecInteractionNotAllowed: the data-protection keychain is
//     locked or the session is not unlocked yet (screen locked, early after
//     login). Observed from Unwrap under launchd.
//   - -25315 errSecInteractionRequired: the same condition reported as "would
//     need UI"; Unwrap never shows UI, so it can only mean the session is not
//     ready.
//   - -25320 errSecInDarkWake: the machine is in dark wake (lid closed, Power
//     Nap) where no UI or keychain access is possible.
//
// -25293 errSecAuthFailed is deliberately NOT here: the framework returns it
// both for a locked keychain and for a key whose access control refuses this
// binary (wrong signature or entitlement), and the code alone cannot tell
// them apart. Treating it as transient would hide a permanent misconfiguration
// behind an endless retry, so it fails fast like any other unknown status.
func transientStatus(code int) bool {
	switch code {
	case statusInteractionNotAllowd, statusInteractionRequired, statusInDarkWake:
		return true
	}
	return false
}

// Transient reports whether the failure is expected to clear by itself (see
// transientStatus). It implements keystore.Transient.
func (e *SecError) Transient() bool { return transientStatus(e.Code) }
