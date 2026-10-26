package darwin

import (
	"fmt"
	"testing"

	"github.com/jmeh-sindikata/grantpin/internal/keystore"
)

func TestSecErrorTransient(t *testing.T) {
	for code, want := range map[int]bool{
		-25308: true,  // errSecInteractionNotAllowed: session locked
		-25315: true,  // errSecInteractionRequired
		-25320: true,  // errSecInDarkWake
		-25293: false, // errSecAuthFailed: cannot tell lock state from a refused binary
		-34018: false, // missing entitlement
		-25291: false, // not available
		-25300: false, // item not found
	} {
		err := fmt.Errorf("vault: unwrap data key: %w", &SecError{Op: "decrypt", Code: code})
		if got := keystore.IsTransient(err); got != want {
			t.Errorf("OSStatus %d: IsTransient = %v, want %v", code, got, want)
		}
	}
}
