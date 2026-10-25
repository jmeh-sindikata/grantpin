package keystore

import (
	"errors"
	"fmt"
	"testing"
)

type transientErr bool

func (transientErr) Error() string     { return "x" }
func (e transientErr) Transient() bool { return bool(e) }

func TestIsTransient(t *testing.T) {
	if !IsTransient(fmt.Errorf("vault: unwrap: %w", transientErr(true))) {
		t.Error("wrapped transient error not detected")
	}
	if IsTransient(transientErr(false)) || IsTransient(errors.New("plain")) || IsTransient(nil) {
		t.Error("non-transient classified transient")
	}
}
