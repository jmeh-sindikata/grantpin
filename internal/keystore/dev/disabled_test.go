//go:build !grantpin_dev

package dev

import (
	"errors"
	"testing"
)

func TestDisabledInNormalBuild(t *testing.T) {
	if Enabled {
		t.Fatal("Enabled must be false without grantpin_dev")
	}
	ks, err := Open()
	if ks != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("Open = %v, %v; want nil, ErrDisabled", ks, err)
	}
}
