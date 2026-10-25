//go:build !grantd_dev

package dev

import (
	"errors"
	"testing"
)

func TestDisabledInNormalBuild(t *testing.T) {
	if Enabled {
		t.Fatal("Enabled must be false without grantd_dev")
	}
	ks, err := Open()
	if ks != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("Open = %v, %v; want nil, ErrDisabled", ks, err)
	}
}
