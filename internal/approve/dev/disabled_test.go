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
	a, err := Open()
	if a != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("Open = %v, %v; want nil, ErrDisabled", a, err)
	}
}
