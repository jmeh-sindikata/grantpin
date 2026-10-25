//go:build !darwin

package service

// New always fails with ErrUnsupported on this platform.
func New() (Manager, error) { return nil, ErrUnsupported }
