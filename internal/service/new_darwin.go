//go:build darwin

package service

// New returns the launchd-backed Manager.
func New() (Manager, error) { return newLaunchd(execRunner{}) }
