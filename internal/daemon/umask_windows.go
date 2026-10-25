//go:build windows

package daemon

func restrictiveUmask() (restore func()) { return func() {} }
