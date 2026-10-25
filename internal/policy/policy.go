package policy

import (
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubs that other milestone steps will fill in.
var ErrNotImplemented = errors.New("not implemented")

// FileName is the per-repo policy file name.
const FileName = ".grantd.yml"

// Policy is a parsed .grantd.yml (§6). Policy restricts; it never grants.
type Policy struct {
	Version     int
	Secrets     []string   // globs: which secrets this repo may request
	Commands    [][]string // allowed argv prefixes
	MaxGrantTTL time.Duration
	// Path is the file the policy was loaded from.
	Path string
}

// Load finds .grantd.yml in cwd or the nearest ancestor. It returns (nil, nil)
// when no policy file exists.
func Load(cwd string) (*Policy, error) { return nil, ErrNotImplemented }

// Check returns nil if every requested secret and the argv are permitted by p.
// A nil *Policy means "no policy" and permits nothing by itself (every request
// still needs explicit approval).
func (p *Policy) Check(secrets []string, argv []string) error { return ErrNotImplemented }
