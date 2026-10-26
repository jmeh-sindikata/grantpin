package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/jmeh-sindikata/grantd/internal/vault"
)

// FileName is the per-repo policy file name.
const FileName = ".grantd.yml"

// DefaultMaxGrantTTL is the grant TTL cap used when the policy file does not
// set max_grant_ttl. DECISION (conservative): absent means 1h, not "no cap".
const DefaultMaxGrantTTL = time.Hour

// maxFileSize bounds how much of a policy file is read.
const maxFileSize = 1 << 20

// Sentinel errors; use errors.Is. Typed variants carry detail (errors.As).
var (
	// ErrSecretNotAllowed: a requested secret is not covered by the policy.
	ErrSecretNotAllowed = errors.New("policy: secret not allowed")
	// ErrCommandNotAllowed: argv does not start with an allowed prefix.
	ErrCommandNotAllowed = errors.New("policy: command not allowed")
	// ErrInsecurePolicy: the policy file is world-writable or not owned by the
	// current user.
	ErrInsecurePolicy = errors.New("policy: insecure policy file")
	// ErrInvalidPolicy: the policy file could not be parsed or failed validation.
	ErrInvalidPolicy = errors.New("policy: invalid policy file")
)

// SecretNotAllowedError names the offending requested secret.
type SecretNotAllowedError struct{ Secret string }

func (e *SecretNotAllowedError) Error() string {
	return fmt.Sprintf("policy: secret %q is not allowed by .grantd.yml", e.Secret)
}

// Is makes errors.Is(err, ErrSecretNotAllowed) true.
func (e *SecretNotAllowedError) Is(target error) bool { return target == ErrSecretNotAllowed }

// CommandNotAllowedError carries the refused argv.
type CommandNotAllowedError struct{ Argv []string }

func (e *CommandNotAllowedError) Error() string {
	return fmt.Sprintf("policy: command %q is not allowed by .grantd.yml", e.Argv)
}

// Is makes errors.Is(err, ErrCommandNotAllowed) true.
func (e *CommandNotAllowedError) Is(target error) bool { return target == ErrCommandNotAllowed }

// InsecurePolicyError describes why a policy file was refused.
type InsecurePolicyError struct {
	Path   string
	Reason string
}

func (e *InsecurePolicyError) Error() string {
	return fmt.Sprintf("policy: refusing %s: %s", e.Path, e.Reason)
}

// Is makes errors.Is(err, ErrInsecurePolicy) true.
func (e *InsecurePolicyError) Is(target error) bool { return target == ErrInsecurePolicy }

// Policy is a parsed .grantd.yml (§6). Policy restricts; it never grants.
// Load always returns a non-nil *Policy on success; when no file exists
// Present() is false and Check permits everything (the daemon must then force
// an explicit approval). A nil *Policy behaves like an absent one.
type Policy struct {
	present     bool
	path        string
	secrets     []string
	commands    [][]string
	maxGrantTTL time.Duration
	// maxStandingTTL is the declared max_standing_grant_ttl; hasStandingTTL
	// says whether the file declared it at all.
	maxStandingTTL time.Duration
	hasStandingTTL bool
}

// file is the on-disk shape. Unknown keys are rejected.
type file struct {
	Version     int        `yaml:"version"`
	Secrets     []string   `yaml:"secrets"`
	Commands    [][]string `yaml:"commands"`
	MaxGrantTTL string     `yaml:"max_grant_ttl"`
	// MaxStandingGrantTTL is optional; see Policy.MaxStandingGrantTTL.
	MaxStandingGrantTTL string `yaml:"max_standing_grant_ttl"`
}

// currentUID is overridable in tests.
var currentUID = os.Getuid

// Load walks from cwd (which must be absolute) up to the filesystem root and
// parses the first .grantd.yml found. It returns an absent Policy (Present()
// false, nil error) when none exists. Any problem with a file that does exist
// (unreadable, insecure, malformed) is an error: Load never walks past a
// broken policy to a looser one.
func Load(cwd string) (*Policy, error) {
	if !filepath.IsAbs(cwd) {
		return nil, fmt.Errorf("policy: cwd %q is not absolute", cwd)
	}
	dir := filepath.Clean(cwd)
	for {
		p := filepath.Join(dir, FileName)
		pol, err := loadFile(p)
		switch {
		case err == nil:
			return pol, nil
		case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			// keep walking
		default:
			return nil, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return &Policy{}, nil
		}
		dir = parent
	}
}

func loadFile(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &InsecurePolicyError{Path: path, Reason: "not a regular file"}
	}
	if err := checkOwnerAndMode(path, info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%w: %s: file too large", ErrInvalidPolicy, path)
	}
	return parse(path, data)
}

func parse(path string, data []byte) (*Policy, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrInvalidPolicy, path, fmt.Sprintf(format, a...))
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, bad("empty file (version: 1 required)")
		}
		return nil, bad("%v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, bad("multiple YAML documents")
	}
	if f.Version != 1 {
		return nil, bad("unsupported version %d (want 1)", f.Version)
	}
	for _, s := range f.Secrets {
		if s == "" || !doublestar.ValidatePattern(s) {
			return nil, bad("invalid secret pattern %q", s)
		}
	}
	for _, c := range f.Commands {
		if len(c) == 0 {
			return nil, bad("empty command prefix")
		}
		if slices.Contains(c, "") {
			return nil, bad("command prefix %q has an empty element", c)
		}
	}
	ttl := DefaultMaxGrantTTL
	if f.MaxGrantTTL != "" {
		d, err := parseTTL(f.MaxGrantTTL)
		if err != nil {
			return nil, bad("max_grant_ttl: %v", err)
		}
		ttl = d
	}
	pol := &Policy{
		present:     true,
		path:        path,
		secrets:     slices.Clone(f.Secrets),
		commands:    cloneCommands(f.Commands),
		maxGrantTTL: ttl,
	}
	if f.MaxStandingGrantTTL != "" {
		d, err := parseTTL(f.MaxStandingGrantTTL)
		if err != nil {
			return nil, bad("max_standing_grant_ttl: %v", err)
		}
		pol.maxStandingTTL, pol.hasStandingTTL = d, true
	}
	return pol, nil
}

// parseTTL accepts Go durations ("90m", "4h") plus a whole-number day suffix
// ("2d" = 48h). Zero and negative values are rejected.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

func cloneCommands(in [][]string) [][]string {
	out := make([][]string, len(in))
	for i, c := range in {
		out[i] = slices.Clone(c)
	}
	return out
}

// Present reports whether a policy file was found.
func (p *Policy) Present() bool { return p != nil && p.present }

// Path is the policy file path ("" when absent).
func (p *Policy) Path() string {
	if !p.Present() {
		return ""
	}
	return p.path
}

// Dir is the directory containing the policy file ("" when absent).
func (p *Policy) Dir() string {
	if !p.Present() {
		return ""
	}
	return filepath.Dir(p.path)
}

// MaxGrantTTL is the cap on grant lifetimes. Absent policy or absent key:
// DefaultMaxGrantTTL.
func (p *Policy) MaxGrantTTL() time.Duration {
	if !p.Present() {
		return DefaultMaxGrantTTL
	}
	return p.maxGrantTTL
}

// MaxStandingGrantTTL is the policy's optional cap on standing grants (the
// ones the human creates with `grantd grants add`). ok is false when there is
// no policy or it does not declare max_standing_grant_ttl; the caller then
// applies only its own global ceiling. The value can only lower that ceiling,
// never raise it.
//
// max_grant_ttl deliberately does NOT apply to standing grants; see the
// package comment.
func (p *Policy) MaxStandingGrantTTL() (d time.Duration, ok bool) {
	if !p.Present() || !p.hasStandingTTL {
		return 0, false
	}
	return p.maxStandingTTL, true
}

// Secrets returns a copy of the allowed secret globs.
func (p *Policy) Secrets() []string {
	if !p.Present() {
		return nil
	}
	return slices.Clone(p.secrets)
}

// Commands returns a copy of the allowed argv prefixes.
func (p *Policy) Commands() [][]string {
	if !p.Present() {
		return nil
	}
	return cloneCommands(p.commands)
}

// Check returns nil if every requested secret and argv are permitted.
//
// A requested literal name must match some policy glob (or equal a literal
// policy entry). A requested glob (e.g. "aws/*") is allowed only if that exact
// text appears in the policy. argv must start, element for element, with one
// of the policy's command prefixes. The secret check runs first.
//
// An absent policy returns nil: Check never grants, and the caller must use
// Present() to force an explicit approval.
func (p *Policy) Check(secrets []string, argv []string) error {
	if !p.Present() {
		return nil
	}
	for _, s := range secrets {
		if !p.secretAllowed(s) {
			return &SecretNotAllowedError{Secret: s}
		}
	}
	for _, c := range p.commands {
		if len(argv) >= len(c) && slices.Equal(argv[:len(c)], c) {
			return nil
		}
	}
	return &CommandNotAllowedError{Argv: slices.Clone(argv)}
}

func (p *Policy) secretAllowed(s string) bool { return vault.Covered(p.secrets, s) }
