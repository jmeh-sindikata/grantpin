package grant

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"grantd/internal/approve"
)

var (
	// ErrNoMatch means no stored grant satisfies the query.
	ErrNoMatch = errors.New("grant: no matching grant")
	// ErrNotFound means a grant ID does not exist.
	ErrNotFound = errors.New("grant: not found")
	// ErrInvalidGrant means Add refused a malformed grant.
	ErrInvalidGrant = errors.New("grant: invalid grant")
)

// Grant is the unit that makes approvals reusable (§6). A request matches only
// if caller, cwd, every requested secret and the argv prefix all satisfy a
// non-expired grant. A grant covers exactly the set it was created for.
type Grant struct {
	ID     string
	Caller string
	// CwdPrefix is an absolute, cleaned directory. A request cwd matches if it
	// equals it or is below it (see Match for the exact rules).
	CwdPrefix string
	// Secrets are names or globs exactly as requested at approval time.
	Secrets []string
	// CmdPrefix is the argv prefix a request must start with. Never empty.
	CmdPrefix     []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsesRemaining *int // nil = unlimited within TTL

	// Expired is set by Get and List (relative to the store clock); it is not
	// persisted and ignored by Add.
	Expired bool
}

// Query is what a run request is matched against.
type Query struct {
	Caller string
	Cwd    string
	// Secrets are the requested names or globs, exactly as the caller sent
	// them. A literal is covered by an equal or glob-matching grant entry; a
	// glob is covered only by the textually identical grant entry.
	Secrets []string
	Argv    []string
	Now     time.Time
}

// newID returns 16 random bytes, hex encoded.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("grant: generating id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// isGlob reports whether s contains doublestar metacharacters. Secret names
// ([A-Za-z0-9_/.-]+) never do.
func isGlob(s string) bool { return strings.ContainsAny(s, `*?[]{}\`) }

// expiredAt: a grant is expired at exactly its ExpiresAt instant.
func (g Grant) expiredAt(now time.Time) bool { return !now.Before(g.ExpiresAt) }

// cwdCovered reports whether cwd (already cleaned) is prefix or below it.
// It is purely lexical: no symlink resolution; callers wanting that must
// EvalSymlinks both sides before comparing. "/a/foo" is not under "/a/f".
func cwdCovered(prefix, cwd string) bool {
	if cwd == prefix {
		return true
	}
	sep := string(filepath.Separator)
	if strings.HasSuffix(prefix, sep) { // filesystem root
		return strings.HasPrefix(cwd, prefix)
	}
	return strings.HasPrefix(cwd, prefix+sep)
}

func secretsCovered(entries, requested []string) bool {
	if len(requested) == 0 {
		return false
	}
	for _, s := range requested {
		if s == "" || !secretCovered(entries, s) {
			return false
		}
	}
	return true
}

func secretCovered(entries []string, s string) bool {
	if slices.Contains(entries, s) {
		return true
	}
	if isGlob(s) {
		return false // globs need a textual match
	}
	for _, e := range entries {
		if isGlob(e) {
			if ok, err := doublestar.Match(e, s); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func argvCovered(prefix, argv []string) bool {
	return len(prefix) > 0 && len(argv) >= len(prefix) && slices.Equal(argv[:len(prefix)], prefix)
}

// matches applies every rule except uses_remaining bookkeeping. q.Cwd must
// already be cleaned and absolute.
func (g Grant) matches(q Query, cleanCwd string) bool {
	return g.Caller == q.Caller &&
		!g.expiredAt(q.Now) &&
		(g.UsesRemaining == nil || *g.UsesRemaining > 0) &&
		cwdCovered(g.CwdPrefix, cleanCwd) &&
		secretsCovered(g.Secrets, q.Secrets) &&
		argvCovered(g.CmdPrefix, q.Argv)
}

// FromDecision builds the exactly-scoped grant for an "Allow for N" decision:
// the request's caller, its cwd as prefix, its secret set and an argv prefix.
//
// cmdPrefix is optional (a policy command prefix). It is used only if it is a
// non-empty element-wise prefix of req.Argv; otherwise (nil, empty or not a
// prefix) the full argv is used, the most restrictive choice. ttl is clamped
// to maxTTL when maxTTL > 0. A ttl <= 0 yields a grant that is already
// expired (ExpiresAt == now), which Store.Add rejects: allow-once decisions
// must not create grants.
func FromDecision(req approve.ApprovalRequest, ttl, maxTTL time.Duration, cmdPrefix []string, now time.Time) Grant {
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	if ttl < 0 {
		ttl = 0
	}
	prefix := req.Argv
	if len(cmdPrefix) > 0 && argvCovered(cmdPrefix, req.Argv) {
		prefix = cmdPrefix
	}
	cwd := req.Cwd
	if cwd != "" {
		cwd = filepath.Clean(cwd)
	}
	return Grant{
		Caller:    req.Caller,
		CwdPrefix: cwd,
		Secrets:   slices.Clone(req.Secrets),
		CmdPrefix: slices.Clone(prefix),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
}
