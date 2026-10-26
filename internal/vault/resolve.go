package vault

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/jmeh-sindikata/grantpin/internal/presence"
)

// ExpandNames expands literal names and doublestar globs ("aws/*", "aws/**")
// against the stored names and returns the sorted, de-duplicated list. It is
// conservative: a literal name that does not exist, or a glob that matches
// nothing, is an error (ErrNotFound). Nothing is decrypted.
func (v *Vault) ExpandNames(ctx context.Context, patterns []string) ([]string, error) {
	unlock, err := v.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return v.expand(ctx, patterns)
}

func (v *Vault) expand(ctx context.Context, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("vault: no secret names given")
	}
	for _, p := range patterns {
		if err := validatePattern(p); err != nil {
			return nil, err
		}
	}
	rows, err := v.db.QueryContext(ctx, `SELECT name FROM secrets`)
	if err != nil {
		return nil, fmt.Errorf("vault: list names: %w", err)
	}
	defer rows.Close()
	have := map[string]struct{}{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("vault: list names: %w", err)
		}
		have[n] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vault: list names: %w", err)
	}

	out := map[string]struct{}{}
	for _, p := range patterns {
		if !IsPattern(p) {
			if _, ok := have[p]; !ok {
				return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
			}
			out[p] = struct{}{}
			continue
		}
		matched := false
		for n := range have {
			if ok, err := doublestar.Match(p, n); err == nil && ok {
				out[n] = struct{}{}
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("%w: pattern %s matches no secret", ErrNotFound, p)
		}
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Resolve expands names (literals and globs, see ExpandNames) and returns
// name to plaintext for every resolved secret. It is INTERNAL: the result may
// only flow to the daemon's runner (and the presence-gated show path), never
// into a Response, log or error message. Callers should zero the slices when
// done. Resolve fails, returning nothing, if any pattern matches nothing, any
// secret is expired (ErrExpired) or any decryption fails.
func (v *Vault) Resolve(ctx context.Context, names []string) (map[string][]byte, error) {
	unlock, err := v.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	resolved, err := v.expand(ctx, names)
	if err != nil {
		return nil, err
	}
	return v.resolveExact(ctx, resolved)
}

// ResolveNames is Resolve for names that ExpandNames already produced: it does
// not expand again, so each name must be an exact stored name (a pattern is an
// ErrInvalidName, a missing name ErrNotFound). Same contract otherwise: the
// result is internal, callers zero it, and on any error nothing is returned.
func (v *Vault) ResolveNames(ctx context.Context, names []string) (map[string][]byte, error) {
	unlock, err := v.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := validateExact(names); err != nil {
		return nil, err
	}
	return v.resolveExact(ctx, names)
}

func validateExact(names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("vault: no secret names given")
	}
	for _, n := range names {
		if err := ValidateName(n); err != nil {
			return err
		}
	}
	return nil
}

// resolveExact decrypts exact names; the caller holds the read lock.
func (v *Vault) resolveExact(ctx context.Context, names []string) (map[string][]byte, error) {
	now := v.cfg.now()
	out := make(map[string][]byte, len(names))
	fail := func(err error) (map[string][]byte, error) {
		for _, b := range out {
			Zero(b)
		}
		return nil, err
	}
	for _, n := range names {
		pt, m, err := v.decrypt(ctx, n)
		if err != nil {
			return fail(err)
		}
		if m.Expired(now) {
			Zero(pt)
			return fail(fmt.Errorf("%w: %s", ErrExpired, n))
		}
		out[n] = pt
	}
	return out, nil
}

// CheckNames is the pre-release check for names that ExpandNames already
// produced (exact names, no expansion): it returns the highest min_tier among
// them and fails with ErrExpired if any is expired at now. Each secret is
// decrypted only to authenticate its metadata (the tier and the name are bound
// into the GCM AAD, so a tampered min_tier fails with ErrDecrypt) and the
// plaintext is zeroed at once; nothing is returned. This is the one decrypt
// that happens before the human or a grant has approved the release.
func (v *Vault) CheckNames(ctx context.Context, names []string, now time.Time) (presence.PresenceTier, error) {
	unlock, err := v.rlock()
	if err != nil {
		return presence.TierNone, err
	}
	defer unlock()
	if err := validateExact(names); err != nil {
		return presence.TierNone, err
	}
	return v.checkExact(ctx, names, now)
}

// checkExact decrypts-and-discards each name; the caller holds the read lock.
func (v *Vault) checkExact(ctx context.Context, names []string, now time.Time) (presence.PresenceTier, error) {
	highest := presence.TierNone
	for _, n := range names {
		pt, m, err := v.decrypt(ctx, n)
		if err != nil {
			return presence.TierNone, err
		}
		Zero(pt)
		if m.Expired(now) {
			return presence.TierNone, fmt.Errorf("%w: %s", ErrExpired, n)
		}
		if m.MinTier > highest {
			highest = m.MinTier
		}
	}
	return highest, nil
}
