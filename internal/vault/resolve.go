package vault

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/bmatcuk/doublestar/v4"

	"grantd/internal/presence"
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
	now := v.cfg.now()
	out := make(map[string][]byte, len(resolved))
	fail := func(err error) (map[string][]byte, error) {
		for _, b := range out {
			zero(b)
		}
		return nil, err
	}
	for _, n := range resolved {
		pt, m, err := v.decrypt(ctx, n)
		if err != nil {
			return fail(err)
		}
		if m.Expired(now) {
			zero(pt)
			return fail(fmt.Errorf("%w: %s", ErrExpired, n))
		}
		out[n] = pt
	}
	return out, nil
}

// MinTierFor expands names like Resolve and returns the highest min_tier among
// the matched secrets. It does not decrypt. An unmatched literal or glob is an
// error, so a caller can never under-estimate the required tier.
func (v *Vault) MinTierFor(ctx context.Context, names []string) (presence.PresenceTier, error) {
	unlock, err := v.rlock()
	if err != nil {
		return presence.TierNone, err
	}
	defer unlock()
	resolved, err := v.expand(ctx, names)
	if err != nil {
		return presence.TierNone, err
	}
	highest := presence.TierNone
	for _, n := range resolved {
		var t int
		err := v.db.QueryRowContext(ctx, `SELECT min_tier FROM secrets WHERE name = ?`, n).Scan(&t)
		if err == sql.ErrNoRows {
			return presence.TierNone, fmt.Errorf("%w: %s", ErrNotFound, n)
		}
		if err != nil {
			return presence.TierNone, fmt.Errorf("vault: read tier: %w", err)
		}
		if pt := presence.PresenceTier(t); pt > highest {
			highest = pt
		}
	}
	return highest, nil
}
