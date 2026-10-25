package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// ConflictMode says what Import does when a name already exists.
type ConflictMode string

// Conflict modes for Import.
const (
	ConflictSkip      ConflictMode = "skip"
	ConflictOverwrite ConflictMode = "overwrite"
	ConflictError     ConflictMode = "error"
)

// ParseConflictMode parses "skip", "overwrite" or "error".
func ParseConflictMode(s string) (ConflictMode, error) {
	switch m := ConflictMode(s); m {
	case ConflictSkip, ConflictOverwrite, ConflictError:
		return m, nil
	}
	return "", fmt.Errorf("vault: unknown conflict mode (want skip, overwrite or error)")
}

// ImportReport lists secret names only, never values.
type ImportReport struct {
	Added       []string // new secrets
	Overwritten []string // existing secrets replaced
	Skipped     []string // existing secrets left alone (ConflictSkip)
	Empty       []string // entries with an empty value, ignored
	DryRun      bool
}

// Import stores kvs as secrets named by their keys, with default metadata.
// It is all-or-nothing: every key is validated and, for ConflictError,
// conflicts are detected before anything is written, and the writes share one
// transaction. With dryRun nothing is written but the report is still
// computed (and conflicts still error). For duplicate keys the last wins.
func (v *Vault) Import(ctx context.Context, kvs []KV, onConflict ConflictMode, dryRun bool) (ImportReport, error) {
	rep := ImportReport{DryRun: dryRun}
	if _, err := ParseConflictMode(string(onConflict)); err != nil {
		return rep, err
	}
	unlock, err := v.rlock()
	if err != nil {
		return rep, err
	}
	defer unlock()

	last := map[string][]byte{}
	for _, kv := range kvs {
		if err := ValidateName(kv.Key); err != nil {
			return rep, err
		}
		last[kv.Key] = kv.Value
	}
	names := make([]string, 0, len(last))
	for n := range last {
		names = append(names, n)
	}
	sort.Strings(names)

	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("vault: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	type action struct {
		name      string
		overwrite bool
	}
	var todo []action
	for _, n := range names {
		if len(last[n]) == 0 {
			rep.Empty = append(rep.Empty, n)
			continue
		}
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM secrets WHERE name = ?`, n).Scan(&one)
		exists := err == nil
		if err != nil && !isNoRows(err) {
			return rep, fmt.Errorf("vault: lookup: %w", err)
		}
		switch {
		case !exists:
			rep.Added = append(rep.Added, n)
			todo = append(todo, action{n, false})
		case onConflict == ConflictSkip:
			rep.Skipped = append(rep.Skipped, n)
		case onConflict == ConflictOverwrite:
			rep.Overwritten = append(rep.Overwritten, n)
			todo = append(todo, action{n, true})
		default:
			return ImportReport{DryRun: dryRun}, fmt.Errorf("%w: %s", ErrExists, n)
		}
	}
	if dryRun {
		return rep, nil
	}
	for _, a := range todo {
		if err := v.setTx(ctx, tx, Meta{Name: a.name}, last[a.name], a.overwrite); err != nil {
			return ImportReport{DryRun: dryRun}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ImportReport{DryRun: dryRun}, fmt.Errorf("vault: commit: %w", err)
	}
	return rep, nil
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
