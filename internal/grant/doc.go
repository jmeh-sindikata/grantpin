// Package grant stores approval grants and matches requests against them.
// A grant is scoped to (caller, cwd prefix, secret globs, argv prefix, expiry).
//
// # Authentication
//
// Grants live in the vault's SQLite file, which any process of the same user
// can write. Without more, `INSERT INTO grants ...` would be a presence bypass:
// the next run would match the forged grant and release secrets with no
// prompt. So every row carries a MAC, HMAC-SHA256 under a key derived from the
// vault data key (vault.DeriveKey("grant-mac")), over a versioned canonical
// encoding of (id, caller, cwd_prefix, secrets, cmd_prefix, created_at,
// expires_at, uses_remaining, kind) (see canonical). Get, List and Match verify it;
// a row that fails is flagged Tampered, never matches, and is reported once at
// WARN. Consuming a use (Store.Consume, called by the broker once a release is
// going ahead; Match does not consume) rewrites uses_remaining and mac in one
// compare-and-swap UPDATE.
//
// # Kinds
//
// A grant is either a dialog grant (kind "", created by the "Allow for N"
// button, at most MaxDialogGrantTTL) or a standing grant (kind "standing",
// created by the human with `grantd grants add`, at most MaxStandingGrantTTL).
// Matching treats them alike; the kind exists so listings can tell them apart.
// It is a column covered by the MAC, so a row cannot be relabelled; rows
// without a kind keep the original encoding and verify as before.
//
// Limits: someone who can write the file can still delete rows (that only
// revokes) and can replay an older, genuinely MAC'd copy of a row they saved
// earlier (reviving a revoked grant, or resetting uses_remaining). The MAC
// stops forgery, not replay. For a standing grant the replay window is its
// whole lifetime (up to MaxStandingGrantTTL), not an hour.
package grant
