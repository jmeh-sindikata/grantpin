// Package audit implements the append-only, HMAC-chained audit log (§6).
//
// The log lives in the vault's SQLite database (the caller passes the shared
// *sql.DB and a key derived from the vault data key, e.g.
// vault.DeriveKey("audit-hmac")). It records who asked for which secret NAMES
// and what was decided. The API has no way to accept a secret value: Entry
// holds only fixed, typed fields and there are no free-form maps.
//
// # Chain
//
//	HMAC_n = HMAC-SHA256(key, canonical(entry_n) || HMAC_{n-1})
//	HMAC_0 (genesis prev) = 32 zero bytes
//
// # Canonical encoding (version 1)
//
// canonical(entry) is the concatenation of, in this order:
//
//	"grantd.audit.v1\x00"            domain/version tag (16 bytes)
//	id        uint64 big-endian      row id (so rows cannot be re-numbered)
//	ts        string                 UTC, time.RFC3339Nano, as stored
//	caller    string
//	cwd       string
//	argv      uint64 count, then count strings
//	secrets   uint64 count, then count strings
//	decision  string
//	grant_id  string
//	reason    string
//	exit_code byte 0, or byte 1 followed by int64 big-endian
//	duration  int64 big-endian, nanoseconds
//
// where "string" is a uint64 big-endian byte length followed by the bytes.
// Length prefixes make the encoding injective (no field-boundary ambiguity).
// A nil and an empty slice encode identically.
//
// # Limits
//
// UPDATE and DELETE are blocked by triggers, but anyone with write access to
// the database file can drop the triggers. The HMAC chain detects edits,
// deletions from the middle, and reordering by anyone lacking the key; it
// cannot detect truncation of the newest rows (no external anchor).
package audit
