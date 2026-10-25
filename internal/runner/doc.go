// Package runner spawns approved commands with secrets injected as environment
// variables and redacts the injected values from the output stream.
//
// It is a pure library: it never logs, never reads the vault and never talks
// to the socket. The daemon resolves secrets, decides on approval and then
// hands the plaintext to [Run] together with the argv to execute.
//
// # Redaction is exact-match only
//
// Output is scrubbed by replacing every exact, byte-for-byte occurrence of an
// injected value with [REDACTED:NAME]. This is defense in depth, not a
// security boundary (HANDOFF §3). It does NOT catch:
//
//   - encoded forms of a secret (base64, hex, URL-encoding, JSON escaping of
//     quotes or newlines, shell quoting that splits the value);
//   - partial leaks (a prefix, suffix or substring of a value);
//   - values transformed by the command (hashed, truncated, reversed, ...);
//   - output the command sends somewhere other than stdout/stderr (network,
//     files, other processes).
//
// Very short values (fewer than [MinSafeValueLen] bytes) are still redacted,
// but they will also match unrelated text ("1" mangles every digit "1" in the
// output). Callers who care should refuse to store such values; this package
// will not second-guess them. Empty values are never redacted.
//
// # Exit codes
//
// See [Result.ExitCode].
package runner
