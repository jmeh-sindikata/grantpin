package proto

import "strings"

// MaxCallerLen is the longest canonical caller label, in bytes.
const MaxCallerLen = 64

// CanonicalCaller is the one normal form of a caller label. The label is
// self-reported and only informational, but a standing grant is addressed by
// it, so the spellings people and MCP clients naturally use for the same
// client must agree: "Claude Code", "claude-code" and "claude_code" are all
// "claude-code".
//
// It lowercases name, keeps [a-z0-9.], turns every other run of characters
// (spaces, '_', '-', punctuation, non-ASCII) into a single '-', trims '-' from
// both ends and cuts the result to MaxCallerLen bytes. It returns "" when
// nothing is left; callers pick their own fallback.
func CanonicalCaller(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if b.Len() >= MaxCallerLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	s := b.String()
	if len(s) > MaxCallerLen {
		s = s[:MaxCallerLen] // ASCII only, so any cut is on a boundary
	}
	return strings.TrimRight(s, "-")
}

// SameCaller reports whether two caller labels name the same caller: equal
// canonical forms, or equal text when a label has no canonical form (so two
// different labels made only of punctuation never match each other).
func SameCaller(a, b string) bool {
	if a == b {
		return true
	}
	ca := CanonicalCaller(a)
	return ca != "" && ca == CanonicalCaller(b)
}
