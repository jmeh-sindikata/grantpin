package proto

import (
	"strings"
	"testing"
)

func TestCanonicalCaller(t *testing.T) {
	for in, want := range map[string]string{
		"claude-code":                  "claude-code",
		"Claude Code":                  "claude-code",
		"claude_code":                  "claude-code",
		"  Claude   Code  ":            "claude-code",
		"Cursor/1.2 (beta)":            "cursor-1.2-beta",
		"--a__b--":                     "a-b",
		"é":                            "",
		"":                             "",
		"!!!":                          "",
		strings.Repeat("A", 100):       strings.Repeat("a", MaxCallerLen),
		strings.Repeat("a ", 100):      strings.TrimRight(strings.Repeat("a-", 32), "-"),
		strings.Repeat("a", 63) + " b": strings.Repeat("a", 63),
	} {
		if got := CanonicalCaller(in); got != want {
			t.Errorf("CanonicalCaller(%q) = %q, want %q", in, got, want)
		}
		if got := CanonicalCaller(CanonicalCaller(in)); got != want {
			t.Errorf("CanonicalCaller is not idempotent on %q: %q", in, got)
		}
	}
}

func TestSameCaller(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"Claude Code", "claude-code", true},
		{"claude_code", "claude-code", true},
		{"claude-code", "claude-code-2", false},
		{"a.b", "a-b", false},
		{"", "", true},
		{"???", "!!!", false},
		{"???", "???", true},
		{"cli", "", false},
	} {
		if got := SameCaller(c.a, c.b); got != c.want {
			t.Errorf("SameCaller(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
