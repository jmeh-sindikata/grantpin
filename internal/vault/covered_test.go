package vault

import "testing"

func TestCovered(t *testing.T) {
	cases := []struct {
		entries []string
		name    string
		want    bool
	}{
		{[]string{"API_KEY"}, "API_KEY", true},
		{[]string{"API_KEY"}, "OTHER", false},
		{[]string{"aws/*"}, "aws/key", true},
		{[]string{"aws/*"}, "aws/a/b", false},
		{[]string{"aws/**"}, "aws/a/b", true},
		{[]string{"aws/*"}, "gcp/key", false},
		{[]string{"DB_?"}, "DB_1", true},
		// A requested glob needs an identical entry.
		{[]string{"aws/*"}, "aws/*", true},
		{[]string{"aws/**"}, "aws/*", false},
		{[]string{"*"}, "aws/*", false},
		{[]string{"aws/*"}, "aws/[ab]", false},
		// Nothing covers the empty name, not even an empty entry.
		{[]string{"", "*"}, "", false},
		{nil, "A", false},
		{[]string{"[unclosed"}, "A", false},
	}
	for _, c := range cases {
		if got := Covered(c.entries, c.name); got != c.want {
			t.Errorf("Covered(%q, %q) = %v, want %v", c.entries, c.name, got, c.want)
		}
	}
	if IsPattern("a/b") || !IsPattern("a/*") || !IsPattern(`a\b`) {
		t.Error("IsPattern")
	}
}
