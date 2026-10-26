package main

import (
	"strings"
	"testing"
)

// listRow returns the `grantpin list` line for name, split on runs of spaces.
func listRow(t *testing.T, name string) []string {
	t.Helper()
	for _, line := range strings.Split(mustCLI(t, "", "list"), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == name {
			return f
		}
	}
	t.Fatalf("%s not in list", name)
	return nil
}

func TestCLIUpdate(t *testing.T) {
	startTestDaemon(t, true)
	t.Chdir(t.TempDir())

	mustCLI(t, secretValue, "set", "API_KEY", "--tags", "prod", "--url", "https://e.x", "--expires", "30d", "--min-tier", "hardware")
	if out := mustCLI(t, "", "update", "API_KEY", "--tags", "b,a", "--min-tier", "dialog"); out != "updated API_KEY\n" {
		t.Errorf("update output = %q", out)
	}
	// NAME TIER EXPIRES TAGS URL
	row := listRow(t, "API_KEY")
	if row[1] != "dialog" || row[3] != "a,b" || row[4] != "https://e.x" || row[2] == "-" {
		t.Errorf("row after update = %q", row)
	}
	// the value is intact
	if out := mustCLI(t, "", "masked", "API_KEY"); out != "****"+secretValue[len(secretValue)-4:]+"\n" {
		t.Errorf("masked = %q", out)
	}

	// clearing: empty --url, empty --tags, --clear-expires
	mustCLI(t, "", "update", "API_KEY", "--url", "", "--tags", "", "--clear-expires")
	row = listRow(t, "API_KEY")
	if row[2] != "-" || row[3] != "-" || row[4] != "-" {
		t.Errorf("row after clear = %q", row)
	}
	// a new expiry
	mustCLI(t, "", "update", "API_KEY", "--expires", "7d", "--notes", "rotated")
	if row = listRow(t, "API_KEY"); row[2] == "-" {
		t.Errorf("expiry not set: %q", row)
	}

	for name, args := range map[string][]string{
		"no flags":          {"update", "API_KEY"},
		"expires and clear": {"update", "API_KEY", "--expires", "7d", "--clear-expires"},
		"bad expires":       {"update", "API_KEY", "--expires", "soon"},
		"zero expires":      {"update", "API_KEY", "--expires", "0d"},
		"bad tier":          {"update", "API_KEY", "--min-tier", "gold"},
		"bad tag":           {"update", "API_KEY", "--tags", "no spaces"},
		"missing secret":    {"update", "NOPE", "--notes", "x"},
	} {
		if _, _, err := cli(t, "", args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, _, err := cli(t, "", "update", "NOPE", "--notes", "x"); err == nil || !strings.Contains(err.Error(), "secret_not_found") {
		t.Errorf("missing secret err = %v", err)
	}
}
