package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/approve"
)

func TestCLIGrantsAddCreatesAStandingGrant(t *testing.T) {
	d := startTestDaemon(t, true)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	mustCLI(t, secretValue, "set", "DB_URL")
	mustCLI(t, secretValue+"x", "set", "aws/key")

	// The documented form: flags, then -- and the command prefix.
	stdout, stderr, err := cli(t, "", "grants", "add", "--caller", "claude-code", "--secrets", "DB_URL,aws/*",
		"--ttl", "30d", "--uses", "5", "--", "php", "artisan")
	if err != nil {
		t.Fatalf("grants add: %v\n%s\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "created standing grant ") || !strings.Contains(stdout, "claude-code may run `php artisan ...`") ||
		!strings.Contains(stdout, "DB_URL,aws/*") || !strings.Contains(stdout, dir) || !strings.Contains(stdout, "5 use(s)") ||
		!strings.Contains(stderr, "Waiting for you to confirm") {
		t.Errorf("output = %q / %q", stdout, stderr)
	}
	r := d.ap.lastReq()
	if r.Kind != approve.KindStandingGrant || r.Caller != "claude-code" || r.Cwd != dir || r.RequestedTTL != 30*24*time.Hour ||
		r.RequestedUses != 5 || strings.Join(r.GrantCmdPrefix, " ") != "php artisan" || strings.Join(r.Secrets, ",") != "DB_URL,aws/*" {
		t.Fatalf("approval request = %+v", r)
	}

	// grants list marks it, with a readable remaining time.
	out := mustCLI(t, "", "grants")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "STANDING") || !strings.Contains(lines[1], "standing") ||
		!strings.Contains(lines[1], "claude-code") || !strings.Contains(lines[1], "30d 0h") {
		t.Errorf("grants = %q", out)
	}

	// A run from that caller matches with no prompt.
	asked := d.ap.asked()
	if _, _, err := cli(t, "", "run", "--caller", "claude-code", "--secrets", "DB_URL", "--", "php", "artisan", "-v"); err == nil {
		// php is not installed everywhere; what matters is that it was released
		// without a prompt, so a missing command (127) is fine.
		t.Log("php ran")
	}
	if d.ap.asked() != asked {
		t.Errorf("standing grant did not satisfy the run (asked %d more times)", d.ap.asked()-asked)
	}
}

func TestCLIGrantsAddCmdFlagAndCwd(t *testing.T) {
	d := startTestDaemon(t, true)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	sub := filepath.Join(root, "proj")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	mustCLI(t, secretValue, "set", "API_KEY")
	// --cmd as the last flag; --cwd relative to the current directory.
	mustCLI(t, "", "grants", "add", "--caller", "codex", "--secrets", "API_KEY", "--ttl", "12h", "--cwd", "proj", "--cmd", "sh", "-c")
	r := d.ap.lastReq()
	if r.Cwd != sub || strings.Join(r.GrantCmdPrefix, " ") != "sh -c" || r.RequestedTTL != 12*time.Hour || r.Caller != "codex" {
		t.Fatalf("approval request = %+v", r)
	}
	// Flags after the command prefix belong to the command.
	mustCLI(t, "", "grants", "add", "--caller", "codex", "--secrets", "API_KEY", "--ttl", "1h", "--", "git", "--version")
	if r := d.ap.lastReq(); strings.Join(r.GrantCmdPrefix, " ") != "git --version" || r.Cwd != root {
		t.Fatalf("approval request = %+v", r)
	}
}

func TestCLIGrantsAddArgumentErrors(t *testing.T) {
	d := startTestDaemon(t, true)
	t.Chdir(t.TempDir())
	mustCLI(t, secretValue, "set", "API_KEY")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no caller":      {[]string{"--secrets", "API_KEY", "--ttl", "1d", "--", "true"}, "--caller"},
		"blank caller":   {[]string{"--caller", " ", "--secrets", "API_KEY", "--ttl", "1d", "--", "true"}, "--caller"},
		"no secrets":     {[]string{"--caller", "x", "--ttl", "1d", "--", "true"}, "--secrets"},
		"no ttl":         {[]string{"--caller", "x", "--secrets", "API_KEY", "--", "true"}, "--ttl"},
		"bad ttl":        {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "soon", "--", "true"}, "--ttl"},
		"zero ttl":       {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "0s", "--", "true"}, "--ttl"},
		"negative ttl":   {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "-1h", "--", "true"}, "--ttl"},
		"no command":     {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "1d"}, "command prefix"},
		"negative uses":  {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "1d", "--uses", "-1", "--", "true"}, "--uses"},
		"ttl too long":   {[]string{"--caller", "x", "--secrets", "API_KEY", "--ttl", "91d", "--", "true"}, "exceeds the maximum standing grant lifetime of 90d"},
		"unknown secret": {[]string{"--caller", "x", "--secrets", "NOPE", "--ttl", "1d", "--", "true"}, "secret_not_found"},
	} {
		_, _, err := cli(t, "", append([]string{"grants", "add"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	if d.ap.asked() != 0 {
		t.Errorf("approver asked %d times for invalid requests", d.ap.asked())
	}
}

func TestCLIGrantsAddDeniedAndRefused(t *testing.T) {
	d := startTestDaemon(t, true)
	dir := t.TempDir()
	t.Chdir(dir)
	mustCLI(t, secretValue, "set", "API_KEY")
	d.ap.allow = false
	_, _, err := cli(t, "", "grants", "add", "--caller", "x", "--secrets", "API_KEY", "--ttl", "1d", "--", "true")
	if c := exitCodeOf(err); c != 77 || !strings.Contains(err.Error(), "user_denied") {
		t.Errorf("denied: code=%d err=%v", c, err)
	}
	if o := mustCLI(t, "", "grants"); strings.Contains(o, "API_KEY") {
		t.Errorf("a denied grant is listed: %q", o)
	}
	d.ap.allow = true
	if err := os.WriteFile(".grantpin.yml", []byte("version: 1\nsecrets: [OTHER]\ncommands:\n  - [true]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := d.ap.asked()
	_, _, err = cli(t, "", "grants", "add", "--caller", "x", "--secrets", "API_KEY", "--ttl", "1d", "--", "true")
	if c := exitCodeOf(err); c != 78 || !strings.Contains(err.Error(), "API_KEY") {
		t.Errorf("policy: code=%d err=%v", c, err)
	}
	if d.ap.asked() != asked {
		t.Error("approver asked for a policy-refused standing grant")
	}
}

func TestFormatRemaining(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:                      "expired",
		0:                                 "expired",
		400 * time.Millisecond:            "expired",
		59*time.Minute + 30*time.Second:   "59m30s",
		47 * time.Hour:                    "47h0m0s",
		48 * time.Hour:                    "2d 0h",
		30*24*time.Hour - time.Second/2:   "30d 0h",
		30*24*time.Hour - 3*time.Second:   "30d 0h",
		29*24*time.Hour + 23*time.Hour:    "29d 23h",
		90*24*time.Hour + 5*time.Minute:   "90d 0h",
		7*24*time.Hour + 5*time.Hour + 59: "7d 5h",
	} {
		if got := formatRemaining(d); got != want {
			t.Errorf("formatRemaining(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestCLIGrantsAddPrintsCanonicalCaller(t *testing.T) {
	d := startTestDaemon(t, true)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	t.Chdir(dir)
	mustCLI(t, secretValue, "set", "API_KEY")
	out := mustCLI(t, "", "grants", "add", "--caller", "Claude Code", "--secrets", "API_KEY", "--ttl", "1h", "--", "true")
	if !strings.Contains(out, `caller stored as "claude-code"`) || !strings.Contains(out, "claude-code may run") {
		t.Errorf("output = %q", out)
	}
	if r := d.ap.lastReq(); r.Caller != "claude-code" {
		t.Errorf("approval caller = %q", r.Caller)
	}
	// Spelled canonically already: no note.
	out = mustCLI(t, "", "grants", "add", "--caller", "claude-code", "--secrets", "API_KEY", "--ttl", "1h", "--", "false")
	if strings.Contains(out, "caller stored as") {
		t.Errorf("unexpected note: %q", out)
	}
	if _, _, err := cli(t, "", "grants", "add", "--caller", "!!", "--secrets", "API_KEY", "--ttl", "1h", "--", "true"); err == nil {
		t.Error("caller without letters or digits accepted")
	}
}
