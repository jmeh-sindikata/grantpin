package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"grantd/internal/client"
)

const secretValue = "s3cr3t-value-ABCDEFG"

func TestCLIEndToEnd(t *testing.T) {
	d := startTestDaemon(t, true)
	dir := t.TempDir()
	t.Chdir(dir)

	// set from stdin (non-TTY): trailing newline stripped.
	out := mustCLI(t, secretValue+"\n", "set", "API_KEY", "--tags", "prod,x", "--url", "https://e.x", "--expires", "30d")
	if !strings.Contains(out, "stored API_KEY") || strings.Contains(out, secretValue) {
		t.Errorf("set output = %q", out)
	}
	if _, _, err := cli(t, "other-value-12345\n", "set", "API_KEY"); err == nil || !strings.Contains(err.Error(), "secret_exists") {
		t.Errorf("duplicate set err = %v", err)
	}
	mustCLI(t, "other-value-12345", "set", "API_KEY", "--overwrite", "--tags", "prod")
	mustCLI(t, secretValue, "set", "API_KEY", "--overwrite", "--tags", "prod,x", "--expires", "30d")
	if _, _, err := cli(t, "", "set", "EMPTY"); err == nil {
		t.Error("empty value accepted")
	}

	out = mustCLI(t, "", "list")
	if !strings.Contains(out, "API_KEY") || !strings.Contains(out, "prod,x") || strings.Contains(out, secretValue) {
		t.Errorf("list output = %q", out)
	}
	if out = mustCLI(t, "", "list", "--tag", "nope"); strings.Contains(out, "API_KEY") {
		t.Errorf("tag filter ignored: %q", out)
	}
	if out = mustCLI(t, "", "list", "--expiring", "7d"); strings.Contains(out, "API_KEY") {
		t.Errorf("expiring filter ignored: %q", out)
	}
	if out = mustCLI(t, "", "list", "--expiring", "60d"); !strings.Contains(out, "API_KEY") {
		t.Errorf("expiring filter wrong: %q", out)
	}
	if out = mustCLI(t, "", "masked", "API_KEY"); out != "****"+secretValue[len(secretValue)-4:]+"\n" {
		t.Errorf("masked output = %q", out)
	}

	// run: redaction on both streams, exit code relay.
	stdout, stderr, err := cli(t, "", "run", "--secrets", "API_KEY", "--", "sh", "-c", `echo "o=$API_KEY"; echo "e=$API_KEY" >&2`)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "o=[REDACTED:API_KEY]\n" || stderr != "e=[REDACTED:API_KEY]\n" {
		t.Errorf("run output stdout=%q stderr=%q", stdout, stderr)
	}
	_, _, err = cli(t, "", "run", "--secrets", "API_KEY", "--", "sh", "-c", "exit 3")
	if c := exitCodeOf(err); c != 3 {
		t.Errorf("exit code = %d (%v)", c, err)
	}
	_, _, err = cli(t, "", "run", "--secrets", "API_KEY", "--timeout", "1s", "--", "sleep", "5")
	if c := exitCodeOf(err); c != 124 {
		t.Errorf("timeout exit code = %d (%v)", c, err)
	}
	// flags after the command belong to the command
	stdout, _, err = cli(t, "", "run", "--secrets", "API_KEY", "--caller", "tester", "--env-prefix", "APP_", "sh", "-c", `echo "$APP_API_KEY"`)
	if err != nil || stdout != "[REDACTED:API_KEY]\n" {
		t.Errorf("env prefix run: %q %v", stdout, err)
	}
	if _, _, err := cli(t, "", "run", "--", "true"); err == nil || !strings.Contains(err.Error(), "--secrets") {
		t.Errorf("missing --secrets err = %v", err)
	}
	if _, _, err := cli(t, "", "run", "--secrets", "API_KEY", "--timeout", "-1s", "--", "true"); err == nil {
		t.Error("negative timeout accepted")
	}
	_, stderr, err = cli(t, "", "run", "--secrets", "API_KEY", "--", "no-such-cmd-xyz")
	if c := exitCodeOf(err); c != 127 || !strings.Contains(stderr, "command not found") {
		t.Errorf("not found: code=%d stderr=%q err=%v", c, stderr, err)
	}
	_, _, err = cli(t, "", "run", "--secrets", "MISSING", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "secret_not_found") || exitCodeOf(err) != 1 {
		t.Errorf("missing secret err = %v", err)
	}

	// denied -> 77
	d.ap.allow = false
	_, _, err = cli(t, "", "run", "--secrets", "API_KEY", "--", "true")
	if c := exitCodeOf(err); c != 77 || !strings.Contains(err.Error(), "user_denied") {
		t.Errorf("denied: code=%d err=%v", c, err)
	}
	d.ap.allow = true

	// refused (policy) -> 78
	if err := os.WriteFile(".grantd.yml", []byte("version: 1\nsecrets: [OTHER]\ncommands:\n  - [true]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := d.ap.asked()
	_, _, err = cli(t, "", "run", "--secrets", "API_KEY", "--", "true")
	if c := exitCodeOf(err); c != 78 || !strings.Contains(err.Error(), "API_KEY") {
		t.Errorf("policy: code=%d err=%v", c, err)
	}
	if d.ap.asked() != asked {
		t.Error("approver asked for policy-refused run")
	}
	if err := os.Remove(".grantd.yml"); err != nil {
		t.Fatal(err)
	}

	// show: refuses without a TTY, before talking to the daemon.
	_, _, err = cli(t, "", "show", "API_KEY")
	if c := exitCodeOf(err); c != 78 || !strings.Contains(err.Error(), "not_tty") {
		t.Errorf("show: code=%d err=%v", c, err)
	}

	// grants + audit
	d.ap.ttl = time.Hour
	mustCLI(t, "", "run", "--secrets", "API_KEY", "--", "true")
	out = mustCLI(t, "", "grants")
	if !strings.Contains(out, "API_KEY") {
		t.Fatalf("grants output = %q", out)
	}
	id := strings.Fields(strings.Split(strings.TrimSpace(out), "\n")[1])[0]
	if o := mustCLI(t, "", "grants", "list"); !strings.Contains(o, id) {
		t.Errorf("grants list = %q", o)
	}
	if _, _, err := cli(t, "", "grants", "revoke", "nope"); err == nil || !strings.Contains(err.Error(), "grant_not_found") {
		t.Errorf("revoke unknown err = %v", err)
	}
	mustCLI(t, "", "grants", "revoke", id)
	mustCLI(t, "", "run", "--secrets", "API_KEY", "--", "true")
	mustCLI(t, "", "grants", "revoke", "--all")
	if o := mustCLI(t, "", "grants"); strings.Contains(o, "API_KEY") {
		t.Errorf("grants after revoke --all = %q", o)
	}
	for _, args := range [][]string{{"grants", "revoke"}, {"grants", "revoke", "x", "--all"}} {
		if _, _, err := cli(t, "", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}

	if o := mustCLI(t, "", "audit"); !strings.Contains(o, "allowed_once") || !strings.Contains(o, "completed") || !strings.Contains(o, "released") || !strings.Contains(o, "denied_user") || !strings.Contains(o, "refused_policy") {
		t.Errorf("audit output = %q", o)
	}
	if o := mustCLI(t, "", "audit", "list", "--limit", "1"); strings.Count(o, "\n") != 2 || !strings.Contains(o, "TOOK") {
		t.Errorf("audit list --limit 1 = %q", o)
	}
	if o := mustCLI(t, "", "audit", "verify"); !strings.Contains(o, "audit chain ok") {
		t.Errorf("verify output = %q", o)
	}
	o := mustCLI(t, "", "audit", "export", "--csv")
	if !strings.HasPrefix(o, "id,") && !strings.Contains(o, "allowed_once") {
		t.Errorf("export output = %q", o)
	}
	for _, s := range []string{o, mustCLI(t, "", "audit")} {
		if strings.Contains(s, secretValue) {
			t.Error("audit output contains the secret value")
		}
	}

	mustCLI(t, "", "delete", "API_KEY")
	if _, _, err := cli(t, "", "delete", "API_KEY"); err == nil || !strings.Contains(err.Error(), "secret_not_found") {
		t.Errorf("second delete err = %v", err)
	}
	if _, _, err := cli(t, "", "masked", "API_KEY"); err == nil {
		t.Error("masked after delete succeeded")
	}
}

func TestCLIImport(t *testing.T) {
	startTestDaemon(t, true)
	file := writeFile(t, ".env", "A_KEY=aaaaaaaaaaaa\nB_KEY=\"bbbbbbbbbbbb\"\nEMPTY=\nA_KEY=aaaaaaaaaaaa2\n")

	out := mustCLI(t, "", "import", file, "--dry-run")
	if !strings.Contains(out, "(dry run) would be added: 2 (A_KEY, B_KEY)") || !strings.Contains(out, "EMPTY") {
		t.Errorf("dry run = %q", out)
	}
	if o := mustCLI(t, "", "list"); strings.Contains(o, "A_KEY") {
		t.Errorf("dry run wrote: %q", o)
	}
	out = mustCLI(t, "", "import", file)
	if !strings.Contains(out, "added: 2 (A_KEY, B_KEY)") || strings.Contains(out, "aaaaaaaaaaaa") {
		t.Errorf("import = %q", out)
	}
	if o := mustCLI(t, "", "masked", "A_KEY"); o != "****aaa2\n" {
		t.Errorf("last duplicate did not win: %q", o)
	}
	// conflict: error (default), skip, overwrite
	if _, _, err := cli(t, "", "import", file); err == nil || !strings.Contains(err.Error(), "A_KEY") {
		t.Errorf("conflict err = %v", err)
	}
	out = mustCLI(t, "", "import", file, "--on-conflict", "skip")
	if !strings.Contains(out, "skipped (exists): 2") {
		t.Errorf("skip = %q", out)
	}
	file2 := writeFile(t, ".env", "A_KEY=zzzzzzzzzzzz9999\nC_KEY=cccccccccccc\n")
	out = mustCLI(t, "", "import", file2, "--on-conflict", "overwrite")
	if !strings.Contains(out, "overwritten: 1 (A_KEY)") || !strings.Contains(out, "added: 1 (C_KEY)") {
		t.Errorf("overwrite = %q", out)
	}
	if o := mustCLI(t, "", "masked", "A_KEY"); o != "****9999\n" {
		t.Errorf("overwrite did not apply: %q", o)
	}
	// stdin and bad input
	if o := mustCLI(t, "D_KEY=dddddddddddd\n", "import", "-"); !strings.Contains(o, "D_KEY") {
		t.Errorf("stdin import = %q", o)
	}
	if _, _, err := cli(t, "", "import", "/nonexistent/.env"); err == nil {
		t.Error("missing file accepted")
	}
	if _, _, err := cli(t, "", "import", file, "--on-conflict", "bogus"); err == nil {
		t.Error("bad mode accepted")
	}
	if o := mustCLI(t, "", "import", writeFile(t, "e", "# nothing\n")); !strings.Contains(o, "nothing to import") {
		t.Errorf("empty import = %q", o)
	}
}

func TestDaemonPicksUpVaultCreatedAfterStart(t *testing.T) {
	startTestDaemon(t, false)
	_, _, err := cli(t, "", "list")
	if err == nil || !strings.Contains(err.Error(), "vault_not_initialized") || !strings.Contains(err.Error(), "grantd init") {
		t.Fatalf("list before init err = %v", err)
	}
	if out := mustCLI(t, "", "status"); !strings.Contains(out, "not initialized") {
		t.Errorf("status = %q", out)
	}
	initTestVault(t)
	mustCLI(t, secretValue, "set", "X")
	out := mustCLI(t, "", "status")
	if !strings.Contains(out, "secrets:      1") || !strings.Contains(out, "initialized") || strings.Contains(out, "not initialized") {
		t.Errorf("status = %q", out)
	}
}

func TestDaemonRefusesUnusableVault(t *testing.T) {
	useFakeBackends(t)
	initTestVault(t)
	vp := os.Getenv("GRANTD_HOME") + "/vault.db"
	if err := os.WriteFile(vp, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runDaemon(t.Context(), shortSocket(t), nil, backendConfig{})
	if err == nil || !strings.Contains(err.Error(), "open vault") {
		t.Fatalf("err = %v", err)
	}
}

func TestNotRunningExitCode(t *testing.T) {
	t.Setenv("GRANTD_SOCKET", shortSocket(t))
	for _, args := range [][]string{
		{"list"}, {"masked", "A"}, {"delete", "A"}, {"grants"}, {"audit"}, {"audit", "verify"},
		{"run", "--secrets", "A", "--", "true"}, {"set", "A"}, {"import", "-"}, {"status"},
	} {
		_, _, err := cli(t, "A=bbbbbbbbbbbb\n", args...)
		if !errors.Is(err, client.ErrNotRunning) || exitCodeOf(err) != 69 || !strings.Contains(err.Error(), "grantd daemon") {
			t.Errorf("%v: err = %v (code %d)", args, err, exitCodeOf(err))
		}
	}
}

func TestExitCodeOf(t *testing.T) {
	if exitCodeOf(&exitError{code: 5}) != 5 || exitCodeOf(errors.New("x")) != 1 {
		t.Error("exitCodeOf mapping wrong")
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d": 30 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "90m": 90 * time.Minute, "1h30m": 90 * time.Minute, " 7d ": 7 * 24 * time.Hour,
	} {
		if got, err := parseDuration(in); err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "d", "-3d", "abc", "99999999d"} {
		if _, err := parseDuration(in); err == nil {
			t.Errorf("parseDuration(%q) accepted", in)
		}
	}
}

func TestReadValue(t *testing.T) {
	var prompt strings.Builder
	for in, want := range map[string]string{"abc": "abc", "abc\n": "abc", "abc\r\n": "abc", "a\nb\n": "a\nb", "": ""} {
		got, err := readValue(strings.NewReader(in), &prompt, "N")
		if err != nil || string(got) != want {
			t.Errorf("readValue(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := readValue(strings.NewReader(strings.Repeat("a", 1<<20+1)), &prompt, "N"); err == nil {
		t.Error("oversized value accepted")
	}
	if prompt.Len() != 0 {
		t.Errorf("prompted on non-TTY: %q", prompt.String())
	}
}

func TestSetFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"set", "A", "--expires", "bogus"}, {"set", "A", "--expires", "0s"}, {"set", "A", "--min-tier", "bogus"},
		{"list", "--expiring", "bogus"}, {"list", "--expiring", "0s"},
	} {
		if _, _, err := cli(t, "value-1234", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestRunInterruptedBySignal(t *testing.T) {
	startTestDaemon(t, true)
	mustCLI(t, secretValue, "set", "API_KEY")
	pidFile := t.TempDir() + "/pid"
	go func() {
		// Wait until the child is up, then interrupt grantd itself.
		for range 200 {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	start := time.Now()
	_, _, err := cli(t, "", "run", "--secrets", "API_KEY", "--", "sh", "-c", "echo $$ > "+pidFile+"; sleep 30")
	if c := exitCodeOf(err); c != 130 {
		t.Fatalf("exit = %d (%v), want 130", c, err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	// The daemon must have killed the child.
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for range 100 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("child %d still running after interrupt", pid)
}
