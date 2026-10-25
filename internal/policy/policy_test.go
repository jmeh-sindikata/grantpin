package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodYAML = `version: 1
secrets:
  - aws/*
  - DB_URL
commands:
  - [php, artisan]
  - [aws]
  - [./deploy.sh]
max_grant_ttl: 4h
`

func write(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, FileName)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // defeat umask
		t.Fatal(err)
	}
	return p
}

func mustLoad(t *testing.T, content string) *Policy {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, content, 0o644)
	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func TestLoadGood(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, goodYAML, 0o600)
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Present() || p.Path() != path || p.Dir() != dir {
		t.Fatalf("bad policy: %+v", p)
	}
	if p.MaxGrantTTL() != 4*time.Hour {
		t.Fatalf("ttl = %v", p.MaxGrantTTL())
	}
	if len(p.Secrets()) != 2 || len(p.Commands()) != 3 {
		t.Fatalf("secrets/commands: %v %v", p.Secrets(), p.Commands())
	}
	// accessors return copies
	p.Secrets()[0] = "x"
	p.Commands()[0][0] = "x"
	if p.Secrets()[0] != "aws/*" || p.Commands()[0][0] != "php" {
		t.Fatal("accessors leak internal state")
	}
}

func TestLoadAbsent(t *testing.T) {
	p, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A stray policy in a parent of the temp dir is possible on a dev machine;
	// only assert shape when none was found.
	if p.Present() {
		t.Skipf("found ambient policy at %s", p.Path())
	}
	if p.Path() != "" || p.Dir() != "" || p.Secrets() != nil || p.Commands() != nil {
		t.Fatal("absent policy should be empty")
	}
	if p.MaxGrantTTL() != DefaultMaxGrantTTL {
		t.Fatalf("ttl = %v", p.MaxGrantTTL())
	}
	if err := p.Check([]string{"anything"}, []string{"rm"}); err != nil {
		t.Fatalf("absent policy Check = %v, want nil", err)
	}
	var nilp *Policy
	if nilp.Present() || nilp.Check([]string{"x"}, nil) != nil || nilp.MaxGrantTTL() != DefaultMaxGrantTTL {
		t.Fatal("nil policy should behave as absent")
	}
}

func TestLoadRelativeCwd(t *testing.T) {
	if _, err := Load("rel/dir"); err == nil {
		t.Fatal("expected error for relative cwd")
	}
}

func TestWalkUpNearestWins(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "version: 1\nsecrets: [ROOT]\ncommands: [[x]]\n", 0o644)
	mid := filepath.Join(root, "a")
	midPath := write(t, mid, "version: 1\nsecrets: [MID]\ncommands: [[x]]\n", 0o644)

	p, err := Load(child)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path() != midPath || p.Secrets()[0] != "MID" {
		t.Fatalf("expected nearest ancestor, got %s", p.Path())
	}
	// uncleaned cwd with .. still resolves lexically
	p, err = Load(filepath.Join(child, "..", ".."))
	if err != nil || p.Path() != midPath {
		t.Fatalf("got %v %v", p, err)
	}
	// from the root dir the root policy is found
	p, err = Load(root)
	if err != nil || p.Secrets()[0] != "ROOT" {
		t.Fatalf("got %v %v", p, err)
	}
}

func TestWalkStopsAtRoot(t *testing.T) {
	// "/" is absolute; this must terminate (not loop) regardless of outcome.
	if _, err := Load("/"); err != nil {
		t.Skipf("ambient policy at /: %v", err)
	}
}

func TestWalkPastNonDirAndDirNamedPolicy(t *testing.T) {
	root := t.TempDir()
	write(t, root, "version: 1\nsecrets: [A]\ncommands: [[x]]\n", 0o644)
	f := filepath.Join(root, "file")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// cwd is a regular file: .grantd.yml under it gives ENOTDIR, keep walking.
	p, err := Load(f)
	if err != nil || !p.Present() {
		t.Fatalf("got %v %v", p, err)
	}
	// A directory called .grantd.yml is refused, not skipped.
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(filepath.Join(sub, FileName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sub); !errors.Is(err, ErrInsecurePolicy) {
		t.Fatalf("err = %v", err)
	}
}

func TestBrokenNearestDoesNotFallThrough(t *testing.T) {
	root := t.TempDir()
	write(t, root, goodYAML, 0o644)
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, sub, "version: 2\n", 0o644)
	if _, err := Load(sub); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidFiles(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"no version":       "secrets: [A]\n",
		"bad version":      "version: 2\n",
		"zero version":     "version: 0\n",
		"unknown key":      "version: 1\nsecretz: [A]\n",
		"unknown nested":   "version: 1\nextra: {a: b}\n",
		"two docs":         "version: 1\n---\nversion: 1\n",
		"bad yaml":         "version: [1\n",
		"wrong type":       "version: 1\nsecrets: nope\n",
		"empty secret":     "version: 1\nsecrets: ['']\n",
		"bad glob":         "version: 1\nsecrets: ['a[']\n",
		"empty command":    "version: 1\ncommands: [[]]\n",
		"empty cmd elem":   "version: 1\ncommands: [['']]\n",
		"ttl zero":         "version: 1\nmax_grant_ttl: 0s\n",
		"ttl negative":     "version: 1\nmax_grant_ttl: -1h\n",
		"ttl garbage":      "version: 1\nmax_grant_ttl: soon\n",
		"ttl days garbage": "version: 1\nmax_grant_ttl: xd\n",
		"ttl zero days":    "version: 1\nmax_grant_ttl: 0d\n",
		"too large":        "version: 1\n# " + strings.Repeat("x", maxFileSize) + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, content, 0o644)
			p, err := Load(dir)
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("err = %v (policy %v), want ErrInvalidPolicy", err, p)
			}
		})
	}
}

func TestMaxGrantTTL(t *testing.T) {
	cases := map[string]time.Duration{
		"":                      DefaultMaxGrantTTL,
		"max_grant_ttl: 4h":     4 * time.Hour,
		"max_grant_ttl: 90m":    90 * time.Minute,
		"max_grant_ttl: 1h30m":  90 * time.Minute,
		"max_grant_ttl: 2d":     48 * time.Hour,
		"max_grant_ttl: ' 3h '": 3 * time.Hour,
	}
	for line, want := range cases {
		p := mustLoad(t, "version: 1\n"+line+"\n")
		if got := p.MaxGrantTTL(); got != want {
			t.Errorf("%q: got %v want %v", line, got, want)
		}
	}
}

func TestNumericCommandElements(t *testing.T) {
	p := mustLoad(t, "version: 1\nsecrets: [A]\ncommands: [[echo, 1]]\n")
	if err := p.Check([]string{"A"}, []string{"echo", "1"}); err != nil {
		t.Fatal(err)
	}
}

func TestPermissions(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, goodYAML, 0o666)
	_, err := Load(dir)
	var ie *InsecurePolicyError
	if !errors.Is(err, ErrInsecurePolicy) || !errors.As(err, &ie) || ie.Reason != "world-writable" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), FileName) {
		t.Fatalf("error should name file: %v", err)
	}

	// group-writable is accepted (documented choice)
	write(t, dir, goodYAML, 0o664)
	if _, err := Load(dir); err != nil {
		t.Fatalf("group-writable: %v", err)
	}

	// foreign owner
	old := currentUID
	t.Cleanup(func() { currentUID = old })
	currentUID = func() int { return os.Getuid() + 1 }
	_, err = Load(dir)
	if !errors.Is(err, ErrInsecurePolicy) || !errors.As(err, &ie) || !strings.Contains(ie.Reason, "not owned") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckSecrets(t *testing.T) {
	p := mustLoad(t, goodYAML)
	argv := []string{"aws", "s3", "ls"}
	ok := [][]string{
		{"DB_URL"},
		{"aws/access_key"},
		{"aws/access_key", "DB_URL"},
		{"aws/*"}, // textually present
		nil,
	}
	for _, s := range ok {
		if err := p.Check(s, argv); err != nil {
			t.Errorf("Check(%v) = %v", s, err)
		}
	}
	bad := map[string][]string{
		"OTHER":          {"OTHER"},
		"aws/a/b":        {"aws/a/b"}, // * does not cross /
		"aws":            {"aws"},
		"awsx/key":       {"awsx/key"},
		"aws/**":         {"aws/**"}, // glob not textually present
		"*":              {"*"},
		"DB_*":           {"DB_*"},
		"aws/?":          {"aws/?"},
		"{aws/a,DB_URL}": {"{aws/a,DB_URL}"},
		"empty":          {""},
		"mixed":          {"DB_URL", "NOPE"},
	}
	for name, s := range bad {
		err := p.Check(s, argv)
		var se *SecretNotAllowedError
		if !errors.Is(err, ErrSecretNotAllowed) || !errors.As(err, &se) {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		if errors.Is(err, ErrCommandNotAllowed) {
			t.Errorf("%s: wrongly matches ErrCommandNotAllowed", name)
		}
	}
	err := p.Check([]string{"DB_URL", "NOPE"}, argv)
	var se *SecretNotAllowedError
	if !errors.As(err, &se) || se.Secret != "NOPE" || !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("offending secret not carried: %v", err)
	}
}

func TestCheckLiteralPolicyEntryAndGlobRequest(t *testing.T) {
	p := mustLoad(t, "version: 1\nsecrets: [DB_URL, 'x/**']\ncommands: [[a]]\n")
	for _, s := range []string{"DB_URL", "x/a/b/c", "x/a"} {
		if err := p.Check([]string{s}, []string{"a"}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	// request glob that a policy glob would match as a literal string is still
	// refused unless textually present.
	if err := p.Check([]string{"x/*"}, []string{"a"}); !errors.Is(err, ErrSecretNotAllowed) {
		t.Errorf("err = %v", err)
	}
	if err := p.Check([]string{"x/**"}, []string{"a"}); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestCheckCommands(t *testing.T) {
	p := mustLoad(t, goodYAML)
	ok := [][]string{
		{"php", "artisan"},
		{"php", "artisan", "sync", "--force"},
		{"aws"},
		{"aws", "s3"},
		{"./deploy.sh"},
		{"./deploy.sh", "prod"},
	}
	for _, a := range ok {
		if err := p.Check([]string{"DB_URL"}, a); err != nil {
			t.Errorf("Check(%v) = %v", a, err)
		}
	}
	bad := [][]string{
		nil,
		{},
		{"php"},                    // shorter than prefix
		{"php", "composer"},        // different second element
		{"php", "artisanx"},        // not a string prefix match
		{"sudo", "php", "artisan"}, // prefix not at start
		{"deploy.sh"},              // textual exactness
		{"AWS"},
		{"rm", "-rf", "/"},
	}
	for _, a := range bad {
		err := p.Check([]string{"DB_URL"}, a)
		var ce *CommandNotAllowedError
		if !errors.Is(err, ErrCommandNotAllowed) || !errors.As(err, &ce) {
			t.Errorf("Check(%v) = %v", a, err)
		}
	}
	// returned argv is a copy
	a := []string{"php"}
	err := p.Check(nil, a)
	var ce *CommandNotAllowedError
	errors.As(err, &ce)
	a[0] = "mutated"
	if ce.Argv[0] != "php" {
		t.Fatal("error aliases caller argv")
	}
	if !strings.Contains(err.Error(), "php") {
		t.Fatalf("error should mention argv: %v", err)
	}
}

func TestEmptyListsAllowNothing(t *testing.T) {
	p := mustLoad(t, "version: 1\n")
	if !p.Present() {
		t.Fatal("present")
	}
	if err := p.Check([]string{"A"}, []string{"x"}); !errors.Is(err, ErrSecretNotAllowed) {
		t.Fatalf("err = %v", err)
	}
	if err := p.Check(nil, []string{"x"}); !errors.Is(err, ErrCommandNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}
