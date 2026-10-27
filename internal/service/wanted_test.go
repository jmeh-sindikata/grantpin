package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWantedCreateIdempotentModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "grantpin") // missing parents
	if Wanted(dir) {
		t.Fatal("wanted before creating")
	}
	for i := 0; i < 2; i++ {
		if err := SetWanted(dir, true); err != nil {
			t.Fatal(err)
		}
		if !Wanted(dir) {
			t.Fatal("not wanted after SetWanted(true)")
		}
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("data dir: %v %v", di, err)
	}
	p := filepath.Join(dir, WantedFile)
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 0 || !fi.Mode().IsRegular() {
		t.Errorf("marker: %v %v", fi, err)
	}
	// A loose pre-existing marker is tightened, not recreated.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetWanted(dir, true); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
}

func TestWantedExistingDirectoryKept(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SetWanted(dir, true); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
		t.Errorf("existing data dir mode changed to %v", fi.Mode().Perm())
	}
}

func TestWantedRemove(t *testing.T) {
	dir := t.TempDir()
	if err := SetWanted(dir, false); err != nil { // absent
		t.Fatal(err)
	}
	if err := SetWanted(filepath.Join(dir, "missing"), false); err != nil { // dir absent
		t.Fatal(err)
	}
	if err := SetWanted(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := SetWanted(dir, false); err != nil {
		t.Fatal(err)
	}
	if Wanted(dir) {
		t.Error("still wanted")
	}
	if _, err := os.Lstat(filepath.Join(dir, WantedFile)); !os.IsNotExist(err) {
		t.Errorf("marker remains: %v", err)
	}
	// A directory at the marker path is neither wanted nor removed.
	if err := os.Mkdir(filepath.Join(dir, WantedFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if Wanted(dir) {
		t.Error("directory counts as wanted")
	}
	if err := SetWanted(dir, false); err == nil {
		t.Error("removed a directory")
	}
	if err := SetWanted(dir, true); err == nil {
		t.Error("created over a directory")
	}
}

func TestWantedSymlinkNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, WantedFile)
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	if Wanted(dir) {
		t.Error("symlink counts as wanted")
	}
	if err := SetWanted(dir, true); err == nil {
		t.Error("SetWanted(true) accepted a symlink")
	}
	fi, _ := os.Stat(outside)
	b, _ := os.ReadFile(outside)
	if string(b) != "keep" || fi.Mode().Perm() != 0o644 {
		t.Errorf("symlink target touched: %q %v", b, fi.Mode().Perm())
	}
	// Dangling symlink: O_EXCL must not create the target either.
	os.Remove(p)
	dangling := filepath.Join(t.TempDir(), "nope")
	if err := os.Symlink(dangling, p); err != nil {
		t.Fatal(err)
	}
	if err := SetWanted(dir, true); err == nil {
		t.Error("SetWanted(true) accepted a dangling symlink")
	}
	if _, err := os.Lstat(dangling); !os.IsNotExist(err) {
		t.Errorf("dangling target created: %v", err)
	}
	// Removing unlinks the symlink only.
	if err := SetWanted(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Error("symlink not removed")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Error("symlink target removed or changed")
	}
}

func TestWantedRejectsRelativeDir(t *testing.T) {
	for _, d := range []string{"", "rel/dir"} {
		if Wanted(d) {
			t.Errorf("Wanted(%q)", d)
		}
		if SetWanted(d, true) == nil || SetWanted(d, false) == nil {
			t.Errorf("SetWanted(%q) accepted", d)
		}
	}
}
