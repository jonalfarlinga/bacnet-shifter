package host

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// A directory readable by the account alone passes; one opened to others
// is refused with ErrOpen and an error that says how to fix it.
func TestCheckDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// A temp directory inherits whatever the profile grants, which on
		// some hosts is more than the account: lock it first, as the
		// README's fix command does, with SYSTEM and Administrators by
		// SID so that the test does not depend on the language of the
		// host.
		user := os.Getenv("USERNAME")
		if user == "" {
			t.Skip("no USERNAME to lock the directory to")
		}
		out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", user+":(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
		if err != nil {
			t.Skipf("icacls could not lock the directory: %v: %s", err, out)
		}
	}
	if err := CheckDir(dir); err != nil {
		t.Fatalf("a directory of the account's own is refused: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Everyone (S-1-1-0), by SID so that the test does not depend on
		// the language of the host.
		if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:R").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v: %s", err, out)
		}
	} else if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	err := CheckDir(dir)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("an opened directory is not refused: %v", err)
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("icacls", dir, "/remove:g", "*S-1-1-0").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v: %s", err, out)
		}
	} else if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir); err != nil {
		t.Errorf("after the fix the directory is still refused: %v", err)
	}
	if err := CheckDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory passed")
	}
	t.Logf("refusal reads: %v", err)
}
