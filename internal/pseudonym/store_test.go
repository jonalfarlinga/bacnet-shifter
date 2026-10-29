package pseudonym

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The key file is created in the store asked for, read back in whichever
// store it is in, and rewritten when the store asked for differs; the
// DPAPI store, on Windows, holds no hex.
func TestKeyStores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	k, created, converted, err := LoadOrCreateIn(path, StoreFile)
	if err != nil || !created || converted || len(k) != KeySize {
		t.Fatalf("create: %v, created %t, converted %t", err, created, converted)
	}
	again, created, converted, err := LoadOrCreateIn(path, StoreFile)
	if err != nil || created || converted || again.String() != k.String() {
		t.Fatalf("read: %v, created %t, converted %t", err, created, converted)
	}
	if _, err := ParseStore("vault"); err == nil {
		t.Error("an unknown store was accepted")
	}
	if s, err := ParseStore(""); err != nil || s != StoreFile {
		t.Errorf("the empty store is not file: %v, %v", s, err)
	}
	if runtime.GOOS != "windows" {
		if _, err := ParseStore("dpapi"); err == nil {
			t.Error("dpapi was accepted off Windows")
		}
		return
	}
	dp, created, converted, err := LoadOrCreateIn(path, StoreDPAPI)
	if err != nil || created || !converted || dp.String() != k.String() {
		t.Fatalf("convert to dpapi: %v, created %t, converted %t", err, created, converted)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), dpapiPrefix) || strings.Contains(string(b), k.String()) {
		t.Errorf("the dpapi key file holds %q", b)
	}
	same, created, converted, err := LoadOrCreateIn(path, StoreDPAPI)
	if err != nil || created || converted || same.String() != k.String() {
		t.Fatalf("read dpapi: %v, created %t, converted %t", err, created, converted)
	}
	back, _, converted, err := LoadOrCreateIn(path, StoreFile)
	if err != nil || !converted || back.String() != k.String() {
		t.Fatalf("convert back to file: %v, converted %t", err, converted)
	}
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != k.String() {
		t.Errorf("the file key is %q", b)
	}
	if _, _, err := decodeFile("dpapi:not base64!"); err == nil {
		t.Error("a bad blob was accepted")
	}
}
