package pseudonym

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jonalfarlinga/bacnet/objects"
)

func testKey(t *testing.T, fill byte) Key {
	t.Helper()
	k := make(Key, KeySize)
	for i := range k {
		k[i] = fill
	}
	return k
}

// The derivation is a pure function of the key and the input: the same key
// gives the same pseudonym every time, and a different key a different one,
// for every kind.
func TestDerivationIsStable(t *testing.T) {
	a, b := New(testKey(t, 1)), New(testKey(t, 2))
	again := New(testKey(t, 1))

	n := a.Name(1001, objects.ObjectTypeAnalogInput, 3, "AHU1.OAT", 0)
	if n != again.Name(1001, objects.ObjectTypeAnalogInput, 3, "AHU1.OAT", 0) {
		t.Errorf("the same key gave two names: %s", n)
	} else if n == b.Name(1001, objects.ObjectTypeAnalogInput, 3, "AHU1.OAT", 0) {
		t.Errorf("two keys gave one name: %s", n)
	} else if !regexp.MustCompile("^AI-[0-9a-f]{12}$").MatchString(n) {
		t.Errorf("name %q is not AI- and 12 hex characters", n)
	}
	if dev := a.Name(1001, objects.ObjectTypeDevice, 1001, "AHU-1", 0); dev[:4] != "DEV-" {
		t.Errorf("a device's name is %q, want DEV-...", dev)
	}
	if a.Name(1001, 0, 3, "", 0) != "" || a.Text(1001, 0, 3, 28, "") != "" {
		t.Error("an empty string did not stay empty")
	}

	for name, f := range map[string]func(*Deriver) string{
		"text": func(d *Deriver) string {
			return d.Text(1001, 0, 3, uint32(objects.PropertyIdDescription), "Outside air")
		},
		"instance": func(d *Deriver) string { return dec(d.Instance(1001, 0)) },
		"mac":      func(d *Deriver) string { return dec(d.MAC(1001, 0)) },
		"network":  func(d *Deriver) string { return dec(d.Network(2001, 0)) },
	} {
		if f(a) != f(again) {
			t.Errorf("%s: the same key gave two values", name)
		}
		if f(a) == f(b) {
			t.Errorf("%s: two keys gave one value %s", name, f(a))
		}
	}
	if !strings.HasPrefix(a.Text(1, 0, 0, uint32(objects.PropertyIdDescription), "x"), "desc-") ||
		!strings.HasPrefix(a.Text(1, 0, 0, uint32(objects.PropertyIdLocation), "x"), "loc-") ||
		!strings.HasPrefix(a.Text(1, 0, 0, uint32(objects.PropertyIdSerialNumber), "x"), "sn-") ||
		!strings.HasPrefix(a.Text(1, 0, 0, uint32(objects.PropertyIdModelName), "x"), "model-") ||
		!strings.HasPrefix(a.Text(1, 0, 0, 999, "x"), "p999-") {
		t.Error("a text prefix is wrong")
	}
}

// The real name is part of a name's input, so a renamed object gets a new
// pseudonym; a candidate differs from candidate 0.
func TestNameInputs(t *testing.T) {
	d := New(testKey(t, 3))
	if d.Name(1, 0, 3, "a", 0) == d.Name(1, 0, 3, "b", 0) {
		t.Error("two names gave one pseudonym")
	}
	if d.Name(1, 0, 3, "a", 0) == d.Name(1, 0, 3, "a", 1) {
		t.Error("candidate 1 equals candidate 0")
	}
	if d.Instance(7, 0) == d.Instance(7, 1) || d.MAC(7, 0) == d.MAC(7, 1) || d.Network(7, 0) == d.Network(7, 1) {
		t.Error("a numeric candidate 1 equals candidate 0")
	}
}

// Every numeric pseudonym is in its range, over many inputs, and the widths
// can be narrowed.
func TestRanges(t *testing.T) {
	d := New(testKey(t, 4))
	for i := uint32(0); i < 5000; i++ {
		if v := d.Instance(i, 0); v >= Instances {
			t.Fatalf("instance %d is out of range", v)
		}
		if v := d.MAC(i, 0); v == 0 || v == 0xFFFF {
			t.Fatalf("MAC %d is out of range", v)
		}
		if v := d.Network(uint16(i), 0); v == 0 || v == 0xFFFF {
			t.Fatalf("network %d is out of range", v)
		}
	}
	d.NameHex, d.Instances, d.MACs, d.Networks = 1, 2, 2, 2
	if n := d.Name(1, 0, 1, "x", 0); len(n) != len("AI-")+1 {
		t.Errorf("narrowed name is %q", n)
	}
	for i := uint32(0); i < 50; i++ {
		if d.Instance(i, 0) > 1 || d.MAC(i, 0) > 2 || d.MAC(i, 0) == 0 || d.Network(uint16(i), 0) > 2 {
			t.Fatal("a narrowed value is out of its range")
		}
	}
}

func TestAbbrev(t *testing.T) {
	for typ, want := range map[uint16]string{0: "AI", 8: "DEV", 20: "TL", 15: "NC", 52: "AE", 59: "LIFT", 128: "T128", 300: "T300"} {
		if got := Abbrev(typ); got != want {
			t.Errorf("Abbrev(%d) = %s, want %s", typ, got, want)
		}
	}
}

// The key file is created on first use with the owner-only mode, read back
// identically, and refused when it is not a key.
func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	k, created, err := LoadOrCreate(path)
	if err != nil || !created || len(k) != KeySize {
		t.Fatalf("first load: key %d bytes, created %t, err %v", len(k), created, err)
	}
	again, created, err := LoadOrCreate(path)
	if err != nil || created || again.String() != k.String() {
		t.Fatalf("second load: created %t, err %v, same %t", created, err, again.String() == k.String())
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if m := info.Mode().Perm(); m&0o077 != 0 && os.PathSeparator != '\\' {
		t.Errorf("the key file has mode %o, want owner-only", m)
	}
	if err := os.WriteFile(path, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Error("a file that is not a key was accepted")
	}
	if _, err := ParseKey("abcd"); err == nil {
		t.Error("a short key was accepted")
	}
}
