// Package pseudonym derives the shifter's pseudonyms and keeps the key they
// are derived under (spec §6.1 and §6.2).
//
// Every derivation is HMAC-SHA256 under a per-site secret of a label and the
// real value's fields, so that a pseudonym is a pure function of the key and
// the real value, and nothing without the key can turn it back. A name comes
// out as an abbreviation of the object type and twelve hex characters of the
// digest; a device instance, a virtual MAC and a virtual network number as
// the digest's leading bytes reduced to their range. Collisions are resolved
// by the table (internal/table), which asks for candidate k when candidate
// k-1 is taken.
package pseudonym

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jonalfarlinga/bacnet/objects"
)

// KeySize is the key's length in bytes.
const KeySize = 32

// Key is the per-site HMAC secret.
type Key []byte

// Generate makes a new key from crypto/rand.
func Generate() (Key, error) {
	k := make(Key, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generating the key: %w", err)
	}
	return k, nil
}

// ParseKey reads a key as the key file holds it: hex, with any surrounding
// white space.
func ParseKey(text string) (Key, error) {
	k, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("the key is not hex: %w", err)
	}
	if len(k) != KeySize {
		return nil, fmt.Errorf("the key is %d bytes, want %d", len(k), KeySize)
	}
	return Key(k), nil
}

// String renders the key as the key file holds it. It is never logged.
func (k Key) String() string { return hex.EncodeToString(k) }

// Load reads the key file.
func Load(path string) (Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ParseKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// LoadOrCreate reads the key file, or when there is none, generates a key
// and writes it there with mode 0o600, which NTFS ignores: on Windows the
// directory itself must be one that only the shifter's account can read.
// created reports whether the file was written.
func LoadOrCreate(path string) (k Key, created bool, err error) {
	k, err = Load(path)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if k, err = Generate(); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	if _, err := f.WriteString(k.String() + "\n"); err != nil {
		f.Close()
		return nil, false, err
	}
	if err := f.Close(); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// Limits of the three numeric spaces, as the spec sets them: a device
// instance is 0..4194302, a virtual MAC 1..65534, a virtual network 1..65534.
const (
	Instances = 4194303
	MACs      = 65534
	Networks  = 65534
	// NameHex is how many hex characters of the digest a name carries.
	NameHex = 12
)

// Deriver derives pseudonyms under one key. The widths are exported so that
// a test can narrow them and force collisions; a program leaves them at the
// defaults New sets.
type Deriver struct {
	key Key
	// NameHex is the hex characters of the digest in a name or text
	// pseudonym.
	NameHex int
	// Instances, MACs and Networks are the sizes of the three numeric
	// spaces: an instance is the digest's first four bytes modulo
	// Instances; a MAC and a network number the first two bytes modulo the
	// size, plus one, so that neither is ever 0.
	Instances, MACs, Networks uint32
}

// New makes a Deriver with the default widths.
func New(key Key) *Deriver {
	return &Deriver{key: key, NameHex: NameHex, Instances: Instances, MACs: MACs, Networks: Networks}
}

// digest is H(label, fields..., "#k"): the HMAC of the label and the fields
// joined with "|", numbers in decimal and text as UTF-8, with "#k" as one
// more field for candidate k > 0.
func (d *Deriver) digest(label string, k int, fields ...string) []byte {
	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(label))
	for _, f := range fields {
		mac.Write([]byte{'|'})
		mac.Write([]byte(f))
	}
	if k > 0 {
		mac.Write([]byte("|#" + strconv.Itoa(k)))
	}
	return mac.Sum(nil)
}

func (d *Deriver) hexN(label string, k int, fields ...string) string {
	return hex.EncodeToString(d.digest(label, k, fields...))[:d.NameHex]
}

func dec[T uint16 | uint32](v T) string { return strconv.FormatUint(uint64(v), 10) }

// Name is the pseudonym of an object's name: the type's abbreviation, a
// hyphen and hex of H("name", device instance, object type, object instance,
// real name). An empty name stays empty.
func (d *Deriver) Name(device uint32, objType uint16, objInstance uint32, real string, k int) string {
	if real == "" {
		return ""
	}
	return Abbrev(objType) + "-" + d.hexN("name", k, dec(device), dec(objType), dec(objInstance), real)
}

// Text is the pseudonym of any other replaced string property: a prefix for
// the property, a hyphen and hex of H("text", device instance, object type,
// object instance, property, text). Texts are not identifiers and have no
// candidates. An empty string stays empty.
func (d *Deriver) Text(device uint32, objType uint16, objInstance uint32, property uint32, text string) string {
	if text == "" {
		return ""
	}
	return TextPrefix(property) + "-" + d.hexN("text", 0, dec(device), dec(objType), dec(objInstance), dec(property), text)
}

// Instance is the virtual instance of a device: H("instance", real
// instance), first four bytes big-endian, modulo 4194303.
func (d *Deriver) Instance(real uint32, k int) uint32 {
	return binary.BigEndian.Uint32(d.digest("instance", k, dec(real))) % d.Instances
}

// MAC is the virtual MAC of a device: H("mac", real instance), first two
// bytes big-endian, modulo 65534, plus 1.
func (d *Deriver) MAC(real uint32, k int) uint16 {
	return uint16(uint32(binary.BigEndian.Uint16(d.digest("mac", k, dec(real))))%d.MACs + 1)
}

// Network is the virtual number of a site network: H("network", real
// number), first two bytes big-endian, modulo 65534, plus 1.
func (d *Deriver) Network(real uint16, k int) uint16 {
	return uint16(uint32(binary.BigEndian.Uint16(d.digest("network", k, dec(real))))%d.Networks + 1)
}

// abbrevs is the abbreviation of each standard object type, in the order of
// objects.ObjectTypeMap.
var abbrevs = []string{
	"AI", "AO", "AV", "BI", "BO", "BV", "CAL", "CMD", "DEV", "EE",
	"FILE", "GRP", "LOOP", "MSI", "MSO", "NC", "PROG", "SCH", "AVG", "MSV",
	"TL", "LSP", "LSZ", "ACC", "PC", "EL", "GG", "TLM", "LC", "SV",
	"AD", "TMR", "ACR", "AP", "AR", "AU", "AZ", "CDI", "NS", "BSV",
	"CSV", "DPV", "DV", "DTPV", "DTV", "IV", "LAV", "OSV", "PIV", "TPV",
	"TV", "NF", "AE", "CH", "LO", "BLO", "NP", "EG", "ESC", "LIFT",
}

// Abbrev is the abbreviation of an object type that heads its names'
// pseudonyms: AI, AO, DEV, TL and so on for the standard types, T<number>
// for any other, proprietary types among them.
func Abbrev(objType uint16) string {
	if int(objType) < len(abbrevs) {
		return abbrevs[objType]
	}
	return "T" + dec(objType)
}

// TextPrefix heads the pseudonym of a replaced string property other than
// the name: desc, loc, sn and model for the four defaults, p<id> for a
// property added in configuration.
func TextPrefix(property uint32) string {
	switch property {
	case uint32(objects.PropertyIdDescription):
		return "desc"
	case uint32(objects.PropertyIdLocation):
		return "loc"
	case uint32(objects.PropertyIdSerialNumber):
		return "sn"
	case uint32(objects.PropertyIdModelName):
		return "model"
	}
	return "p" + dec(property)
}
