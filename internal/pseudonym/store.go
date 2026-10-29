package pseudonym

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Store is how the key file holds the key.
type Store string

const (
	// StoreFile is the key in hex, as the file has always held it.
	StoreFile Store = "file"
	// StoreDPAPI is the key encrypted with the Windows Data Protection API
	// to the account that runs the shifter: a copied data directory, or
	// the file read by another account, gives nothing. Windows only.
	StoreDPAPI Store = "dpapi"
)

// ParseStore reads a store name.
func ParseStore(s string) (Store, error) {
	switch Store(strings.ToLower(strings.TrimSpace(s))) {
	case StoreFile, "":
		return StoreFile, nil
	case StoreDPAPI:
		if !dpapiAvailable {
			return "", errors.New("data.key_store dpapi is Windows only")
		}
		return StoreDPAPI, nil
	}
	return "", fmt.Errorf("data.key_store %q is not file or dpapi", s)
}

// dpapiPrefix heads a key file that holds a DPAPI blob, base64 after it.
const dpapiPrefix = "dpapi:"

// decodeFile reads a key as the file holds it, in either store, and says
// which store that was.
func decodeFile(text string) (Key, Store, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, dpapiPrefix) {
		k, err := ParseKey(text)
		return k, StoreFile, err
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, dpapiPrefix))
	if err != nil {
		return nil, StoreDPAPI, fmt.Errorf("the key file holds a DPAPI blob that is not base64: %w", err)
	}
	k, err := dpapiUnprotect(blob)
	if err != nil {
		return nil, StoreDPAPI, fmt.Errorf("the key file holds a DPAPI blob this account cannot decrypt: %w", err)
	}
	if len(k) != KeySize {
		return nil, StoreDPAPI, fmt.Errorf("the decrypted key is %d bytes, want %d", len(k), KeySize)
	}
	return Key(k), StoreDPAPI, nil
}

// encodeFile renders a key for the file in a store.
func encodeFile(k Key, store Store) (string, error) {
	if store != StoreDPAPI {
		return k.String() + "\n", nil
	}
	blob, err := dpapiProtect([]byte(k))
	if err != nil {
		return "", fmt.Errorf("encrypting the key: %w", err)
	}
	return dpapiPrefix + base64.StdEncoding.EncodeToString(blob) + "\n", nil
}

// LoadOrCreateIn is LoadOrCreate for a store: the key file is read in
// whichever store it is in, and rewritten in the store asked for when
// that differs, which converted reports. A missing file gets a new key in
// the store asked for.
func LoadOrCreateIn(path string, store Store) (k Key, created, converted bool, err error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if k, err = Generate(); err != nil {
			return nil, false, false, err
		}
		text, err := encodeFile(k, store)
		if err != nil {
			return nil, false, false, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, false, false, err
		}
		if _, err := f.WriteString(text); err != nil {
			f.Close()
			return nil, false, false, err
		}
		return k, true, false, f.Close()
	case err != nil:
		return nil, false, false, err
	}
	k, held, err := decodeFile(string(b))
	if err != nil {
		return nil, false, false, fmt.Errorf("%s: %w", path, err)
	}
	if held == store {
		return k, false, false, nil
	}
	text, err := encodeFile(k, store)
	if err != nil {
		return nil, false, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return nil, false, false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, false, false, err
	}
	return k, false, true, nil
}
