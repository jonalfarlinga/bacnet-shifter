//go:build !windows

package host

import (
	"fmt"
	"os"
)

// checkDir refuses a directory with any group or other permission bit.
func checkDir(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o; chmod 700 %s", ErrOpen, path, perm, path)
	}
	return nil
}
