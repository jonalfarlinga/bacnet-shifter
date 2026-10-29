// Package host checks what the shifter needs of the host it runs on: that
// the data directory, which holds the de-anonymization secret, is readable
// by the shifter's own account only. The check is the platform's: the mode
// bits on Unix, the access control list on Windows. The shifter refuses to
// start when it fails, unless told to skip it.
package host

import (
	"errors"
	"fmt"
	"os"
)

// ErrOpen is a data directory that anyone but the shifter's account can
// read. The error that wraps it names who, and how to fix it.
var ErrOpen = errors.New("the data directory is readable by others")

// CheckDir reports whether the directory is readable by the current
// account only, with an error that wraps ErrOpen when it is not.
func CheckDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return checkDir(path, info)
}
