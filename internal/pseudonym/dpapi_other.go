//go:build !windows

package pseudonym

import "errors"

const dpapiAvailable = false

var errNoDPAPI = errors.New("the Data Protection API is Windows only")

func dpapiProtect([]byte) ([]byte, error)   { return nil, errNoDPAPI }
func dpapiUnprotect([]byte) ([]byte, error) { return nil, errNoDPAPI }
