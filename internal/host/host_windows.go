//go:build windows

package host

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkDir reads the directory's discretionary access control list and
// refuses it when any access-allowed entry names a principal other than
// the directory's owner, the current account, SYSTEM and the local
// Administrators group. A directory with no list at all is open to
// everyone and refused too. Deny entries narrow access and are ignored.
func checkDir(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the access control list of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("reading the access control list of %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: %s has no access control list, so everyone can read it; %s", ErrOpen, path, fix(path))
	}
	me, err := currentUser()
	if err != nil {
		return err
	}
	var others []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading entry %d of the access control list of %s: %w", i, path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(owner) || sid.Equals(me) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			continue
		}
		others = append(others, accountName(sid))
	}
	if len(others) > 0 {
		return fmt.Errorf("%w: %s grants access to %s; %s", ErrOpen, path, strings.Join(others, ", "), fix(path))
	}
	return nil
}

// currentUser is the SID of the account the shifter runs as.
func currentUser() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("reading the current account: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("reading the current account: %w", err)
	}
	return user.User.Sid, nil
}

// accountName names a SID as DOMAIN\name, or as the SID itself when the
// name cannot be looked up.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// fix is the icacls command that leaves the directory to the account,
// SYSTEM and Administrators.
func fix(path string) string {
	return fmt.Sprintf(`fix with: icacls "%s" /inheritance:r /grant:r "%%USERNAME%%:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F"`, path)
}
