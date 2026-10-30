package capsula

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func userSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

// Elevated tokens create objects owned by BUILTIN\Administrators by default.
// Permit reopening those objects after returning to an ordinary token too.
// Access remains restricted to this user and SYSTEM by the separate DACL check.
func privateOwnerMatches(owner, me *windows.SID) bool {
	return owner.Equals(me) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func owned(_ os.FileInfo) error             { return nil }  // Ownership and DACL are checked on the open handle.
func privatePermissions(_ os.FileInfo) bool { return true } // Unix mode bits do not represent Windows access.

func checkPrivateHandle(h windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!directory && info.NumberOfLinks != 1) {
		return fmt.Errorf("ссылка вместо приватного файла/каталога")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fmt.Errorf("неверный тип приватного объекта")
	}
	me, err := userSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !privateOwnerMatches(owner, me) {
		return fmt.Errorf("приватный файл принадлежит другому пользователю")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount == 0 {
		return fmt.Errorf("нет приватного ACL")
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, n, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("неподдерживаемый приватный ACL")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(me) && !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return fmt.Errorf("приватный файл доступен другому пользователю")
		}
	}
	return nil
}

func openWindowsPath(p string, access, disposition uint32) (windows.Handle, error) {
	if err := rejectReparsePath(p); err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(ptr, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func openPrivate(p string) (*os.File, error) {
	h, err := openWindowsPath(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.OPEN_EXISTING)
	if err != nil {
		return nil, err
	}
	if err = checkPrivateHandle(h, false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), p), nil
}

func protectDir(p string) error {
	h, err := openWindowsPath(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	me, err := userSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !privateOwnerMatches(owner, me) {
		return fmt.Errorf("каталог принадлежит другому пользователю")
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + me.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	acl, _, err := private.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	return checkPrivateHandle(h, true)
}

func rejectReparsePath(p string) error {
	p, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	for {
		ptr, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(ptr)
		if err == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point в пути %s", p)
		}
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return err
		}
		next := filepath.Dir(p)
		if next == p {
			return nil
		}
		p = next
	}
}

func lockFile(p string) (func(), error) {
	h, err := openWindowsPath(p, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.OPEN_ALWAYS)
	if err != nil {
		return nil, err
	}
	if err = checkPrivateHandle(h, false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("сеанс уже занят: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}

func availableSpace(p string) (uint64, error) {
	ptr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	var free uint64
	err = windows.GetDiskFreeSpaceEx(ptr, &free, nil, nil)
	return free, err
}

func replaceState(tmp, p string) error {
	if err := rejectReparsePath(p); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func safeRelativePath(p string) bool {
	if p == "" || filepath.IsAbs(p) || filepath.VolumeName(p) != "" || strings.Contains(p, ":") || strings.ContainsAny(p, "\x00") || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(strings.ReplaceAll(p, `\`, "/"), "/") {
		if part == ".." {
			return false
		}
		if strings.TrimRight(part, " .") != part {
			return false
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9') {
			return false
		}
	}
	return true
}
