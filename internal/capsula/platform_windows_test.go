package capsula

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateStateAndLocks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Капсула с пробелами")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "state.json")
	for _, n := range []int{1, 2} {
		if err := SaveSealed(file, map[string]int{"n": n}); err != nil {
			t.Fatal(err)
		}
	}
	var state map[string]int
	if err := ReadSealed(file, &state); err != nil || state["n"] != 2 {
		t.Fatal(state, err)
	}
	lock := filepath.Join(dir, "lock")
	unlock, err := lockFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if release, e := lockFile(lock); e == nil {
		release()
		t.Fatal("second lock accepted")
	}
	unlock()
	unlock, err = lockFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	link := filepath.Join(dir, "hardlink")
	if err = os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if err = ReadSealed(file, &state); err == nil {
		t.Fatal("hardlinked state accepted")
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err = ReadSealed(file, &state); err == nil {
		t.Fatal("world-readable state accepted")
	}
}

func TestWindowsRelativePaths(t *testing.T) {
	for _, bad := range []string{`C:secret`, `C:\secret`, `\\server\share`, `\secret`, `x:stream`, `../secret`, `x\..\secret`, `NUL`, `con.txt`, `COM1`, `LPT9.txt`, `file.`, `file `} {
		if safeRelativePath(bad) {
			t.Fatal("unsafe path accepted", bad)
		}
	}
	for _, good := range []string{"resources/ramboot/Image", "runs/session/state.json", "каталог с пробелами/file"} {
		if !safeRelativePath(good) {
			t.Fatal("safe path rejected", good)
		}
	}
	if unsafe.Sizeof(windows.Overlapped{}) != 32 || unsafe.Sizeof(windows.DevInfoData{}) != 32 || unsafe.Sizeof(windows.DCB{}) != 28 {
		t.Fatal("unexpected Windows ABI")
	}
}

func TestWindowsNativeCredentials(t *testing.T) {
	r := sourceResources(t)
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ключ с пробелами")
	if _, err := r.Native("dropbearmulti", []string{"dropbearkey", "-t", "ed25519", "-f", path}, nil); err != nil {
		t.Fatal(err)
	}
	pub, err := publicHostKey(r, path)
	if err != nil || !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatal(pub, err)
	}
	for _, pw := range [][]byte{[]byte("7"), []byte("пароль 😀"), bytes.Repeat([]byte{'x'}, 512)} {
		hash, e := r.Native("password-hash", nil, pw)
		if e != nil {
			t.Fatalf("password helper failed: %v", e)
		}
		// Exercise the same parser as BuildPackage, not a TrimSpace shortcut.
		normalized, e := normalizeGeneratedPasswordHash(hash)
		if e != nil || !bytes.Equal(normalized, append(bytes.TrimSpace(hash), '\n')) {
			t.Fatalf("password helper output rejected by package builder: %v", e)
		}
	}
	for _, pw := range [][]byte{nil, []byte("x\ny"), bytes.Repeat([]byte{'x'}, 513)} {
		if _, e := r.Native("password-hash", nil, pw); e == nil {
			t.Fatal("invalid helper input accepted")
		}
	}
}
