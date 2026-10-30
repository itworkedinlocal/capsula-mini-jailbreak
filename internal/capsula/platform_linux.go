package capsula

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

func owned(i os.FileInfo) error {
	v, ok := i.Sys().(*syscall.Stat_t)
	if !ok || v.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("файл принадлежит другому пользователю")
	}
	return nil
}
func openPrivate(p string) (*os.File, error) {
	fd, e := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), p), nil
}
func lockFile(p string) (func(), error) {
	fd, e := unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	i, e := f.Stat()
	if e == nil {
		e = owned(i)
	}
	if e == nil && (!i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Sys().(*syscall.Stat_t).Nlink != 1) {
		e = fmt.Errorf("небезопасная блокировка")
	}
	if e == nil {
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if e != nil {
		f.Close()
		return nil, fmt.Errorf("сеанс уже занят или блокировка небезопасна: %w", e)
	}
	return func() { f.Close() }, nil
}

func privatePermissions(i os.FileInfo) bool { return i.Mode().Perm()&0077 == 0 }
func protectDir(p string) error             { return os.Chmod(p, 0700) }
func availableSpace(p string) (uint64, error) {
	var fs unix.Statfs_t
	if e := unix.Statfs(p, &fs); e != nil {
		return 0, e
	}
	return fs.Bavail * uint64(fs.Bsize), nil
}
func replaceState(tmp, p string) error {
	if e := os.Rename(tmp, p); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func safeRelativePath(p string) bool { return p != "" && !filepath.IsAbs(p) }
