package cataloguev1

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var errPrivateRecord = errors.New("catalogue v1 persisted file is not a private bounded regular file")

// The console writes these files as 0600. Kubernetes fsGroup may add group
// read/write on a volume, yielding 0660 while retaining the writer UID and the
// console's intended GID. Read through one no-follow descriptor so a pathname
// swap cannot substitute different bytes between a separate Stat and ReadFile.
func readPrivateRecord(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, errPrivateRecord
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !trustedPrivateRecord(before, os.Geteuid(), os.Getegid()) {
		return nil, errPrivateRecord
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil || len(raw) != int(before.Size()) {
		return nil, errPrivateRecord
	}
	afterFD, err := f.Stat()
	if err != nil || !trustedPrivateRecord(afterFD, os.Geteuid(), os.Getegid()) || !samePrivateRecord(before, afterFD) {
		return nil, errPrivateRecord
	}
	afterPath, err := os.Lstat(path)
	if err != nil || !trustedPrivateRecord(afterPath, os.Geteuid(), os.Getegid()) || !samePrivateRecord(before, afterPath) {
		return nil, errPrivateRecord
	}
	return raw, nil
}

func trustedPrivateRecord(info os.FileInfo, euid, egid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRecordBytes ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(euid) {
		return false
	}
	switch info.Mode().Perm() {
	case 0o600:
		return true
	case 0o660:
		return stat.Gid == uint32(egid)
	default:
		return false
	}
}

func samePrivateRecord(before, after os.FileInfo) bool {
	if before == nil || after == nil || !os.SameFile(before, after) ||
		before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	return aOK && bOK && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Ctim == b.Ctim
}
