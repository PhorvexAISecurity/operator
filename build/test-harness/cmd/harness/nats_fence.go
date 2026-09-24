package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireNATSFence excludes the original harness and a later read-only
// reconciler from the same run. The stable inode is also bound into the
// pre-effect anchor, so unlinking/replacing the lock file cannot prove exit.
func acquireNATSFence(out string) (*os.File, string, error) {
	if out == "" {
		return nil, "", errors.New("NATS run output directory unavailable")
	}
	if err := os.MkdirAll(out, 0750); err != nil {
		return nil, "", err
	}
	path := filepath.Join(out, "nats-baseline.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, "", err
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, "", errors.New("NATS fence is not one regular owned file")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("original NATS run may still hold process fence: %w", err)
	}
	var current syscall.Stat_t
	if err = syscall.Lstat(path, &current); err != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Mode&syscall.S_IFMT != syscall.S_IFREG {
		f.Close()
		return nil, "", errors.New("NATS process fence path was replaced")
	}
	// A replaced file can receive a recently freed inode. Bind a durable random
	// file token as well as dev/inode; only the lock holder may initialize it.
	token := make([]byte, 32)
	switch st.Size {
	case 0:
		seed := make([]byte, 16)
		if _, err := rand.Read(seed); err != nil {
			f.Close()
			return nil, "", err
		}
		copy(token, hex.EncodeToString(seed))
		if _, err := f.WriteAt(token, 0); err != nil {
			f.Close()
			return nil, "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, "", err
		}
	case 32:
		if _, err := f.ReadAt(token, 0); err != nil {
			f.Close()
			return nil, "", err
		}
		if _, err := hex.DecodeString(string(token)); err != nil {
			f.Close()
			return nil, "", errors.New("NATS fence token invalid")
		}
	default:
		f.Close()
		return nil, "", errors.New("NATS fence content invalid")
	}
	return f, fmt.Sprintf("flock-v1:%d:%d:%s", st.Dev, st.Ino, token), nil
}
