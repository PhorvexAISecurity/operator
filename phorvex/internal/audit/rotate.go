// Package audit provides process-local, checked size rotation. Each path must have
// exactly one writer process. It does not provide distributed file ownership.
package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type RotatingWriter struct {
	mu         sync.Mutex
	path       string
	capBytes   int64
	maxBackups int
	f          *os.File
	size       int64
	failed     error
}

// capBytes<=0 preserves legacy unbounded mode. With rotation enabled, at least
// one backup is required. Reject unsafe retention before touching any files.
func NewRotatingWriter(path string, capBytes int64, maxBackups int) (*RotatingWriter, error) {
	if capBytes > 0 && maxBackups <= 0 {
		return nil, fmt.Errorf("audit rotation requires audit-max-backups >= 1")
	}
	w := &RotatingWriter{path: path, capBytes: capBytes, maxBackups: maxBackups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}
func (w *RotatingWriter) syncDir() error {
	d, err := os.Open(filepath.Dir(w.path))
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err == nil {
		err = w.syncDir()
	}
	if err != nil {
		return errors.Join(err, f.Close())
	}
	w.f = f
	w.size = fi.Size()
	return nil
}
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.capBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.capBytes {
		if err := w.rotate(); err != nil {
			w.failed = err
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	// A partial line must not be followed by new JSON as if it were intact.
	if err != nil {
		w.failed = err
	}
	return n, err
}
func (w *RotatingWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return w.failed
	}
	if w.f == nil {
		return os.ErrClosed
	}
	return w.f.Sync()
}

// Stop on the first failure and preserve remaining bytes for operator recovery.
// Descending renames implement the existing count limit without deleting the live
// segment first. An interrupted rotation requires inspection, not blind retry.
func (w *RotatingWriter) rotate() error {
	if err := w.f.Sync(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		w.f = nil
		return err
	}
	w.f = nil
	for i := w.maxBackups - 1; i >= 1; i-- {
		err := os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		return err
	}
	if err := w.syncDir(); err != nil {
		return err
	}
	return w.open()
}
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return w.failed
	}
	err := errors.Join(w.failed, w.f.Sync(), w.f.Close())
	w.f = nil
	return err
}
