/*
 * Phorvex — audit-log size-capped rotation (P4b fix: bound the previously-unbounded
 * append-only decision JSONL so a long soak / production run cannot fill the disk).
 *
 * A RotatingWriter is a drop-in io.Writer for the --audit-json sink. When the live file
 * would exceed CapBytes, it rotates path -> path.1 -> path.2 ... dropping the oldest beyond
 * MaxBackups, then reopens. Total bytes on disk are bounded by CapBytes*(MaxBackups+1).
 * Rotation is best-effort: a failed rename never drops a decision (it keeps appending).
 */

package audit

import (
	"fmt"
	"os"
	"sync"
)

type RotatingWriter struct {
	mu         sync.Mutex
	path       string
	capBytes   int64
	maxBackups int
	f          *os.File
	size       int64
}

// NewRotatingWriter opens (or creates) path for append with size-capped rotation.
// capBytes<=0 disables rotation (unbounded, the legacy behavior). maxBackups<0 => 0.
func NewRotatingWriter(path string, capBytes int64, maxBackups int) (*RotatingWriter, error) {
	if maxBackups < 0 {
		maxBackups = 0
	}
	w := &RotatingWriter{path: path, capBytes: capBytes, maxBackups: maxBackups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.f = f
	w.size = 0
	if fi, serr := f.Stat(); serr == nil {
		w.size = fi.Size()
	}
	return nil
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.capBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.capBytes {
		w.rotate() // best-effort; on failure we keep appending to the current file
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the live file, shifts path.(N) -> path.(N+1) dropping the oldest, renames
// the live file to path.1, and reopens a fresh live file. Caller holds the lock.
func (w *RotatingWriter) rotate() {
	_ = w.f.Close()
	if w.maxBackups <= 0 {
		_ = os.Remove(w.path) // no backups kept: discard the rolled segment
	} else {
		_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxBackups)) // drop the oldest
		for i := w.maxBackups - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
		}
		_ = os.Rename(w.path, w.path+".1")
	}
	if err := w.open(); err != nil {
		// reopen failed: leave w.f as the closed handle; the next Write errors honestly
		// rather than silently losing data. (Rare: same dir we already wrote to.)
		_ = err
	}
}

func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}
