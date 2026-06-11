package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRotatingWriterBoundsSize — the P4b audit-rotation fix: total bytes on disk stay bounded
// by capBytes*(maxBackups+1), and rotated segments appear.
func TestRotatingWriterBoundsSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	const cap = 1000
	const backups = 2
	w, err := NewRotatingWriter(path, cap, backups)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(fmt.Sprintf("%0200d\n", 0)) // ~201 bytes/line
	for i := 0; i < 500; i++ {                 // ~100 KB written; far past cap*(backups+1)=3000
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	var total int64
	for _, p := range []string{path, path + ".1", path + ".2"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	// past the oldest backup must NOT exist (only .1 and .2 kept).
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Errorf("path.3 exists — rotation kept more than %d backups", backups)
	}
	maxAllowed := int64(cap)*(backups+1) + int64(len(line)) // + one in-flight line slack
	if total > maxAllowed {
		t.Errorf("total on-disk %d bytes exceeds bound %d", total, maxAllowed)
	}
	if total == 0 {
		t.Error("nothing written")
	}
}

// TestRotatingWriterUnbounded — capBytes<=0 disables rotation (legacy behavior preserved).
func TestRotatingWriterUnbounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	w, _ := NewRotatingWriter(path, 0, 4)
	for i := 0; i < 100; i++ {
		w.Write([]byte("x\n"))
	}
	w.Close()
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("rotated despite capBytes=0 (should be unbounded)")
	}
}
