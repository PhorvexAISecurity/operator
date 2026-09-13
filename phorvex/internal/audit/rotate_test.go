package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotatingWriterBoundsSize checks the nominal segment budget plus one whole-record
// allowance per retained segment. Rotation never splits a JSONL record.
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

func retainedLines(t *testing.T, path string, backups int) []string {
	t.Helper()
	var out []string
	for i := backups; i >= 0; i-- {
		p := path
		if i > 0 {
			p = fmt.Sprintf("%s.%d", path, i)
		}
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

func TestRotatingWriterLargerBudgetRetainsMoreCompleteOrderedRecords(t *testing.T) {
	write := func(capBytes int64) []string {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		w, err := NewRotatingWriter(path, capBytes, 2)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 40; i++ {
			if i == 20 {
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				w, err = NewRotatingWriter(path, capBytes, 2)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fmt.Fprintf(w, "{\"sequence\":%03d}\n", i); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return retainedLines(t, path, 2)
	}
	small, large := write(80), write(160)
	if len(large) <= len(small) {
		t.Fatalf("larger target retained %d records, small target retained %d", len(large), len(small))
	}
	for name, lines := range map[string][]string{"small": small, "large": large} {
		for i, line := range lines {
			want := fmt.Sprintf("{\"sequence\":%03d}", 40-len(lines)+i)
			if line != want {
				t.Fatalf("%s record %d=%q want %q", name, i, line, want)
			}
		}
	}
}

func TestRotatingWriterPreservesOversizedWholeRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := NewRotatingWriter(path, 16, 1)
	if err != nil {
		t.Fatal(err)
	}
	oversized := []byte("{\"payload\":\"record-larger-than-cap\"}\n")
	if _, err := w.Write(oversized); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path + ".1")
	if err != nil || !bytes.Equal(got, oversized) {
		t.Fatalf("oversized record not preserved whole: %q err=%v", got, err)
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
