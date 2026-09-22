package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/routecatalogue"
)

func TestWriteJournalAppendsAndSyncsTypedRows(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "writes.jsonl")
	journal, err := newWriteJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	row := routecatalogue.WriteObservation{Sequence: 1, Method: "PATCH", Kind: "*v1.Pod", Namespace: "fixture", Name: "target"}
	if err := journal.Append(row); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal metadata differs: mode=%v err=%v", info.Mode(), err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], writeJournalSchema) || !strings.Contains(lines[1], `"method":"PATCH"`) {
		t.Fatalf("journal rows differ: %q", lines)
	}
	sha, bytes, err := hashFile(path)
	if err != nil || len(sha) != 64 || bytes <= 0 {
		t.Fatalf("journal hash differs: sha=%q bytes=%d err=%v", sha, bytes, err)
	}
}
