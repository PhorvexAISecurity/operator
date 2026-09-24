package cataloguev1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPersistedJobAndRuntimeLoadAfterFSGroupMode(t *testing.T) {
	stateDir := t.TempDir()
	runtime := Runtime{StateDir: stateDir, ConfigSHA256: strings.Repeat("b", 64), AllowedTenant: "vllm"}
	job := runnerTestJob(t, runtime, runnerTestHandler{})
	jobPath := filepath.Join(job.OutputDir, "job.json")
	if err := WriteJob(jobPath, stateDir, job); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(stateDir, "runtime.json")
	if err := WriteRuntimeConfig(runtimePath, RuntimeConfig{Version: RuntimeConfigVersion, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJob(jobPath, stateDir); err != nil {
		t.Fatalf("writer's original 0600 job refused: %v", err)
	}
	if _, err := LoadRuntimeConfig(runtimePath); err != nil {
		t.Fatalf("writer's original 0600 runtime refused: %v", err)
	}
	for _, path := range []string{jobPath, runtimePath} {
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadJob(jobPath, stateDir); err != nil {
		t.Fatalf("same-owner persisted job with fsGroup 0660 refused: %v", err)
	}
	if _, err := LoadRuntimeConfig(runtimePath); err != nil {
		t.Fatalf("same-owner persisted runtime with fsGroup 0660 refused: %v", err)
	}
}

func TestPrivateRecordRejectsOtherOwnersAndUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := readPrivateRecord(dir); err == nil {
		t.Fatal("directory accepted as persisted record")
	}
	fifo := filepath.Join(dir, "record.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	fifoResult := make(chan error, 1)
	go func() { _, err := readPrivateRecord(fifo); fifoResult <- err }()
	select {
	case err := <-fifoResult:
		if err == nil {
			t.Fatal("FIFO accepted as persisted record")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO read blocked before regular-file validation")
	}
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateRecord(path); err != nil {
		t.Fatalf("0600 private record refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o604, 0o640, 0o664, 0o670, 0o770} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readPrivateRecord(path); err == nil {
			t.Fatalf("unsafe file mode %04o accepted", mode)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !trustedPrivateRecord(info, os.Geteuid(), os.Getegid()) ||
		trustedPrivateRecord(info, os.Geteuid()+1, os.Getegid()) ||
		trustedPrivateRecord(info, os.Geteuid(), os.Getegid()+1) {
		t.Fatal("0660 accepted an unrelated owner/group or refused the exact writer")
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateRecord(alias); err == nil {
		t.Fatal("symlinked record accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	beforeLink, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	afterLink, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if samePrivateRecord(beforeLink, afterLink) {
		t.Fatal("hard-link count changed during read without invalidating record")
	}
	if _, err := readPrivateRecord(path); err == nil {
		t.Fatal("hard-linked record accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, []byte("{}\n"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if samePrivateRecord(before, after) {
		t.Fatal("replaced pathname was treated as original opened inode")
	}
	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, maxRecordBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateRecord(oversized); err == nil {
		t.Fatal("oversized persisted record accepted")
	}
}
