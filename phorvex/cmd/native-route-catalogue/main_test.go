package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/routecatalogue"
)

func TestRunRejectsEvidenceDestinationBeforeKubernetesClientOrWrites(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(private, "invalid-kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("this would fail if parsed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := commandConfig{Schema: commandSchema, Kubeconfig: kubeconfig, Context: "unreachable", MaxDurationSeconds: 60, Run: routecatalogue.RunConfig{SourceRevision: strings.Repeat("a", 40)}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(private, "config.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	public := filepath.Join(private, "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	privateOutput := filepath.Join(private, "private-output")
	if err := os.Mkdir(privateOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		output   string
		conflict string
		want     string
	}{
		"non-private-parent": {output: filepath.Join(public, "receipt.json"), want: "output directory must exist and be private"},
		"existing-receipt":   {output: filepath.Join(privateOutput, "existing-receipt.json"), conflict: "output", want: "output already exists"},
		"existing-temporary": {output: filepath.Join(privateOutput, "existing-temporary.json"), conflict: "temporary", want: "temporary already exists"},
		"existing-journal":   {output: filepath.Join(privateOutput, "existing-journal.json"), conflict: "write journal", want: "write journal already exists"},
	} {
		t.Run(name, func(t *testing.T) {
			conflictPath := map[string]string{"output": tc.output, "temporary": tc.output + ".tmp", "write journal": tc.output + ".writes.jsonl"}[tc.conflict]
			if conflictPath != "" {
				if err := os.WriteFile(conflictPath, []byte("retained\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			buildCalls := 0
			err := runWithBuildValidator(configPath, tc.output, func(revision string) error {
				buildCalls++
				if revision != cfg.Run.SourceRevision {
					t.Fatalf("build source revision=%q", revision)
				}
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) || buildCalls != 1 {
				t.Fatalf("pre-dispatch refusal differs: err=%v buildCalls=%d", err, buildCalls)
			}
			for _, path := range []string{tc.output, tc.output + ".tmp", tc.output + ".writes.jsonl"} {
				contents, readErr := os.ReadFile(path)
				if path == conflictPath {
					if readErr != nil || string(contents) != "retained\n" {
						t.Fatalf("pre-existing evidence destination changed: path=%s contents=%q err=%v", path, contents, readErr)
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatalf("pre-dispatch refusal created %s: err=%v", path, readErr)
				}
			}
		})
	}
}

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
