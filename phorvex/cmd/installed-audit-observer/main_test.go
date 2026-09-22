package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func baseArgs() []string {
	return []string{"--mode=cursor", "--url=https://audit.test", "--server-name=audit.test", "--ca-file=/tls/ca", "--client-cert-file=/tls/cert", "--client-key-file=/tls/key"}
}

func TestParseRejectsUnknownModePositionalAndInvalidGrace(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown-mode":  append(baseArgs(), "--mode=other"),
		"positional":    append(baseArgs(), "extra"),
		"invalid-grace": append(baseArgs(), "--expected-grace-seconds=-2"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(args); err == nil {
				t.Fatal("invalid command line accepted")
			}
		})
	}
}

func TestDestinationCommitsExactPrivateFileAndRemovesFailedTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.jsonl")
	w, finish, err := destination(path, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("receipt\n")); err != nil {
		t.Fatal(err)
	}
	if err = finish(true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "receipt\n" {
		t.Fatalf("body=%q err=%v", b, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	failed := filepath.Join(dir, "failed.jsonl")
	w, finish, err = destination(failed, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("partial"))
	if err = finish(false); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(failed); !os.IsNotExist(err) {
		t.Fatalf("failed output retained: %v", err)
	}
	if _, err = os.Stat(failed + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary output retained: %v", err)
	}
}
