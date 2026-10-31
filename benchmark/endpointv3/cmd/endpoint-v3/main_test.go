package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictInput(t *testing.T) {
	for _, raw := range []string{`{"n":1,"n":2}`, `{"n":{"x":1,"x":2}}`} {
		if uniqueKeys(json.NewDecoder(bytes.NewBufferString(raw)), 0) == nil {
			t.Fatal("duplicate keys accepted", raw)
		}
	}
	for _, raw := range []string{`{"n":1,"n":2}`, `{"n":{"x":1,"x":2}}`, `{} {}`, `{"unknown":2}`} {
		path := filepath.Join(t.TempDir(), "input.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var v struct {
			N int `json:"n"`
		}
		if decode(path, &v) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"n":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	var v struct {
		N int `json:"n"`
	}
	if err := decode(path, &v); err != nil || v.N != 2 {
		t.Fatal(v, err)
	}
}
