package actuator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAdapterSourcesFileStrictAndCopied(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"sources":[{"namespace":"team-a","adapter":"safe.v1","source":"/models/safe-v1"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadAdapterSourcesFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s.source("team-a", "safe.v1"); !ok || got != "/models/safe-v1" {
		t.Fatalf("missing mapping: %q %t", got, ok)
	}
	n := NewNativeActuator(nil)
	n.SetAdapterSources(s)
	s[adapterSourceKey("team-a", "safe.v1")] = "/changed"
	if got, _ := n.AdapterSources.source("team-a", "safe.v1"); got != "/models/safe-v1" {
		t.Fatal("configuration was not copied")
	}
}

func TestLoadAdapterSourcesFileRefusals(t *testing.T) {
	refusals := map[string]string{
		"unknown":                   `{"version":1,"sources":[],"extra":true}`,
		"duplicate-mapping":         `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/a"},{"namespace":"n","adapter":"a","source":"/b"}]}`,
		"duplicate-version-field":   `{"version":9,"version":1,"sources":[]}`,
		"duplicate-source-field":    `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/a","source":"/b"}]}`,
		"duplicate-namespace-field": `{"version":1,"sources":[{"namespace":"n","namespace":"other","adapter":"a","source":"/a"}]}`,
		"relative":                  `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"../a"}]}`,
		"traversal":                 `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/x/../a"}]}`,
		"url":                       `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"https://example/a"}]}`,
		"wildcard":                  `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/models/*"}]}`,
		"question-pattern":          `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/models/a?"}]}`,
		"control":                   "{\"version\":1,\"sources\":[{\"namespace\":\"n\",\"adapter\":\"a\",\"source\":\"/a\\u0001\"}]}",
	}
	refusals["oversized-source-path"] = `{"version":1,"sources":[{"namespace":"n","adapter":"a","source":"/` + strings.Repeat("a", maxAdapterSourcePathBytes) + `"}]}`
	for name, body := range refusals {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x")
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAdapterSourcesFile(p); err == nil {
				t.Fatal("malformed configuration accepted")
			}
		})
	}
}

func TestM177AdapterSourcesRequireExactPublishedJSONKeys(t *testing.T) {
	refusals := map[string]string{
		"root-version-alias":              `{"Version":1,"sources":[]}`,
		"root-sources-alias":              `{"version":1,"Sources":[]}`,
		"entry-namespace-alias":           `{"version":1,"sources":[{"Namespace":"tenant","adapter":"safe.v1","source":"/models/safe-v1"}]}`,
		"entry-adapter-alias":             `{"version":1,"sources":[{"namespace":"tenant","Adapter":"safe.v1","source":"/models/safe-v1"}]}`,
		"entry-source-alias":              `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","Source":"/models/safe-v1"}]}`,
		"root-canonical-then-alias":       `{"version":9,"Version":1,"sources":[]}`,
		"root-alias-then-canonical":       `{"Version":9,"version":1,"sources":[]}`,
		"entry-canonical-then-alias":      `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","source":"relative","Source":"/models/safe-v1"}]}`,
		"entry-alias-then-canonical":      `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","Source":"relative","source":"/models/safe-v1"}]}`,
		"root-escaped-decoded-duplicate":  `{"ver\u0073ion":9,"version":1,"sources":[]}`,
		"entry-escaped-decoded-duplicate": `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","sou\u0072ce":"relative","source":"/models/safe-v1"}]}`,
		"root-literal-duplicate":          `{"version":9,"version":1,"sources":[]}`,
		"entry-literal-duplicate":         `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","source":"relative","source":"/models/safe-v1"}]}`,
		"missing-version":                 `{"sources":[]}`,
		"missing-entry-source":            `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1"}]}`,
		"invalid-version-type":            `{"version":"1","sources":[]}`,
		"invalid-sources-type":            `{"version":1,"sources":{}}`,
		"invalid-entry-type":              `{"version":1,"sources":["not-an-object"]}`,
	}
	for name, body := range refusals {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sources.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAdapterSourcesFile(path); err == nil {
				t.Fatalf("accepted ambiguous or invalid adapter source document: %s", body)
			}
		})
	}

	for name, body := range map[string]string{
		"omitted-sources":  `{"version":1}`,
		"empty-sources":    `{"version":1,"sources":[]}`,
		"canonical-source": `{"version":1,"sources":[{"namespace":"tenant","adapter":"safe.v1","source":"/models/safe-v1"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sources.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			sources, err := LoadAdapterSourcesFile(path)
			if err != nil {
				t.Fatalf("canonical adapter source document rejected: %v", err)
			}
			if name == "canonical-source" {
				got, ok := sources.source("tenant", "safe.v1")
				if !ok || got != "/models/safe-v1" {
					t.Fatalf("canonical lookup: source=%q ok=%t", got, ok)
				}
			}
		})
	}
}
