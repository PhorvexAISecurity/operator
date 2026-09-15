package actuator

import (
	"os"
	"path/filepath"
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
	for name, body := range map[string]string{
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
	} {
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
