package actuator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMIGProfilesExactAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadMIGProfilesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Resolve("tenant", "nvidia.com/mig-1g.10gb")
	if err != nil || r.Profile != "2g.20gb" {
		t.Fatalf("resolve: %#v %v", r, err)
	}
	if _, err := p.Resolve("foreign", "nvidia.com/mig-1g.10gb"); err == nil {
		t.Fatal("foreign namespace inherited profile")
	}
}

func TestMIGProfilesAcceptsKubernetesMediaExtensionName(t *testing.T) {
	p := &MIGProfiles{Version: 1, Rules: []MIGProfileRule{{
		Namespace: "tenant", Resource: "nvidia.com/mig-1g.10gb.me", Profile: "1g.10gb+me",
	}}}
	if err := p.validate(); err != nil {
		t.Fatalf("NVIDIA media-extension resource rejected: %v", err)
	}
	if _, err := p.Resolve("tenant", "nvidia.com/mig-1g.10gb.me"); err != nil {
		t.Fatalf("NVIDIA media-extension resource did not resolve: %v", err)
	}
}

func TestMIGProfilesRejectsWildcardDuplicateAndBadProfile(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"rules":[{"namespace":"*","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}`,
		`{"version":1,"rules":[{"namespace":"n","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"},{"namespace":"n","resource":"nvidia.com/mig-1g.10gb","profile":"3g.40gb"}]}`,
		`{"version":1,"rules":[{"namespace":"n","resource":"nvidia.com/mig-1g.10gb","profile":"all"}]}`,
		`{"version":1,"rules":[{"namespace":"n","resource":"nvidia.com/mig-1g.10gb.shared","profile":"2g.20gb"}]}`,
		`{"version":1,"version":1,"rules":[]}`,
		`{"version":1,"rules":[{"namespace":"n","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb","profile":"3g.40gb"}]}`,
		`{"version":1,"rules":[]} {}`,
	} {
		path := filepath.Join(t.TempDir(), "profiles.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadMIGProfilesFile(path); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	path := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxMIGProfilesBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMIGProfilesFile(path); err == nil {
		t.Fatal("oversized profile configuration accepted")
	}
}

func TestMIGProfilesSetterTakesValidatedImmutableSnapshot(t *testing.T) {
	source := testMIGProfiles()
	native := NewNativeActuator(nil)
	native.SetMIGProfiles(source)
	source.Rules[0].Profile = "7g.80gb"
	rule, err := native.migProfiles.Resolve("ns", "nvidia.com/mig-1g.10gb")
	if err != nil || rule.Profile != "2g.20gb" {
		t.Fatalf("configured profile changed through caller-owned memory: rule=%+v err=%v", rule, err)
	}
	invalid := &MIGProfiles{Version: 1, Rules: []MIGProfileRule{{Namespace: "*", Resource: "nvidia.com/mig-1g.10gb", Profile: "2g.20gb"}}}
	native.SetMIGProfiles(invalid)
	if _, err := native.migProfiles.Resolve("ns", "nvidia.com/mig-1g.10gb"); err == nil {
		t.Fatal("invalid profile configuration gained authority through setter")
	}
}

func TestM177MIGProfilesRequireExactPublishedJSONKeys(t *testing.T) {
	validRule := `{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}`
	refusals := map[string]string{
		"root-version-alias":                 `{"Version":1,"rules":[]}`,
		"root-rules-alias":                   `{"version":1,"Rules":[]}`,
		"entry-namespace-alias":              `{"version":1,"rules":[{"Namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}`,
		"entry-resource-alias":               `{"version":1,"rules":[{"namespace":"tenant","Resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}`,
		"entry-profile-alias":                `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","Profile":"2g.20gb"}]}`,
		"root-canonical-then-alias":          `{"version":9,"Version":1,"rules":[]}`,
		"root-alias-then-canonical":          `{"Version":9,"version":1,"rules":[]}`,
		"entry-canonical-then-alias":         `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"bad","Profile":"2g.20gb"}]}`,
		"entry-alias-then-canonical":         `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","Profile":"bad","profile":"2g.20gb"}]}`,
		"root-escaped-decoded-duplicate":     `{"ver\u0073ion":9,"version":1,"rules":[]}`,
		"entry-escaped-decoded-duplicate":    `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","pro\u0066ile":"bad","profile":"2g.20gb"}]}`,
		"root-literal-duplicate":             `{"version":9,"version":1,"rules":[]}`,
		"entry-literal-duplicate":            `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"bad","profile":"2g.20gb"}]}`,
		"missing-version":                    `{"rules":[]}`,
		"missing-entry-profile":              `{"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb"}]}`,
		"invalid-version-type":               `{"version":"1","rules":[]}`,
		"invalid-rules-type":                 `{"version":1,"rules":{}}`,
		"invalid-entry-type":                 `{"version":1,"rules":["not-an-object"]}`,
		"unknown-canonical-looking-root-key": `{"version":1,"rules":[],"Profiles":[]}`,
	}
	for name, body := range refusals {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profiles.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadMIGProfilesFile(path); err == nil {
				t.Fatalf("accepted ambiguous or invalid MIG profile document: %s", body)
			}
		})
	}

	for name, body := range map[string]string{
		"omitted-rules":  `{"version":1}`,
		"empty-rules":    `{"version":1,"rules":[]}`,
		"canonical-rule": `{"version":1,"rules":[` + validRule + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profiles.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			profiles, err := LoadMIGProfilesFile(path)
			if err != nil {
				t.Fatalf("canonical MIG profile document rejected: %v", err)
			}
			if name == "canonical-rule" {
				rule, err := profiles.Resolve("tenant", "nvidia.com/mig-1g.10gb")
				if err != nil || rule.Profile != "2g.20gb" {
					t.Fatalf("canonical lookup: rule=%+v err=%v", rule, err)
				}
			}
		})
	}
}
