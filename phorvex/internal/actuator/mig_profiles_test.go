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
