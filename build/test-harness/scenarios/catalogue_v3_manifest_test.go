package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

type catalogueV3Manifest struct {
	Schema               string `json:"schema"`
	Revision             string `json:"revision"`
	Status               string `json:"status"`
	Purpose              string `json:"purpose"`
	ImplementationStatus string `json:"implementationStatus"`
	LiveStatusAuthority  string `json:"liveStatusAuthority"`
	SourceHashSemantics  string `json:"sourceHashSemantics"`
	GlobalRules          struct {
		NegativeControl             bool   `json:"negativeControl"`
		Adaptive                    bool   `json:"adaptive"`
		Resume                      bool   `json:"resume"`
		AllowedScenarioClass        string `json:"allowedScenarioClass"`
		BenignControl               bool   `json:"benignControl"`
		SecurityEfficacy            string `json:"securityEfficacy"`
		MonetaryROI                 string `json:"monetaryROI"`
		DefaultSelection            string `json:"defaultSelection"`
		ExtraControllerOrCRDInstall bool   `json:"extraControllerOrCRDInstall"`
		LegacyDefenderExcluded      string `json:"legacyDefenderExcluded"`
		UnavailableFixture          string `json:"unavailableFixture"`
	} `json:"globalRules"`
	Entries []struct {
		ID               string `json:"id"`
		WorkloadBoundary string `json:"workloadBoundary"`
		SourceFile       string `json:"sourceFile"`
		SourceSHA256     string `json:"sourceSHA256"`
		Measures         string `json:"measures"`
		Limits           string `json:"limits"`
	} `json:"entries"`
	Profiles []struct {
		ID                    string                     `json:"id"`
		ScenarioFilter        []string                   `json:"scenarioFilter"`
		DefenderFilter        []string                   `json:"defenderFilter"`
		TrialsPerArm          int                        `json:"trialsPerArm"`
		ExecutionKind         string                     `json:"executionKind"`
		RequiredFixtures      []string                   `json:"requiredFixtures"`
		RequiredRelationships []string                   `json:"requiredRelationships"`
		RequiredConfigValues  map[string]json.RawMessage `json:"requiredConfigValues"`
		OutputIsolation       string                     `json:"outputIsolation"`
	} `json:"profiles"`
	ComparisonContract   json.RawMessage   `json:"comparisonContract"`
	ExcludedCapabilities []json.RawMessage `json:"excludedCapabilities"`
}

func TestCatalogueV3ManifestMatchesRegisteredSourceAndExplicitProfiles(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate catalogue manifest test source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(currentFile))
	raw, err := os.ReadFile(filepath.Join(moduleRoot, "catalogue", "v3", "suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest catalogueV3Manifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode catalogue v3 suite: %v", err)
	}
	if manifest.Schema != "phorvex.catalogue-suite.v1" || manifest.Revision == "" || manifest.Purpose == "" || !strings.Contains(manifest.Status, "NOT_ACCEPTED") || manifest.ImplementationStatus == "" || manifest.LiveStatusAuthority == "" || !strings.Contains(manifest.SourceHashSemantics, "exact scenario source-file bytes") {
		t.Fatalf("manifest does not separate registered implementation from external evidence acceptance: %+v", manifest)
	}
	if manifest.GlobalRules.NegativeControl || manifest.GlobalRules.Adaptive || manifest.GlobalRules.Resume || manifest.GlobalRules.AllowedScenarioClass != "executable-mechanism" || !manifest.GlobalRules.BenignControl || manifest.GlobalRules.SecurityEfficacy != "NOT_MEASURED" || manifest.GlobalRules.MonetaryROI != "NOT_MEASURED" || manifest.GlobalRules.DefaultSelection != "NONE" || manifest.GlobalRules.LegacyDefenderExcluded != "d-phorvex" || manifest.GlobalRules.ExtraControllerOrCRDInstall || manifest.GlobalRules.UnavailableFixture == "" || len(manifest.ComparisonContract) == 0 || len(manifest.ExcludedCapabilities) == 0 {
		t.Fatalf("unsafe catalogue defaults: %+v", manifest.GlobalRules)
	}

	registeredScenarios := map[string]bool{}
	for _, scenario := range core.Scenarios() {
		registeredScenarios[scenario.Metadata().Name] = true
	}
	registeredDefenders := map[string]bool{}
	for _, defender := range core.Defenders() {
		registeredDefenders[defender.Metadata().Name] = true
	}
	entryIDs := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entryIDs[entry.ID] || !registeredScenarios[entry.ID] || entry.WorkloadBoundary == "" || entry.Measures == "" || entry.Limits == "" || filepath.IsAbs(entry.SourceFile) || filepath.Clean(entry.SourceFile) != entry.SourceFile || strings.HasPrefix(entry.SourceFile, "..") {
			t.Fatalf("invalid or unregistered catalogue entry: %+v", entry)
		}
		entryIDs[entry.ID] = true
		if len(entry.SourceSHA256) != sha256.Size*2 {
			t.Fatalf("entry %s has malformed source hash", entry.ID)
		}
		if _, err := hex.DecodeString(entry.SourceSHA256); err != nil {
			t.Fatalf("entry %s has malformed source hash: %v", entry.ID, err)
		}
		source, err := os.ReadFile(filepath.Join(moduleRoot, entry.SourceFile))
		if err != nil {
			t.Fatalf("read source for %s: %v", entry.ID, err)
		}
		if got := sha256.Sum256(source); hex.EncodeToString(got[:]) != entry.SourceSHA256 {
			t.Fatalf("entry %s source hash drifted", entry.ID)
		}
	}
	if len(entryIDs) != 7 {
		t.Fatalf("catalogue entries=%d want 7", len(entryIDs))
	}

	seenProfiles := map[string]bool{}
	selectedEntries := map[string]bool{}
	gpuModes := map[string]map[string]bool{}
	natsModes := map[string]bool{}
	for _, profile := range manifest.Profiles {
		if profile.ID == "" || seenProfiles[profile.ID] || len(profile.ScenarioFilter) != 1 || !entryIDs[profile.ScenarioFilter[0]] || len(profile.DefenderFilter) == 0 || profile.TrialsPerArm < 1 || profile.ExecutionKind == "" || len(profile.RequiredFixtures) == 0 || profile.OutputIsolation == "" {
			t.Fatalf("profile differs from maintained selection contract: %+v", profile)
		}
		seenProfiles[profile.ID] = true
		selectedEntries[profile.ScenarioFilter[0]] = true
		for _, defender := range profile.DefenderFilter {
			if defender == "d-phorvex" || !registeredDefenders[defender] {
				t.Fatalf("profile %s selects prohibited or unregistered defender %s", profile.ID, defender)
			}
		}
		if strings.HasPrefix(profile.ID, "gpu-") {
			if profile.ExecutionKind != "direct-protocol-control" || profile.TrialsPerArm != 1 || !slices.Equal(profile.DefenderFilter, []string{"d-nomtd"}) || !slices.Equal(profile.RequiredRelationships, []string{"expectedNamespaceUID == gpuFunctionalFixture.namespaceUID"}) {
				t.Fatalf("GPU profile lacks direct-mode/namespace identity boundary: %+v", profile)
			}
			var mode string
			if err := json.Unmarshal(profile.RequiredConfigValues["gpuFunctionalFixture.mode"], &mode); err != nil {
				t.Fatalf("GPU profile %s mode is not a string: %v", profile.ID, err)
			}
			wantSuffix := "-" + mode
			if (mode != "direct" && mode != "no-action") || !strings.HasSuffix(profile.ID, wantSuffix) {
				t.Fatalf("GPU profile %s mode %q does not match its profile suffix", profile.ID, mode)
			}
			var operation string
			if err := json.Unmarshal(profile.RequiredConfigValues["gpuFunctionalFixture.operation"], &operation); err != nil {
				t.Fatalf("GPU profile %s operation is not a string: %v", profile.ID, err)
			}
			wantScenario := map[string]string{"prefix-cache-reset": vllmPrefixScenario, "request-drain": vllmDrainScenario}[operation]
			if wantScenario == "" || profile.ScenarioFilter[0] != wantScenario || !strings.Contains(profile.ID, operation) {
				t.Fatalf("GPU profile %s operation %q does not match scenario %s", profile.ID, operation, profile.ScenarioFilter[0])
			}
			if gpuModes[wantScenario] == nil {
				gpuModes[wantScenario] = map[string]bool{}
			}
			gpuModes[wantScenario][mode] = true
		}
		if strings.HasPrefix(profile.ID, "nats-") {
			if profile.ExecutionKind != "direct-protocol-control" || profile.TrialsPerArm != 1 || !slices.Equal(profile.DefenderFilter, []string{"d-nomtd"}) || profile.ScenarioFilter[0] != natsDurabilityScenario {
				t.Fatalf("NATS profile lacks direct protocol boundary: %+v", profile)
			}
			var mode string
			if err := json.Unmarshal(profile.RequiredConfigValues["natsJetStreamFixture.mode"], &mode); err != nil {
				t.Fatalf("NATS profile %s mode is not a string: %v", profile.ID, err)
			}
			wantID := map[string]string{"no-action": "nats-no-action", "member-restart": "nats-member-restart", "quorum-pause": "nats-quorum-pause"}[mode]
			if wantID == "" || profile.ID != wantID || natsModes[mode] {
				t.Fatalf("NATS profile %s mode %q is duplicated or mismatched", profile.ID, mode)
			}
			natsModes[mode] = true
		}
	}
	for entry := range entryIDs {
		if !selectedEntries[entry] {
			t.Fatalf("registered catalogue entry %s has no maintained profile", entry)
		}
	}
	for _, scenario := range []string{vllmPrefixScenario, vllmDrainScenario} {
		if !gpuModes[scenario]["no-action"] || !gpuModes[scenario]["direct"] {
			t.Fatalf("GPU scenario %s lacks separate no-action and direct functional profiles", scenario)
		}
	}
	for _, mode := range []string{"no-action", "member-restart", "quorum-pause"} {
		if !natsModes[mode] {
			t.Fatalf("NATS catalogue lacks explicit %s profile", mode)
		}
	}
}
