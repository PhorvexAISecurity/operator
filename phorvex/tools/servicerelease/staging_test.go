package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingContractsAreExactSourceDerivedAndIsolated(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	contracts, err := StagingContracts(r.root, r.releaseDir, r.source, StagingTargetName)
	if err != nil {
		t.Fatal(err)
	}
	if len(contracts) != len(Components) {
		t.Fatalf("contracts = %d, want %d", len(contracts), len(Components))
	}
	for i, contract := range contracts {
		component := Components[i]
		if contract.Component != component.Name || contract.Source != r.source {
			t.Fatalf("contract %d identity = %s/%s", i, contract.Component, contract.Source)
		}
		wantRepository := StagingRepositoryPrefix + component.Name
		wantTag := "1.0.0-git-" + r.source
		if contract.Image.Repository != wantRepository || contract.Image.Tag != wantTag ||
			len(contract.Image.Tags) != 2 || contract.Image.Tags[0] != wantTag || contract.Image.Tags[1] != "git-"+r.source {
			t.Fatalf("%s staging image = %#v", component.Name, contract.Image)
		}
		if contract.Deploy.Namespace != "phorvex-staging" || contract.Deploy.ReleaseName != "staging" ||
			!strings.HasPrefix(contract.Deploy.ValuesFile, "deploy/environments/staging/") || len(contract.Deploy.Consumers) == 0 {
			t.Fatalf("%s deployment is not staging-only: %#v", component.Name, contract.Deploy)
		}
		for _, consumer := range contract.Deploy.Consumers {
			if consumer.ExpectedRepository != ReleaseRegistry+"/"+wantRepository {
				t.Fatalf("%s consumer repository = %s", component.Name, consumer.ExpectedRepository)
			}
		}
	}
}

func TestStagingContractsRejectUnknownTargetAndIncompleteServiceSet(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	if _, err := StagingContracts(r.root, r.releaseDir, r.source, "arbitrary"); err == nil || !strings.Contains(err.Error(), "want \"staging-isolated\"") {
		t.Fatalf("unknown target error = %v", err)
	}
	r = newBatchTestRepo(t, map[string]string{"brain": "1.0.0"})
	if _, err := StagingContracts(r.root, r.releaseDir, r.source, StagingTargetName); err == nil || !strings.Contains(err.Error(), "requires all six services") {
		t.Fatalf("incomplete target error = %v", err)
	}
}

func TestPinStagingServicesUsesOnlyPersistedContractsAndRendersDigests(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	contracts, err := StagingContracts(r.root, r.releaseDir, r.source, StagingTargetName)
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	contractPath := filepath.Join(temporary, "contracts.json")
	raw, err := stagingContractsJSON(contracts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contractPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	results := map[string]Released{}
	for i := range contracts {
		contract := &contracts[i]
		results[contract.Component] = Released{
			Repository: expectedRepository(contract),
			Digest:     "sha256:" + strings.Repeat(string("abcdef"[i]), 64),
		}
	}
	resultsRaw, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	resultsPath := filepath.Join(temporary, "results.json")
	if err := os.WriteFile(resultsPath, resultsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PinStagingServices(r.root, contractPath, resultsPath); err != nil {
		t.Fatal(err)
	}
	for i := range contracts {
		contract := &contracts[i]
		values, err := pinValues(r.root, contract.Deploy)
		if err != nil {
			t.Fatal(err)
		}
		result := results[contract.Component]
		if values[contract.Deploy.RepositoryKey] != result.Repository || values[contract.Deploy.TagKey] != contract.Image.Tag || values[contract.Deploy.DigestKey] != result.Digest {
			t.Fatalf("%s pin = %#v", contract.Component, values)
		}
	}
}
