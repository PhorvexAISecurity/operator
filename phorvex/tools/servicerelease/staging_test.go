package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
		wantTag := "staging-1.0.0-git-" + r.source
		if contract.Image.Repository != wantRepository || contract.Image.Tag != wantTag ||
			len(contract.Image.Tags) != 2 || contract.Image.Tags[0] != wantTag || contract.Image.Tags[1] != "staging-git-"+r.source {
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

func writeIsolatedBatchForTest(t *testing.T, r *batchTestRepo, source string, authority *IsolatedStagingAuthority, contracts []BatchComponent, results map[string]Released) {
	t.Helper()
	targetSum := sha256.Sum256([]byte("{\"name\":\"staging-isolated\"}"))
	components := make([]map[string]any, 0, len(stagingComponentOrder))
	releases := map[string]Released{}
	for i := range contracts {
		raw, err := json.Marshal(contracts[i])
		if err != nil {
			t.Fatal(err)
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		item["kind"] = "service"
		components = append(components, item)
		releases[contracts[i].Component] = results[contracts[i].Component]
	}
	for _, name := range []string{"agent-sim", "catalogue-workload"} {
		version := "fixture-v1"
		tag := "staging-" + version + "-git-" + source
		components = append(components, map[string]any{
			"component": name, "kind": "fixture", "source": source, "version": version,
			"build": map[string]any{}, "identity": map[string]any{}, "deploy": map[string]any{},
			"image": ComponentImage{Registry: ReleaseRegistry, Repository: StagingRepositoryPrefix + name, Tag: tag, Tags: []string{tag, "staging-git-" + source}},
		})
		releases[name] = Released{Repository: ReleaseRegistry + "/" + StagingRepositoryPrefix + name, Digest: "sha256:" + strings.Repeat("f", 64)}
	}
	value := map[string]any{
		"schema": 1, "status": "complete", "target": StagingTargetName,
		"targetDigest": fmt.Sprintf("sha256:%x", targetSum), "environment": ReleaseEnvironment,
		"source": source, "sourceTree": r.git("rev-parse", source+"^{tree}"),
		"authority":          authority,
		"expectedComponents": stagingComponentOrder, "components": components, "releases": releases,
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.releaseDir, "staging-batch.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeStagingAuthorityFixtures(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		".github/workflows/staging-isolated-release.yml": "name: staging\n",
		"release/staging-fixture-identities.json":        "{}\n",
		"release/staging-target.json":                    "{\"name\":\"staging-isolated\"}\n",
		"tools/staging_release.py":                       "# staging helper\n",
		"phorvex/tools/servicerelease/staging.go":        "package main\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStagingAuthorityAllowsValidatedPreparedSharedBatch(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	r.ensureBatch()
	r.commit("persist prepared shared batch")
	writeStagingAuthorityFixtures(t, r.root)
	source := r.commit("review isolated staging authority")
	authority, err := BuildStagingAuthority(r.root, r.releaseDir, source, StagingTargetName)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Shared.Status != "prepared" || !reflect.DeepEqual(authority.Shared.PendingComponents, []string{"manager", "brain", "sensor", "actuator", "console", "attacks"}) {
		t.Fatalf("prepared shared authority = %#v", authority.Shared)
	}
	if authority.Shared.BatchPath != "release/batch.json" || authority.Isolated.BatchPath != "release/staging-batch.json" {
		t.Fatalf("shared/isolated records overlap: %#v", authority)
	}
	for _, repository := range authority.Shared.Repositories {
		if strings.HasPrefix(repository, StagingRepositoryPrefix) {
			t.Fatalf("shared repository overlaps staging: %s", repository)
		}
	}
}

func TestStagingAuthorityRejectsMalformedTamperedAndNonAncestorSharedBatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *batchTestRepo)
		want   string
	}{
		{
			name: "unknown schema",
			mutate: func(t *testing.T, r *batchTestRepo) {
				batch, err := readBatch(r.releaseDir)
				if err != nil {
					t.Fatal(err)
				}
				batch.Schema = 99
				if err := writeBatch(r.releaseDir, batch); err != nil {
					t.Fatal(err)
				}
			},
			want: "schema 99",
		},
		{
			name: "unknown field",
			mutate: func(t *testing.T, r *batchTestRepo) {
				path := filepath.Join(r.releaseDir, BatchFile)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				value["supersedes"] = "shared"
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "unknown field",
		},
		{
			name: "repository overlap",
			mutate: func(t *testing.T, r *batchTestRepo) {
				batch, err := readBatch(r.releaseDir)
				if err != nil {
					t.Fatal(err)
				}
				batch.Components[0].Image.Repository = "phorvex/staging/manager"
				if err := writeBatch(r.releaseDir, batch); err != nil {
					t.Fatal(err)
				}
			},
			want: "pinned-source contract",
		},
		{
			name: "non ancestor source",
			mutate: func(t *testing.T, r *batchTestRepo) {
				other := r.git("commit-tree", r.git("rev-parse", "HEAD^{tree}"), "-m", "unrelated")
				batch, err := readBatch(r.releaseDir)
				if err != nil {
					t.Fatal(err)
				}
				batch.Source = other
				if err := writeBatch(r.releaseDir, batch); err != nil {
					t.Fatal(err)
				}
			},
			want: "is not an ancestor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			r.ensureBatch()
			r.commit("persist prepared shared batch")
			writeStagingAuthorityFixtures(t, r.root)
			r.commit("review isolated staging authority")
			test.mutate(t, r)
			source := r.commit("tamper shared batch")
			if _, err := BuildStagingAuthority(r.root, r.releaseDir, source, StagingTargetName); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("authority error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSharedIsolatedSharedDeploymentSelectionTransition(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	r.ensureBatch()
	r.commit("persist shared batch")
	for i, component := range Components {
		r.record(component.Name, "1.0.0", string(rune('a'+i)))
	}
	r.commit("complete shared batch")

	marker := filepath.Join(r.root, "isolated-source")
	if err := os.WriteFile(marker, []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStagingAuthorityFixtures(t, r.root)
	isolationSource := r.commit("review isolated release source")
	authority, err := BuildStagingAuthority(r.root, r.releaseDir, isolationSource, StagingTargetName)
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := StagingContracts(r.root, r.releaseDir, isolationSource, StagingTargetName)
	if err != nil {
		t.Fatal(err)
	}
	results := map[string]Released{}
	for i := range contracts {
		contract := &contracts[i]
		results[contract.Component] = Released{
			Repository: expectedRepository(contract),
			Digest:     "sha256:" + strings.Repeat(string(rune('1'+i)), 64),
		}
	}
	temporary := t.TempDir()
	contractsRaw, _ := stagingContractsJSON(contracts)
	contractsPath := filepath.Join(temporary, "contracts.json")
	resultsPath := filepath.Join(temporary, "results.json")
	if err := os.WriteFile(contractsPath, contractsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	resultsRaw, _ := json.Marshal(results)
	if err := os.WriteFile(resultsPath, resultsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PinStagingServices(r.root, contractsPath, resultsPath); err != nil {
		t.Fatal(err)
	}
	writeIsolatedBatchForTest(t, r, isolationSource, authority, contracts, results)
	r.commit("select isolated staging deployment")
	if pending, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err != nil || len(pending) != 0 {
		t.Fatalf("shared publication after isolated selection = %v, %v", pending, err)
	}
	shared, err := readBatch(r.releaseDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := shared.Releases["manager"]
	shared.Releases["manager"] = Released{Repository: ReleaseRegistry + "/phorvex/staging/manager", Digest: manager.Digest}
	if err := validateBatch(r.root, r.releaseDir, "HEAD", shared, true, ""); err == nil || !strings.Contains(err.Error(), "immutable batch repository") {
		t.Fatalf("superseded shared repository error = %v", err)
	}
	shared.Releases["manager"] = Released{Repository: manager.Repository, Digest: "not-a-digest"}
	if err := validateBatch(r.root, r.releaseDir, "HEAD", shared, true, ""); err == nil || !strings.Contains(err.Error(), "sha256:<64 lowercase hex>") {
		t.Fatalf("superseded shared digest error = %v", err)
	}
	shared.Releases["manager"] = manager

	next := batchVersions()
	for name := range next {
		next[name] = "1.0.1"
	}
	r.writeVersions(next)
	r.commit("prepare later shared release")
	if _, changed, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err != nil || !changed {
		t.Fatalf("prepare shared successor: changed=%v err=%v", changed, err)
	}
	r.commit("persist shared successor")
	for i, component := range Components {
		r.record(component.Name, "1.0.1", string("789abc"[i]))
	}
	r.commit("complete shared successor")
	if pending, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err != nil || len(pending) != 0 {
		t.Fatalf("shared successor after isolated selection = %v, %v", pending, err)
	}
}
