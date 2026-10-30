package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const (
	StagingTargetName       = "staging-isolated"
	StagingRepositoryPrefix = "phorvex/staging/"
)

var stagingComponentOrder = []string{
	"manager", "brain", "sensor", "actuator", "console", "attacks", "agent-sim", "catalogue-workload",
}

type isolatedStagingBatch struct {
	Schema             int                          `json:"schema"`
	Status             string                       `json:"status"`
	Target             string                       `json:"target"`
	TargetDigest       string                       `json:"targetDigest"`
	Environment        string                       `json:"environment"`
	Source             string                       `json:"source"`
	SourceTree         string                       `json:"sourceTree"`
	ExpectedComponents []string                     `json:"expectedComponents"`
	Components         []map[string]json.RawMessage `json:"components"`
	Releases           map[string]Released          `json:"releases"`
}

// isolatedStagingSupersedes reports whether a complete, committed isolated
// batch is the active deployment selection after this historical shared batch.
// It never weakens publication/tag validation, and a later shared source does
// not treat an older isolated batch as active.
func isolatedStagingSupersedes(root, dir, head string, shared *Batch) (bool, error) {
	path := filepath.Join(dir, "staging-batch.json")
	raw, err := readRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var candidate isolatedStagingBatch
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&candidate); err != nil {
		return false, fmt.Errorf("staging-batch.json: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return false, fmt.Errorf("staging-batch.json: trailing data")
		}
		return false, fmt.Errorf("staging-batch.json: %w", err)
	}
	if candidate.Schema != 1 || candidate.Status != "complete" || candidate.Target != StagingTargetName ||
		candidate.Environment != ReleaseEnvironment || !fullSHA.MatchString(candidate.Source) ||
		!fullSHA.MatchString(candidate.SourceTree) || !digestSHA.MatchString(candidate.TargetDigest) ||
		!reflect.DeepEqual(candidate.ExpectedComponents, stagingComponentOrder) || len(candidate.Components) != len(stagingComponentOrder) ||
		len(candidate.Releases) != len(stagingComponentOrder) {
		return false, fmt.Errorf("staging-batch.json is not a complete exact isolated batch")
	}
	targetRaw, err := readRegularFile(filepath.Join(dir, "staging-target.json"))
	if err != nil {
		return false, err
	}
	var targetValue any
	if err := json.Unmarshal(targetRaw, &targetValue); err != nil {
		return false, fmt.Errorf("staging-target.json: %w", err)
	}
	targetCanonical, err := json.Marshal(targetValue)
	if err != nil {
		return false, err
	}
	targetSum := sha256.Sum256(targetCanonical)
	if candidate.TargetDigest != fmt.Sprintf("sha256:%x", targetSum) {
		return false, fmt.Errorf("staging-batch.json target digest does not match staging-target.json")
	}
	tree, err := git(root, "rev-parse", candidate.Source+"^{tree}")
	if err != nil || strings.TrimSpace(tree) != candidate.SourceTree {
		return false, fmt.Errorf("staging-batch.json source tree does not match Git")
	}
	if _, err := git(root, "merge-base", "--is-ancestor", candidate.Source, head); err != nil {
		return false, fmt.Errorf("staging-batch.json source is not an ancestor of %s", head)
	}
	if _, err := git(root, "merge-base", "--is-ancestor", shared.Source, candidate.Source); err != nil {
		return false, nil
	}
	for i, fields := range candidate.Components {
		name := stagingComponentOrder[i]
		var component, kind, source, version string
		var image ComponentImage
		for key, target := range map[string]any{
			"component": &component, "kind": &kind, "source": &source, "version": &version, "image": &image,
		} {
			value, ok := fields[key]
			if !ok || json.Unmarshal(value, target) != nil {
				return false, fmt.Errorf("staging-batch.json component %s has malformed %s", name, key)
			}
		}
		wantKind := "fixture"
		if i < len(Components) {
			wantKind = "service"
		}
		wantKeys := 8
		if wantKind == "service" {
			wantKeys = 9
		}
		wantTag := version + "-git-" + candidate.Source
		if len(fields) != wantKeys || component != name || kind != wantKind || source != candidate.Source || version == "" ||
			image.Registry != ReleaseRegistry || image.Repository != StagingRepositoryPrefix+name || image.Tag != wantTag ||
			!reflect.DeepEqual(image.Tags, []string{wantTag, "git-" + candidate.Source}) {
			return false, fmt.Errorf("staging-batch.json component %s is not an exact isolated image contract", name)
		}
		released, ok := candidate.Releases[name]
		if !ok || released.Repository != ReleaseRegistry+"/"+StagingRepositoryPrefix+name || !digestSHA.MatchString(released.Digest) {
			return false, fmt.Errorf("staging-batch.json component %s has no exact isolated release", name)
		}
	}
	return true, nil
}

// StagingContracts derives the complete six-service build and rendered-consumer
// contract from one exact clean source. It has no repository override flag: the
// target name selects the reviewed staging-only prefix or fails closed.
func StagingContracts(root, dir, source, target string) ([]BatchComponent, error) {
	if target != StagingTargetName {
		return nil, fmt.Errorf("staging release target %q, want %q", target, StagingTargetName)
	}
	if err := requireClean(root); err != nil {
		return nil, err
	}
	if !fullSHA.MatchString(source) {
		return nil, fmt.Errorf("staging source %q is not a full lowercase Git SHA", source)
	}
	resolved, err := resolveCommit(root, source)
	if err != nil || resolved != source {
		return nil, fmt.Errorf("staging source %s does not resolve exactly", source)
	}
	head, err := resolveCommit(root, "HEAD")
	if err != nil {
		return nil, err
	}
	if head != source {
		return nil, fmt.Errorf("staging contract must run at detached source %s, HEAD is %s", source, head)
	}
	versions, err := versionsAtSource(root, dir, source)
	if err != nil {
		return nil, err
	}
	expected, err := expectedComponentSet(versions)
	if err != nil {
		return nil, err
	}
	want := make([]string, 0, len(Components))
	for _, component := range Components {
		want = append(want, component.Name)
	}
	if !reflect.DeepEqual(expected, want) {
		return nil, fmt.Errorf("staging target requires all six services %v, source versions select %v", want, expected)
	}
	targetContract := func(name, version string) (string, string, []string, error) {
		if componentByName(name) == nil {
			return "", "", nil, fmt.Errorf("unknown staging component %q", name)
		}
		repository := StagingRepositoryPrefix + name
		deploymentTag := version + "-git-" + source
		tags := []string{deploymentTag, "git-" + source}
		return repository, deploymentTag, tags, nil
	}
	contracts, err := componentContractsForTarget(root, dir, source, ReleaseEnvironment, expected, versions, true, targetContract)
	if err != nil {
		return nil, err
	}
	for i := range contracts {
		contract := &contracts[i]
		if contract.Image.Repository != StagingRepositoryPrefix+contract.Component || len(contract.Image.Tags) != 2 || contract.Image.Tag != contract.Image.Tags[0] {
			return nil, fmt.Errorf("component %s staging image contract is not canonical", contract.Component)
		}
		if contract.Deploy.Application != deploymentManifest || contract.Deploy.ReleaseName != "staging" || contract.Deploy.Namespace != "phorvex-staging" ||
			!strings.HasPrefix(contract.Deploy.ValuesFile, "deploy/environments/staging/") {
			return nil, fmt.Errorf("component %s staging deployment route can fan out beyond isolated staging", contract.Component)
		}
		for _, consumer := range contract.Deploy.Consumers {
			if consumer.ExpectedRepository != ReleaseRegistry+"/"+contract.Image.Repository {
				return nil, fmt.Errorf("component %s consumer repository is not staging-only", contract.Component)
			}
		}
	}
	return contracts, nil
}

func readStagingContracts(path string) ([]BatchComponent, error) {
	raw, err := readRegularFile(path)
	if err != nil {
		return nil, err
	}
	var contracts []BatchComponent
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&contracts); err != nil {
		return nil, err
	}
	if len(contracts) != len(Components) {
		return nil, fmt.Errorf("staging service contract has %d components, want %d", len(contracts), len(Components))
	}
	return contracts, nil
}

func stagingResultMap(path string) (map[string]Released, error) {
	raw, err := readRegularFile(path)
	if err != nil {
		return nil, err
	}
	var results map[string]Released
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&results); err != nil {
		return nil, err
	}
	return results, nil
}

// PinStagingServices changes only the six source-derived staging value targets,
// then re-renders and verifies every persisted consumer against its digest pin.
func PinStagingServices(root, contractPath, resultsPath string) error {
	contracts, err := readStagingContracts(contractPath)
	if err != nil {
		return err
	}
	source := contracts[0].Source
	canonical, err := StagingContracts(root, filepath.Join(root, "release"), source, StagingTargetName)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(contracts, canonical) {
		return fmt.Errorf("staging service contract differs from the exact source-derived contract")
	}
	results, err := stagingResultMap(resultsPath)
	if err != nil {
		return err
	}
	if len(results) != len(contracts) {
		return fmt.Errorf("staging service results contain %d components, want %d", len(results), len(contracts))
	}
	for i := range contracts {
		contract := &contracts[i]
		result, ok := results[contract.Component]
		if !ok {
			return fmt.Errorf("staging service result %s is missing", contract.Component)
		}
		if result.Repository != expectedRepository(contract) || !digestSHA.MatchString(result.Digest) {
			return fmt.Errorf("staging service result %s has an invalid repository or digest", contract.Component)
		}
	}
	for i := range contracts {
		contract := &contracts[i]
		result := results[contract.Component]
		if err := deployContract(root, contract.Deploy, result.Repository, contract.Image.Tag, result.Digest, contract.Source); err != nil {
			return err
		}
	}
	batch := &Batch{Environment: ReleaseEnvironment, Source: source}
	for i := range contracts {
		contract := &contracts[i]
		result := results[contract.Component]
		if err := validateDeploymentConsumer(root, batch, contract, &result, nil); err != nil {
			return err
		}
	}
	return nil
}

func stagingContractsJSON(contracts []BatchComponent) ([]byte, error) {
	copyContracts := append([]BatchComponent(nil), contracts...)
	sort.SliceStable(copyContracts, func(i, j int) bool {
		return componentOrder(copyContracts[i].Component) < componentOrder(copyContracts[j].Component)
	})
	raw, err := json.MarshalIndent(copyContracts, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func componentOrder(name string) int {
	for i := range Components {
		if Components[i].Name == name {
			return i
		}
	}
	return len(Components)
}

func writeStagingContracts(path string, contracts []BatchComponent) error {
	raw, err := stagingContractsJSON(contracts)
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	return writeAtomicFile(path, raw)
}
