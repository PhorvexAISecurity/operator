package main

import (
	"encoding/json"
	"fmt"
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
