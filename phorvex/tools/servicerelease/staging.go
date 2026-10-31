package main

import (
	"bytes"
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

var stagingProposalPaths = []string{
	"deploy/environments/staging/actuator.yaml",
	"deploy/environments/staging/attacks.yaml",
	"deploy/environments/staging/brain.yaml",
	"deploy/environments/staging/catalogue-family.yaml",
	"deploy/environments/staging/console.yaml",
	"deploy/environments/staging/manager.yaml",
	"deploy/environments/staging/phorvex.yaml",
	"deploy/environments/staging/sensor.yaml",
	"release/staging-batch.json",
}

var stagingSourceFiles = []string{
	".github/workflows/staging-isolated-release.yml",
	"release/staging-fixture-identities.json",
	"release/staging-target.json",
	"tools/staging_release.py",
}

// IsolatedStagingAuthority is the immutable bridge between a valid shared
// batch and a separately authoritative staging-only batch. Pending shared work
// is recorded, not reinterpreted: the shared record, repositories and release
// gate remain untouched and authoritative for the normal release lane.
type IsolatedStagingAuthority struct {
	Schema int    `json:"schema"`
	Target string `json:"target"`
	Source struct {
		Commit            string            `json:"commit"`
		Tree              string            `json:"tree"`
		DispatchRef       string            `json:"dispatchRef"`
		ServiceHelperTree string            `json:"serviceHelperTree"`
		Files             map[string]string `json:"files"`
	} `json:"source"`
	Shared struct {
		BatchPath          string   `json:"batchPath"`
		BatchDigest        string   `json:"batchDigest"`
		Schema             int      `json:"schema"`
		Status             string   `json:"status"`
		Source             string   `json:"source"`
		ExpectedComponents []string `json:"expectedComponents"`
		PendingComponents  []string `json:"pendingComponents"`
		Repositories       []string `json:"repositories"`
	} `json:"shared"`
	Isolated struct {
		BatchPath     string   `json:"batchPath"`
		Repositories  []string `json:"repositories"`
		ProposalPaths []string `json:"proposalPaths"`
	} `json:"isolated"`
}

type isolatedStagingBatch struct {
	Schema             int                          `json:"schema"`
	Status             string                       `json:"status"`
	Target             string                       `json:"target"`
	TargetDigest       string                       `json:"targetDigest"`
	Environment        string                       `json:"environment"`
	Source             string                       `json:"source"`
	SourceTree         string                       `json:"sourceTree"`
	Authority          IsolatedStagingAuthority     `json:"authority"`
	ExpectedComponents []string                     `json:"expectedComponents"`
	Components         []map[string]json.RawMessage `json:"components"`
	Releases           map[string]Released          `json:"releases"`
}

func stagingRepositories() []string {
	repositories := make([]string, 0, len(stagingComponentOrder))
	for _, name := range stagingComponentOrder {
		repositories = append(repositories, StagingRepositoryPrefix+name)
	}
	return repositories
}

func sharedRepositories(batch *Batch) []string {
	repositories := make([]string, 0, len(batch.Components))
	for i := range batch.Components {
		repositories = append(repositories, batch.Components[i].Image.Repository)
	}
	return repositories
}

func validateStagingSource(root, source, target string) error {
	if target != StagingTargetName {
		return fmt.Errorf("staging release target %q, want %q", target, StagingTargetName)
	}
	if err := requireClean(root); err != nil {
		return err
	}
	if !fullSHA.MatchString(source) {
		return fmt.Errorf("staging source %q is not a full lowercase Git SHA", source)
	}
	resolved, err := resolveCommit(root, source)
	if err != nil || resolved != source {
		return fmt.Errorf("staging source %s does not resolve exactly", source)
	}
	head, err := resolveCommit(root, "HEAD")
	if err != nil {
		return err
	}
	if head != source {
		return fmt.Errorf("staging contract must run at detached source %s, HEAD is %s", source, head)
	}
	return nil
}

func gitObject(root, source, path string) (string, error) {
	value, err := git(root, "rev-parse", "--verify", source+":"+path)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if !fullSHA.MatchString(value) {
		return "", fmt.Errorf("cannot resolve source-pinned Git object %s", path)
	}
	return value, nil
}

// BuildStagingAuthority validates the ordinary shared batch with the exact
// source-built helper, then records why a separate staging batch may be
// derived. It deliberately accepts prepared/partial shared status: this is not
// a shared release transition and never writes the shared batch or its pins.
func BuildStagingAuthority(root, dir, source, target string) (*IsolatedStagingAuthority, error) {
	if err := validateStagingSource(root, source, target); err != nil {
		return nil, err
	}
	batch, err := readBatch(dir)
	if err != nil {
		return nil, fmt.Errorf("shared batch authority: %w", err)
	}
	var pending []Pending
	if batch.Status == "prepared" {
		// An untouched prepared shared batch owns no deployed pin. Later reviewed
		// isolated staging overlays may therefore change the current render route;
		// validate the batch against its immutable source and require its record to
		// remain byte-identical instead of treating that overlay as shared drift.
		if err := validateBatch(root, dir, "HEAD", batch, false, ""); err != nil {
			return nil, fmt.Errorf("shared batch authority: %w", err)
		}
		batchPath, err := filepath.Rel(root, filepath.Join(dir, BatchFile))
		if err != nil || batchPath == "." || strings.HasPrefix(batchPath, "..") {
			return nil, fmt.Errorf("shared batch authority: release directory escapes repository")
		}
		batchPath = filepath.ToSlash(batchPath)
		currentRaw, err := readRegularFile(filepath.Join(dir, BatchFile))
		if err != nil {
			return nil, err
		}
		sourceRaw, err := git(root, "show", source+":"+batchPath)
		if err != nil || !bytes.Equal(currentRaw, []byte(sourceRaw)) {
			return nil, fmt.Errorf("shared batch authority: prepared batch differs from the exact selected source")
		}
		currentVersions, err := readVersions(dir)
		if err != nil || !mapsEqual(currentVersions, batch.Versions) {
			return nil, fmt.Errorf("shared batch authority: prepared versions changed")
		}
		prepared, err := preparedSource(root, dir, "HEAD")
		if err != nil || prepared != batch.Source {
			return nil, fmt.Errorf("shared batch authority: prepared source changed")
		}
		for _, name := range batch.ExpectedComponents {
			contract := contractByName(batch, name)
			if contract == nil {
				return nil, fmt.Errorf("shared batch authority: missing component %s", name)
			}
			pending = append(pending, *contract)
		}
	} else {
		pending, err = PendingReleases(root, dir, "HEAD")
		if err != nil {
			return nil, fmt.Errorf("shared batch authority: %w", err)
		}
	}
	batchRaw, err := readRegularFile(filepath.Join(dir, BatchFile))
	if err != nil {
		return nil, err
	}
	sharedRepos := sharedRepositories(batch)
	isolatedRepos := stagingRepositories()
	seen := map[string]bool{}
	for i, repository := range sharedRepos {
		name := batch.Components[i].Component
		if repository != "phorvex/"+name || strings.HasPrefix(repository, StagingRepositoryPrefix) {
			return nil, fmt.Errorf("shared component %s repository %q overlaps isolated staging authority", name, repository)
		}
		seen[repository] = true
	}
	for _, repository := range isolatedRepos {
		if seen[repository] {
			return nil, fmt.Errorf("shared and isolated repository authority overlap at %s", repository)
		}
	}
	for i := range batch.Components {
		if batch.Components[i].Record.BatchFile != "release/batch.json" {
			return nil, fmt.Errorf("shared component %s record escapes release/batch.json", batch.Components[i].Component)
		}
	}

	authority := &IsolatedStagingAuthority{Schema: 1, Target: StagingTargetName}
	authority.Source.Commit = source
	treeValue, err := git(root, "rev-parse", "--verify", source+"^{tree}")
	if err != nil {
		return nil, err
	}
	tree := strings.TrimSpace(treeValue)
	if !fullSHA.MatchString(tree) {
		return nil, fmt.Errorf("cannot resolve staging source tree")
	}
	authority.Source.Tree = tree
	authority.Source.DispatchRef = "refs/heads/main"
	authority.Source.ServiceHelperTree, err = gitObject(root, source, "phorvex/tools/servicerelease")
	if err != nil {
		return nil, err
	}
	authority.Source.Files = map[string]string{}
	for _, path := range stagingSourceFiles {
		authority.Source.Files[path], err = gitObject(root, source, path)
		if err != nil {
			return nil, err
		}
	}
	batchSum := sha256.Sum256(batchRaw)
	authority.Shared.BatchPath = "release/batch.json"
	authority.Shared.BatchDigest = fmt.Sprintf("sha256:%x", batchSum)
	authority.Shared.Schema = batch.Schema
	authority.Shared.Status = batch.Status
	authority.Shared.Source = batch.Source
	authority.Shared.ExpectedComponents = append([]string(nil), batch.ExpectedComponents...)
	for i := range pending {
		authority.Shared.PendingComponents = append(authority.Shared.PendingComponents, pending[i].Component)
	}
	if authority.Shared.PendingComponents == nil {
		authority.Shared.PendingComponents = []string{}
	}
	authority.Shared.Repositories = append([]string(nil), sharedRepos...)
	authority.Isolated.BatchPath = "release/staging-batch.json"
	authority.Isolated.Repositories = append([]string(nil), isolatedRepos...)
	authority.Isolated.ProposalPaths = append([]string(nil), stagingProposalPaths...)
	return authority, nil
}

func writeStagingAuthority(path string, authority *IsolatedStagingAuthority) error {
	raw, err := json.MarshalIndent(authority, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	return writeAtomicFile(path, raw)
}

func validateRecordedStagingAuthority(root string, authority IsolatedStagingAuthority, source, tree string) error {
	if authority.Schema != 1 || authority.Target != StagingTargetName ||
		authority.Source.Commit != source || authority.Source.Tree != tree ||
		authority.Source.DispatchRef != "refs/heads/main" ||
		authority.Shared.BatchPath != "release/batch.json" ||
		authority.Isolated.BatchPath != "release/staging-batch.json" ||
		!reflect.DeepEqual(authority.Isolated.Repositories, stagingRepositories()) ||
		!reflect.DeepEqual(authority.Isolated.ProposalPaths, stagingProposalPaths) {
		return fmt.Errorf("staging-batch.json has malformed isolated authority")
	}
	helperTree, err := gitObject(root, source, "phorvex/tools/servicerelease")
	if err != nil || authority.Source.ServiceHelperTree != helperTree {
		return fmt.Errorf("staging-batch.json source helper identity changed")
	}
	if len(authority.Source.Files) != len(stagingSourceFiles) {
		return fmt.Errorf("staging-batch.json source file authority is incomplete")
	}
	for _, path := range stagingSourceFiles {
		object, objectErr := gitObject(root, source, path)
		if objectErr != nil || authority.Source.Files[path] != object {
			return fmt.Errorf("staging-batch.json source file identity changed for %s", path)
		}
	}
	sharedRaw, err := git(root, "show", source+":"+authority.Shared.BatchPath)
	if err != nil {
		return err
	}
	sharedSum := sha256.Sum256([]byte(sharedRaw))
	if authority.Shared.BatchDigest != fmt.Sprintf("sha256:%x", sharedSum) {
		return fmt.Errorf("staging-batch.json shared authority digest changed")
	}
	var shared Batch
	decoder := json.NewDecoder(strings.NewReader(sharedRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&shared); err != nil {
		return fmt.Errorf("staging-batch.json shared authority is malformed: %w", err)
	}
	pending := make([]string, 0, len(shared.ExpectedComponents))
	for _, name := range shared.ExpectedComponents {
		if _, ok := shared.Releases[name]; !ok {
			pending = append(pending, name)
		}
	}
	if authority.Shared.Schema != shared.Schema || authority.Shared.Status != shared.Status ||
		authority.Shared.Source != shared.Source ||
		!reflect.DeepEqual(authority.Shared.ExpectedComponents, shared.ExpectedComponents) ||
		!reflect.DeepEqual(authority.Shared.PendingComponents, pending) ||
		!reflect.DeepEqual(authority.Shared.Repositories, sharedRepositories(&shared)) {
		return fmt.Errorf("staging-batch.json shared authority snapshot changed")
	}
	for _, repository := range authority.Shared.Repositories {
		if strings.HasPrefix(repository, StagingRepositoryPrefix) {
			return fmt.Errorf("staging-batch.json shared and isolated repository authority overlap")
		}
	}
	return nil
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
	if err := validateRecordedStagingAuthority(root, candidate.Authority, candidate.Source, candidate.SourceTree); err != nil {
		return false, err
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
		wantTag := "staging-" + version + "-git-" + candidate.Source
		if len(fields) != wantKeys || component != name || kind != wantKind || source != candidate.Source || version == "" ||
			image.Registry != ReleaseRegistry || image.Repository != StagingRepositoryPrefix+name || image.Tag != wantTag ||
			!reflect.DeepEqual(image.Tags, []string{wantTag, "staging-git-" + candidate.Source}) {
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
	if err := validateStagingSource(root, source, target); err != nil {
		return nil, err
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
		deploymentTag := "staging-" + version + "-git-" + source
		tags := []string{deploymentTag, "staging-git-" + source}
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
