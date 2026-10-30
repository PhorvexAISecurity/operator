package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	// BatchFile is the canonical, committed record for the prepared release.
	BatchFile   = "batch.json"
	batchSchema = 2
	// ReleaseEnvironment is the one environment the release workflow records.
	ReleaseEnvironment = "staging"
	// ReleaseRegistry is part of the immutable component contract. The workflow
	// refuses credentials for, or a push result from, any other registry.
	ReleaseRegistry = "753556437180.dkr.ecr.us-east-2.amazonaws.com"
)

var (
	fullSHA   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestSHA = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ComponentIdentity fixes every name used to select or verify a component.
// Aliases is explicit (and currently empty) so adding an alternate lookup key is
// a contract change rather than an unrecorded convenience in a later helper.
type ComponentIdentity struct {
	Service         string   `json:"service"`
	Command         string   `json:"command"`
	ValidationImage string   `json:"validationImage"`
	Aliases         []string `json:"aliases"`
}

// ComponentBuild fixes all Docker inputs selected by release orchestration.
type ComponentBuild struct {
	Dockerfile string   `json:"dockerfile"`
	Context    string   `json:"context"`
	Target     string   `json:"target"`
	Args       []string `json:"args"`
}

// ComponentImage is the one remotely tagged image the component may publish.
type ComponentImage struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

// ComponentDeploy fixes the authoritative Argo render route, exact values
// location, source-input fingerprints and every workload image consumer.
type ComponentDeploy struct {
	Application       string          `json:"application"`
	ApplicationDigest string          `json:"applicationDigest"`
	Chart             string          `json:"chart"`
	ChartDigest       string          `json:"chartDigest"`
	ReleaseName       string          `json:"releaseName"`
	Namespace         string          `json:"namespace"`
	ValuesFiles       []string        `json:"valuesFiles"`
	ValuesDigests     []FileDigest    `json:"valuesDigests"`
	ValuesFile        string          `json:"valuesFile"`
	Path              []string        `json:"path"`
	RepositoryKey     string          `json:"repositoryKey"`
	TagKey            string          `json:"tagKey"`
	DigestKey         string          `json:"digestKey"`
	SourceKey         string          `json:"sourceKey"`
	Consumers         []ImageConsumer `json:"consumers"`
}

// ComponentRecord fixes every Git/release-record lookup key for a component.
type ComponentRecord struct {
	BatchFile  string `json:"batchFile"`
	ReleaseKey string `json:"releaseKey"`
	GitTag     string `json:"gitTag"`
}

// BatchComponent is the immutable, source-derived execution contract for one
// prepared component. Its order in Batch.Components is also canonical.
type BatchComponent struct {
	Component string            `json:"component"`
	Identity  ComponentIdentity `json:"identity"`
	Source    string            `json:"source"`
	Version   string            `json:"version"`
	Build     ComponentBuild    `json:"build"`
	Image     ComponentImage    `json:"image"`
	Deploy    ComponentDeploy   `json:"deploy"`
	Record    ComponentRecord   `json:"record"`
}

// Pending is an unrecorded component of the current prepared batch.
type Pending = BatchComponent

// Released records the immutable image identity published for one component.
// Source, version, repository and tag are fixed by the matching BatchComponent.
type Released struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// Batch is the canonical release record. Source, Versions and Components never
// change for a batch; Releases grows from empty to the complete version set.
type Batch struct {
	Schema      int                 `json:"schema"`
	Status      string              `json:"status"`
	Environment string              `json:"environment"`
	Source      string              `json:"source"`
	Versions    map[string]string   `json:"versions"`
	Components  []BatchComponent    `json:"components"`
	Releases    map[string]Released `json:"releases"`
}

func batchStatus(versions map[string]string, releases map[string]Released) string {
	switch len(releases) {
	case 0:
		return "prepared"
	case len(versions):
		return "complete"
	default:
		return "partial"
	}
}

func componentByName(name string) *Component {
	for i := range Components {
		if Components[i].Name == name {
			return &Components[i]
		}
	}
	return nil
}

func parseVersions(raw []byte) (map[string]string, error) {
	versions := map[string]string{}
	if err := json.Unmarshal(raw, &versions); err != nil {
		return nil, fmt.Errorf("%s: %w", VersionsFile, err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s: no prepared releases", VersionsFile)
	}
	for name, version := range versions {
		if componentByName(name) == nil {
			return nil, fmt.Errorf("%s: unknown component %q", VersionsFile, name)
		}
		if _, err := ParseVersion(version); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", VersionsFile, name, err)
		}
	}
	return versions, nil
}

func readVersions(dir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, VersionsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseVersions(raw)
}

func readBatch(dir string) (*Batch, error) {
	path := filepath.Join(dir, BatchFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var batch Batch
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		return nil, fmt.Errorf("%s: %w", BatchFile, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%s: trailing data", BatchFile)
		}
		return nil, fmt.Errorf("%s: %w", BatchFile, err)
	}
	return &batch, nil
}

// readBatchPointer is the deliberately narrow current-main trust boundary. It
// reads only the versioned source pointer needed to locate a candidate helper;
// the helper built from the candidate source later validates the whole batch.
func readBatchPointer(dir string) (schema int, source string, err error) {
	raw, err := os.ReadFile(filepath.Join(dir, BatchFile))
	if err != nil {
		return 0, "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return 0, "", fmt.Errorf("%s pointer: %w", BatchFile, err)
	}
	if err := json.Unmarshal(fields["schema"], &schema); err != nil {
		return 0, "", fmt.Errorf("%s pointer: schema: %w", BatchFile, err)
	}
	if err := json.Unmarshal(fields["source"], &source); err != nil {
		return 0, "", fmt.Errorf("%s pointer: source: %w", BatchFile, err)
	}
	return schema, source, nil
}

func writeBatch(dir string, batch *Batch) error {
	raw, err := marshalBatch(batch)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, BatchFile), raw, 0o644)
}

func marshalBatch(batch *Batch) ([]byte, error) {
	raw, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func cloneBatch(batch *Batch) (*Batch, error) {
	raw, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	var clone Batch
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func writeAtomicFile(path string, raw []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".servicerelease-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func writeRecordAtomically(valuesPath string, valuesRaw []byte, batchPath string, batchRaw []byte) error {
	oldValues, err := os.ReadFile(valuesPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(batchPath); err != nil {
		return err
	}
	if err := writeAtomicFile(valuesPath, valuesRaw); err != nil {
		return err
	}
	if err := writeAtomicFile(batchPath, batchRaw); err != nil {
		restoreErr := writeAtomicFile(valuesPath, oldValues)
		return errors.Join(err, restoreErr)
	}
	return nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func requireClean(root string) error {
	status, err := git(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("release source is dirty:\n%s", strings.TrimSpace(status))
	}
	return nil
}

// preparedSource is the first-parent commit that introduced the current
// versions record. For a merged release PR this is its merge commit, even when
// main has advanced through later record commits.
func preparedSource(root, dir, head string) (string, error) {
	rel, err := filepath.Rel(root, filepath.Join(dir, VersionsFile))
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("release directory %q is outside repository", dir)
	}
	out, err := git(root, "log", "--first-parent", "-1", "--format=%H", head, "--", filepath.ToSlash(rel))
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if !fullSHA.MatchString(sha) {
		return "", fmt.Errorf("cannot resolve prepared release source at %s", head)
	}
	return sha, nil
}

func resolveCommit(root, ref string) (string, error) {
	out, err := git(root, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func tagCommit(root, tag string) (string, bool, error) {
	out, err := git(root, "rev-parse", "--verify", "--quiet", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return "", false, nil
	}
	return strings.TrimSpace(out), true, nil
}

func versionsAtSource(root, dir, source string) (map[string]string, error) {
	rel, err := filepath.Rel(root, filepath.Join(dir, VersionsFile))
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("release directory %q is outside repository", dir)
	}
	raw, err := git(root, "show", source+":"+filepath.ToSlash(rel))
	if err != nil {
		return nil, err
	}
	return parseVersions([]byte(raw))
}

func componentContracts(root, dir, source, environment string, versions map[string]string, proveConsumers bool) ([]BatchComponent, error) {
	releaseDir, err := filepath.Rel(root, dir)
	if err != nil || releaseDir == "." || strings.HasPrefix(releaseDir, "..") {
		return nil, fmt.Errorf("release directory %q is outside repository", dir)
	}
	sourceTree, cleanup, err := sourceReleaseTree(root, source, environment)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	recordFile := filepath.ToSlash(filepath.Join(releaseDir, BatchFile))
	contracts := make([]BatchComponent, 0, len(versions))
	for _, c := range Components {
		version, ok := versions[c.Name]
		if !ok {
			continue
		}
		args := []string{"GIT_SHA=" + source, "RELEASE_VERSION=" + version}
		for key, value := range c.BuildArgs {
			args = append(args, key+"="+strings.ReplaceAll(value, "{version}", version))
		}
		sort.Strings(args)
		deploy, err := buildComponentDeployment(sourceTree, environment, &c, ComponentDeploy{
			Chart:      c.Chart,
			ValuesFile: filepath.ToSlash(filepath.Join("deploy", "environments", environment, c.Deploy.File+".yaml")),
			Path:       append([]string(nil), c.Deploy.Path...), RepositoryKey: c.Deploy.Repository,
			TagKey: c.Deploy.Tag, DigestKey: c.Deploy.Digest, SourceKey: c.Deploy.Source,
		}, proveConsumers)
		if err != nil {
			return nil, fmt.Errorf("component %s source deployment contract: %w", c.Name, err)
		}
		contracts = append(contracts, BatchComponent{
			Component: c.Name,
			Identity: ComponentIdentity{
				Service: c.Name, Command: c.Command, ValidationImage: c.Image, Aliases: []string{},
			},
			Source:  source,
			Version: version,
			Build: ComponentBuild{
				Dockerfile: c.Dockerfile, Context: ".", Target: c.Target, Args: args,
			},
			Image:  ComponentImage{Registry: ReleaseRegistry, Repository: c.Repository, Tag: version},
			Deploy: deploy,
			Record: ComponentRecord{BatchFile: recordFile, ReleaseKey: c.Name, GitTag: c.Name + "-v" + version},
		})
	}
	return contracts, nil
}

func contractByName(batch *Batch, name string) *BatchComponent {
	for i := range batch.Components {
		if batch.Components[i].Component == name {
			return &batch.Components[i]
		}
	}
	return nil
}

func validateContractSet(root, dir string, batch *Batch) error {
	expected, err := componentContracts(root, dir, batch.Source, batch.Environment, batch.Versions, false)
	if err != nil {
		return err
	}
	if len(batch.Components) != len(batch.Versions) {
		return fmt.Errorf("%s: %d component contracts, want %d", BatchFile, len(batch.Components), len(batch.Versions))
	}
	if len(batch.Components) != len(expected) {
		return fmt.Errorf("%s: prepared component set is missing or has extra components", BatchFile)
	}
	canonical := map[string]bool{}
	for name := range batch.Versions {
		canonical[name] = true
	}
	seenComponents := map[string]bool{}
	seenImages := map[string]string{}
	seenDeploys := map[string]string{}
	seenReleaseKeys := map[string]string{}
	seenTags := map[string]string{}
	seenAliases := map[string]string{}
	for i, contract := range batch.Components {
		name := contract.Component
		if seenComponents[name] {
			return fmt.Errorf("%s: duplicate component contract %q", BatchFile, name)
		}
		seenComponents[name] = true
		version, ok := batch.Versions[name]
		if !ok {
			return fmt.Errorf("%s: extra component contract %q", BatchFile, name)
		}
		if contract.Source != batch.Source || contract.Version != version {
			return fmt.Errorf("%s: component %s source/version differs from its batch", BatchFile, name)
		}
		if expected[i].Component != name {
			return fmt.Errorf("%s: component contract %d is %q, want %q (reordered or aliased)", BatchFile, i, name, expected[i].Component)
		}
		image := contract.Image.Registry + "/" + contract.Image.Repository
		if other := seenImages[image]; other != "" {
			return fmt.Errorf("%s: components %s and %s share image repository %s", BatchFile, other, name, image)
		}
		seenImages[image] = name
		deploy := contract.Deploy.ValuesFile + "\x00" + strings.Join(contract.Deploy.Path, "\x00")
		if other := seenDeploys[deploy]; other != "" {
			return fmt.Errorf("%s: components %s and %s share deployment pin target", BatchFile, other, name)
		}
		seenDeploys[deploy] = name
		if other := seenReleaseKeys[contract.Record.ReleaseKey]; other != "" {
			return fmt.Errorf("%s: components %s and %s share release key %q", BatchFile, other, name, contract.Record.ReleaseKey)
		}
		seenReleaseKeys[contract.Record.ReleaseKey] = name
		if other := seenTags[contract.Record.GitTag]; other != "" {
			return fmt.Errorf("%s: components %s and %s share Git tag %q", BatchFile, other, name, contract.Record.GitTag)
		}
		seenTags[contract.Record.GitTag] = name
		for _, alias := range contract.Identity.Aliases {
			if alias == "" || canonical[alias] {
				return fmt.Errorf("%s: component %s alias %q is empty or redirects a canonical component", BatchFile, name, alias)
			}
			if other := seenAliases[alias]; other != "" {
				return fmt.Errorf("%s: components %s and %s share alias %q", BatchFile, other, name, alias)
			}
			seenAliases[alias] = name
		}
		expected[i].Deploy.Consumers = append([]ImageConsumer(nil), contract.Deploy.Consumers...)
		if len(contract.Deploy.Consumers) == 0 {
			return fmt.Errorf("%s: component %s has no pinned rendered image consumers", BatchFile, name)
		}
		if !reflect.DeepEqual(contract, expected[i]) {
			return fmt.Errorf("%s: component %s contract differs from the helper's pinned-source contract", BatchFile, name)
		}
	}
	for name := range batch.Versions {
		if !seenComponents[name] {
			return fmt.Errorf("%s: missing component contract %q", BatchFile, name)
		}
	}
	return nil
}

func pinValues(root string, target ComponentDeploy) (map[string]string, error) {
	path := filepath.Join(root, filepath.FromSlash(target.ValuesFile))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pinValuesRaw(raw, target)
}

func expectedRepository(contract *BatchComponent) string {
	return contract.Image.Registry + "/" + contract.Image.Repository
}

func validateRepository(repository string, contract *BatchComponent) error {
	want := expectedRepository(contract)
	if repository != want {
		return fmt.Errorf("component %s repository %q, want immutable batch repository %q", contract.Component, repository, want)
	}
	return nil
}

func validatePin(root string, batch *Batch, contract *BatchComponent, released Released, overrideRaw []byte) error {
	if err := validateRepository(released.Repository, contract); err != nil {
		return err
	}
	if !digestSHA.MatchString(released.Digest) {
		return fmt.Errorf("component %s digest %q is not sha256:<64 lowercase hex>", contract.Component, released.Digest)
	}
	var values map[string]string
	var err error
	if overrideRaw == nil {
		values, err = pinValues(root, contract.Deploy)
	} else {
		values, err = pinValuesRaw(overrideRaw, contract.Deploy)
	}
	if err != nil {
		return err
	}
	if values[contract.Deploy.RepositoryKey] != released.Repository || values[contract.Deploy.TagKey] != contract.Image.Tag || values[contract.Deploy.DigestKey] != released.Digest {
		return fmt.Errorf("component %s release record does not match its %s image pin", contract.Component, batch.Environment)
	}
	if contract.Deploy.SourceKey != "" && values[contract.Deploy.SourceKey] != contract.Source {
		return fmt.Errorf("component %s image pin source %q does not match batch source %s", contract.Component, values[contract.Deploy.SourceKey], batch.Source)
	}
	return nil
}

// validateBatch verifies the whole batch. allowTag permits RecordRelease to
// validate the one just-created local tag before adding its release entry.
func validateBatch(root, dir, head string, batch *Batch, current bool, allowTag string) error {
	return validateBatchOverlay(root, dir, head, batch, current, allowTag, nil)
}

func validateBatchOverlay(root, dir, head string, batch *Batch, current bool, allowTag string, overrides map[string][]byte) error {
	if batch.Schema != batchSchema {
		return fmt.Errorf("%s: schema %d, want %d", BatchFile, batch.Schema, batchSchema)
	}
	if batch.Environment != ReleaseEnvironment {
		return fmt.Errorf("%s: environment %q, want %q", BatchFile, batch.Environment, ReleaseEnvironment)
	}
	if !fullSHA.MatchString(batch.Source) {
		return fmt.Errorf("%s: source %q is not a full lowercase Git SHA", BatchFile, batch.Source)
	}
	resolved, err := resolveCommit(root, batch.Source)
	if err != nil {
		return fmt.Errorf("%s: source %s does not resolve exactly: %w", BatchFile, batch.Source, err)
	}
	if resolved != batch.Source {
		return fmt.Errorf("%s: source %s resolves to %s", BatchFile, batch.Source, resolved)
	}
	if _, err := git(root, "merge-base", "--is-ancestor", batch.Source, head); err != nil {
		return fmt.Errorf("%s: source %s is not an ancestor of %s", BatchFile, batch.Source, head)
	}
	atSource, err := versionsAtSource(root, dir, batch.Source)
	if err != nil {
		return fmt.Errorf("%s: cannot read versions at source %s: %w", BatchFile, batch.Source, err)
	}
	if !mapsEqual(atSource, batch.Versions) {
		return fmt.Errorf("%s: versions do not match source %s", BatchFile, batch.Source)
	}
	introduced, err := preparedSource(root, dir, batch.Source)
	if err != nil {
		return err
	}
	if introduced != batch.Source {
		return fmt.Errorf("%s: source %s did not introduce its prepared version set", BatchFile, batch.Source)
	}
	if current {
		versions, err := readVersions(dir)
		if err != nil {
			return err
		}
		if !mapsEqual(versions, batch.Versions) {
			return fmt.Errorf("%s: release record versions do not match %s", BatchFile, VersionsFile)
		}
		prepared, err := preparedSource(root, dir, head)
		if err != nil {
			return err
		}
		if prepared != batch.Source {
			return fmt.Errorf("%s: source %s differs from prepared source %s", BatchFile, batch.Source, prepared)
		}
	}
	if len(batch.Versions) == 0 {
		return fmt.Errorf("%s: no versions", BatchFile)
	}
	if batch.Releases == nil {
		return fmt.Errorf("%s: releases must be an object", BatchFile)
	}
	if err := validateContractSet(root, dir, batch); err != nil {
		return err
	}
	for i := range batch.Components {
		contract := &batch.Components[i]
		name := contract.Component
		released, recorded := batch.Releases[contract.Record.ReleaseKey]
		overrideRaw := overrides[contract.Deploy.ValuesFile]
		taggedSource, tagged, err := tagCommit(root, contract.Record.GitTag)
		if err != nil {
			return err
		}
		if tagged && taggedSource != batch.Source {
			return fmt.Errorf("component %s tag points to %s, batch source is %s", name, taggedSource, batch.Source)
		}
		switch {
		case recorded && !tagged:
			return fmt.Errorf("component %s is recorded without tag %s", name, contract.Record.GitTag)
		case !recorded && tagged && allowTag != name:
			return fmt.Errorf("component %s tag exists without a release record", name)
		case recorded:
			if err := validatePin(root, batch, contract, released, overrideRaw); err != nil {
				return err
			}
		}
		if current {
			var release *Released
			if recorded {
				release = &released
			}
			if err := validateDeploymentConsumer(root, batch, contract, release, overrideRaw); err != nil {
				return err
			}
		}
	}
	for name := range batch.Releases {
		contract := contractByName(batch, name)
		if contract == nil || contract.Record.ReleaseKey != name {
			return fmt.Errorf("%s: release %q is not in the prepared component contract", BatchFile, name)
		}
	}
	wantStatus := batchStatus(batch.Versions, batch.Releases)
	if batch.Status != wantStatus {
		return fmt.Errorf("%s: status %q, want %q", BatchFile, batch.Status, wantStatus)
	}
	return nil
}

// BootstrapSource is the only operation a helper built from current main may
// perform for an in-flight batch. It validates only schema/source pointer shape
// and returns the commit that introduced versions.json. All component authority
// starts after a helper has been compiled from that returned commit.
func BootstrapSource(root, dir, head string) (string, error) {
	if err := requireClean(root); err != nil {
		return "", err
	}
	source, err := preparedSource(root, dir, head)
	if err != nil {
		return "", err
	}
	schema, pointerSource, err := readBatchPointer(dir)
	if errors.Is(err, os.ErrNotExist) {
		return source, nil
	}
	if err != nil {
		return "", err
	}
	if schema != batchSchema {
		return "", fmt.Errorf("%s pointer: schema %d, want %d", BatchFile, schema, batchSchema)
	}
	if !fullSHA.MatchString(pointerSource) {
		return "", fmt.Errorf("%s pointer: source %q is not a full lowercase Git SHA", BatchFile, pointerSource)
	}
	resolved, err := resolveCommit(root, pointerSource)
	if err != nil || resolved != pointerSource {
		return "", fmt.Errorf("%s pointer: source %s does not resolve exactly", BatchFile, pointerSource)
	}
	if _, err := git(root, "merge-base", "--is-ancestor", pointerSource, head); err != nil {
		return "", fmt.Errorf("%s pointer: source %s is not an ancestor of %s", BatchFile, pointerSource, head)
	}
	return source, nil
}

func importCompleteBatch(root, dir, head, environment, source string, versions map[string]string) (*Batch, error) {
	contracts, err := componentContracts(root, dir, source, environment, versions, true)
	if err != nil {
		return nil, err
	}
	batch := &Batch{Schema: batchSchema, Environment: environment, Source: source, Versions: versions, Components: contracts, Releases: map[string]Released{}}
	tagged := 0
	for i := range contracts {
		contract := &contracts[i]
		taggedSource, ok, err := tagCommit(root, contract.Record.GitTag)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		tagged++
		if taggedSource != source {
			return nil, fmt.Errorf("component %s tag points to %s, prepared source is %s", contract.Component, taggedSource, source)
		}
	}
	if tagged != 0 && tagged != len(versions) {
		return nil, fmt.Errorf("%s is missing for a partially tagged release; refusing to infer a batch source", BatchFile)
	}
	if tagged == len(versions) {
		for i := range contracts {
			contract := &contracts[i]
			values, err := pinValues(root, contract.Deploy)
			if err != nil {
				return nil, err
			}
			released := Released{Repository: values[contract.Deploy.RepositoryKey], Digest: values[contract.Deploy.DigestKey]}
			if values[contract.Deploy.TagKey] != contract.Image.Tag {
				return nil, fmt.Errorf("component %s pin version %q, want %q", contract.Component, values[contract.Deploy.TagKey], contract.Image.Tag)
			}
			if contract.Deploy.SourceKey != "" && values[contract.Deploy.SourceKey] != source {
				return nil, fmt.Errorf("component %s pin source %q, want %q", contract.Component, values[contract.Deploy.SourceKey], source)
			}
			batch.Releases[contract.Record.ReleaseKey] = released
		}
	}
	batch.Status = batchStatus(batch.Versions, batch.Releases)
	if err := validateBatch(root, dir, head, batch, true, ""); err != nil {
		return nil, err
	}
	return batch, nil
}

// ImportTerminalBatch is the one-time bridge for a fully published release
// whose source predates the versioned batch helper. It is intentionally unable
// to create a prepared or partial batch: current-main metadata can describe
// historical state only after every tag and deployment pin already proves the
// same source. It can never authorize component work.
func ImportTerminalBatch(root, dir, head, environment string) (*Batch, error) {
	if environment != ReleaseEnvironment {
		return nil, fmt.Errorf("release environment %q, want %q", environment, ReleaseEnvironment)
	}
	if err := requireClean(root); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, BatchFile)); err == nil {
		return nil, fmt.Errorf("%s already exists; terminal import is only for legacy releases", BatchFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	versions, err := readVersions(dir)
	if err != nil {
		return nil, err
	}
	if versions == nil {
		return nil, fmt.Errorf("%s is missing", VersionsFile)
	}
	source, err := preparedSource(root, dir, head)
	if err != nil {
		return nil, err
	}
	batch, err := importCompleteBatch(root, dir, head, environment, source, versions)
	if err != nil {
		return nil, err
	}
	if batch.Status != "complete" {
		return nil, fmt.Errorf("legacy release at %s is %s, not terminal; refusing current-main metadata authority", source, batch.Status)
	}
	if err := writeBatch(dir, batch); err != nil {
		return nil, err
	}
	return batch, nil
}

// EnsureBatch creates the source and complete component contract for a newly
// prepared version set, or validates the existing batch. It must run and be
// committed before any build.
func EnsureBatch(root, dir, head, environment string) (*Batch, bool, error) {
	if environment != ReleaseEnvironment {
		return nil, false, fmt.Errorf("release environment %q, want %q", environment, ReleaseEnvironment)
	}
	if err := requireClean(root); err != nil {
		return nil, false, err
	}
	versions, err := readVersions(dir)
	if err != nil || versions == nil {
		return nil, false, err
	}
	source, err := preparedSource(root, dir, head)
	if err != nil {
		return nil, false, err
	}
	batch, err := readBatch(dir)
	if errors.Is(err, os.ErrNotExist) {
		batch, err = importCompleteBatch(root, dir, head, environment, source, versions)
		if err != nil {
			return nil, false, err
		}
		return batch, true, writeBatch(dir, batch)
	}
	if err != nil {
		return nil, false, err
	}
	if mapsEqual(batch.Versions, versions) {
		if err := validateBatch(root, dir, head, batch, true, ""); err != nil {
			return nil, false, err
		}
		return batch, false, nil
	}
	if err := validateBatch(root, dir, head, batch, false, ""); err != nil {
		return nil, false, fmt.Errorf("prior batch is not terminally valid: %w", err)
	}
	if batch.Status != "complete" {
		return nil, false, fmt.Errorf("prior batch %s is %s, refusing concurrent batch creation", batch.Source, batch.Status)
	}
	contracts, err := componentContracts(root, dir, source, environment, versions, true)
	if err != nil {
		return nil, false, err
	}
	batch = &Batch{Schema: batchSchema, Status: "prepared", Environment: environment, Source: source, Versions: versions, Components: contracts, Releases: map[string]Released{}}
	if err := validateBatch(root, dir, head, batch, true, ""); err != nil {
		return nil, false, err
	}
	return batch, true, writeBatch(dir, batch)
}

// LoadBatch validates and returns the current canonical batch.
func LoadBatch(root, dir, head string, clean bool) (*Batch, error) {
	if clean {
		if err := requireClean(root); err != nil {
			return nil, err
		}
	}
	batch, err := readBatch(dir)
	if err != nil {
		return nil, err
	}
	if err := validateBatch(root, dir, head, batch, true, ""); err != nil {
		return nil, err
	}
	return batch, nil
}

// PendingReleases lists the immutable contracts of unrecorded components.
func PendingReleases(root, dir, head string) ([]Pending, error) {
	batch, err := LoadBatch(root, dir, head, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s is missing; run servicerelease batch before pending", BatchFile)
	}
	if err != nil {
		return nil, err
	}
	var out []Pending
	for _, contract := range batch.Components {
		if _, released := batch.Releases[contract.Record.ReleaseKey]; released {
			continue
		}
		out = append(out, contract)
	}
	return out, nil
}

// RecordRelease adds one locally tagged component and its staging pin to the
// batch. The caller publishes the record commit and component tags atomically.
func RecordRelease(root, dir, head, environment, component, repository, version, digest, source string) error {
	batch, err := readBatch(dir)
	if err != nil {
		return err
	}
	if batch.Environment != environment {
		return fmt.Errorf("release environment %q does not match batch environment %q", environment, batch.Environment)
	}
	if batch.Source != source {
		return fmt.Errorf("component %s source %s does not match batch source %s", component, source, batch.Source)
	}
	if batch.Schema != batchSchema || batch.Releases == nil {
		return fmt.Errorf("%s is not a complete schema-v%d batch object", BatchFile, batchSchema)
	}
	if err := validateContractSet(root, dir, batch); err != nil {
		return err
	}
	contract := contractByName(batch, component)
	if contract == nil {
		return fmt.Errorf("component %q is not in the immutable batch contract", component)
	}
	if contract.Version != version || contract.Image.Tag != version {
		return fmt.Errorf("component %s version %q does not match immutable batch version/tag %q", component, version, contract.Version)
	}
	if err := validateRepository(repository, contract); err != nil {
		return err
	}
	if !digestSHA.MatchString(digest) {
		return fmt.Errorf("digest %q is not sha256:<64 lowercase hex>", digest)
	}
	released := Released{Repository: repository, Digest: digest}
	if old, exists := batch.Releases[contract.Record.ReleaseKey]; exists && old != released {
		return fmt.Errorf("component %s is already recorded with different image provenance", component)
	}
	valuesPath := filepath.Join(root, filepath.FromSlash(contract.Deploy.ValuesFile))
	valuesRaw, err := os.ReadFile(valuesPath)
	if err != nil {
		return err
	}
	newValues, err := mutateDeploymentValues(valuesRaw, contract.Deploy, repository, contract.Image.Tag, digest, contract.Source)
	if err != nil {
		return err
	}
	candidate, err := cloneBatch(batch)
	if err != nil {
		return err
	}
	candidate.Releases[contract.Record.ReleaseKey] = released
	candidate.Status = batchStatus(candidate.Versions, candidate.Releases)
	if err := validateBatchOverlay(root, dir, head, candidate, true, "", map[string][]byte{contract.Deploy.ValuesFile: newValues}); err != nil {
		return err
	}
	batchRaw, err := marshalBatch(candidate)
	if err != nil {
		return err
	}
	return writeRecordAtomically(valuesPath, newValues, filepath.Join(dir, BatchFile), batchRaw)
}
