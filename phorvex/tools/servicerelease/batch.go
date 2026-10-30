package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// BatchFile is the canonical, committed record for the prepared release.
	BatchFile   = "batch.json"
	batchSchema = 1
	// ReleaseEnvironment is the one environment the release workflow records.
	ReleaseEnvironment = "staging"
)

var (
	fullSHA   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestSHA = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Released records the immutable image identity published for one component.
// Source is deliberately batch-wide, in Batch.Source, rather than repeated.
type Released struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// Batch is the canonical release record. Versions and Source never change for
// a batch; Releases grows from empty to the complete version set.
type Batch struct {
	Schema      int                 `json:"schema"`
	Status      string              `json:"status"`
	Environment string              `json:"environment"`
	Source      string              `json:"source"`
	Versions    map[string]string   `json:"versions"`
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

func writeBatch(dir string, batch *Batch) error {
	raw, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, BatchFile), append(raw, '\n'), 0o644)
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

func tagCommit(root, component, version string) (string, bool, error) {
	ref := "refs/tags/" + component + "-v" + version
	out, err := git(root, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
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

func lookupMapping(m *yaml.Node, key string) (*yaml.Node, bool) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], true
		}
	}
	return nil, false
}

func pinValues(root, environment string, c *Component) (map[string]string, error) {
	path := filepath.Join(root, "deploy", "environments", environment, c.Deploy.File+".yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%s: not a document", path)
	}
	node := doc.Content[0]
	for _, key := range c.Deploy.Path {
		var ok bool
		node, ok = lookupMapping(node, key)
		if !ok {
			return nil, fmt.Errorf("%s: missing image path %s", path, strings.Join(c.Deploy.Path, "."))
		}
	}
	values := map[string]string{}
	for _, key := range []string{c.Deploy.Repository, c.Deploy.Tag, c.Deploy.Digest, c.Deploy.Source} {
		if key == "" {
			continue
		}
		value, ok := lookupMapping(node, key)
		if !ok || value.Kind != yaml.ScalarNode || value.Value == "" {
			return nil, fmt.Errorf("%s: missing image value %s", path, key)
		}
		values[key] = value.Value
	}
	return values, nil
}

func validateRepository(repository string, c *Component) error {
	if !strings.HasSuffix(repository, "/"+c.Repository) || strings.TrimSuffix(repository, "/"+c.Repository) == "" {
		return fmt.Errorf("component %s repository %q does not end in /%s", c.Name, repository, c.Repository)
	}
	return nil
}

func validatePin(root string, batch *Batch, name, version string, released Released) error {
	c := componentByName(name)
	if c == nil {
		return fmt.Errorf("batch: unknown component %q", name)
	}
	if err := validateRepository(released.Repository, c); err != nil {
		return err
	}
	if !digestSHA.MatchString(released.Digest) {
		return fmt.Errorf("component %s digest %q is not sha256:<64 lowercase hex>", name, released.Digest)
	}
	values, err := pinValues(root, batch.Environment, c)
	if err != nil {
		return err
	}
	if values[c.Deploy.Repository] != released.Repository || values[c.Deploy.Tag] != version || values[c.Deploy.Digest] != released.Digest {
		return fmt.Errorf("component %s release record does not match its %s image pin", name, batch.Environment)
	}
	if c.Deploy.Source != "" && values[c.Deploy.Source] != batch.Source {
		return fmt.Errorf("component %s image pin source %q does not match batch source %s", name, values[c.Deploy.Source], batch.Source)
	}
	return nil
}

// validateBatch verifies the whole batch. allowTag permits RecordRelease to
// validate the one just-created local tag before adding its release entry.
func validateBatch(root, dir, head string, batch *Batch, current bool, allowTag string) error {
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
	for name, version := range batch.Versions {
		if componentByName(name) == nil {
			return fmt.Errorf("%s: unknown component %q", BatchFile, name)
		}
		if _, err := ParseVersion(version); err != nil {
			return fmt.Errorf("%s: %s: %w", BatchFile, name, err)
		}
		released, recorded := batch.Releases[name]
		taggedSource, tagged, err := tagCommit(root, name, version)
		if err != nil {
			return err
		}
		if tagged && taggedSource != batch.Source {
			return fmt.Errorf("component %s tag points to %s, batch source is %s", name, taggedSource, batch.Source)
		}
		switch {
		case recorded && !tagged:
			return fmt.Errorf("component %s is recorded without tag %s-v%s", name, name, version)
		case !recorded && tagged && allowTag != name:
			return fmt.Errorf("component %s tag exists without a release record", name)
		case recorded:
			if err := validatePin(root, batch, name, version, released); err != nil {
				return err
			}
		}
	}
	for name := range batch.Releases {
		if _, ok := batch.Versions[name]; !ok {
			return fmt.Errorf("%s: release %q is not in the prepared version set", BatchFile, name)
		}
	}
	wantStatus := batchStatus(batch.Versions, batch.Releases)
	if batch.Status != wantStatus {
		return fmt.Errorf("%s: status %q, want %q", BatchFile, batch.Status, wantStatus)
	}
	return nil
}

func importCompleteBatch(root, dir, head, environment, source string, versions map[string]string) (*Batch, error) {
	batch := &Batch{Schema: batchSchema, Environment: environment, Source: source, Versions: versions, Releases: map[string]Released{}}
	tagged := 0
	for name, version := range versions {
		taggedSource, ok, err := tagCommit(root, name, version)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		tagged++
		if taggedSource != source {
			return nil, fmt.Errorf("component %s tag points to %s, prepared source is %s", name, taggedSource, source)
		}
	}
	if tagged != 0 && tagged != len(versions) {
		return nil, fmt.Errorf("%s is missing for a partially tagged release; refusing to infer a batch source", BatchFile)
	}
	if tagged == len(versions) {
		for name, version := range versions {
			c := componentByName(name)
			values, err := pinValues(root, environment, c)
			if err != nil {
				return nil, err
			}
			released := Released{Repository: values[c.Deploy.Repository], Digest: values[c.Deploy.Digest]}
			if values[c.Deploy.Tag] != version {
				return nil, fmt.Errorf("component %s pin version %q, want %q", name, values[c.Deploy.Tag], version)
			}
			if c.Deploy.Source != "" && values[c.Deploy.Source] != source {
				return nil, fmt.Errorf("component %s pin source %q, want %q", name, values[c.Deploy.Source], source)
			}
			batch.Releases[name] = released
		}
	}
	batch.Status = batchStatus(batch.Versions, batch.Releases)
	if err := validateBatch(root, dir, head, batch, true, ""); err != nil {
		return nil, err
	}
	return batch, nil
}

// EnsureBatch creates the source pin for a newly prepared version set, or
// validates the existing batch. It must run and be committed before any build.
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
	batch = &Batch{Schema: batchSchema, Status: "prepared", Environment: environment, Source: source, Versions: versions, Releases: map[string]Released{}}
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

// PendingReleases lists the unrecorded components of a valid prepared batch.
func PendingReleases(root, dir, head string) ([]Pending, error) {
	batch, err := LoadBatch(root, dir, head, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s is missing; run servicerelease batch before pending", BatchFile)
	}
	if err != nil {
		return nil, err
	}
	var out []Pending
	for _, c := range Components {
		version, ok := batch.Versions[c.Name]
		if !ok {
			continue
		}
		if _, released := batch.Releases[c.Name]; released {
			continue
		}
		pending := Pending{Component: c.Name, Version: version, Dockerfile: c.Dockerfile, Repository: c.Repository, Target: c.Target}
		for key, value := range c.BuildArgs {
			pending.BuildArgs = append(pending.BuildArgs, key+"="+strings.ReplaceAll(value, "{version}", version))
		}
		sort.Strings(pending.BuildArgs)
		out = append(out, pending)
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
	if batch.Versions[component] != version {
		return fmt.Errorf("component %s version %q does not match prepared version %q", component, version, batch.Versions[component])
	}
	c := componentByName(component)
	if c == nil {
		return fmt.Errorf("no component %q", component)
	}
	if err := validateRepository(repository, c); err != nil {
		return err
	}
	if !digestSHA.MatchString(digest) {
		return fmt.Errorf("digest %q is not sha256:<64 lowercase hex>", digest)
	}
	if err := validateBatch(root, dir, head, batch, true, component); err != nil {
		return err
	}
	released := Released{Repository: repository, Digest: digest}
	if old, exists := batch.Releases[component]; exists && old != released {
		return fmt.Errorf("component %s is already recorded with different image provenance", component)
	}
	if err := Deploy(root, environment, component, repository, version, digest, source); err != nil {
		return err
	}
	batch.Releases[component] = released
	batch.Status = batchStatus(batch.Versions, batch.Releases)
	if err := writeBatch(dir, batch); err != nil {
		return err
	}
	return validateBatch(root, dir, head, batch, true, "")
}
