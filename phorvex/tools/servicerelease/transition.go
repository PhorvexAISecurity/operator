package main

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

func transitionEndpoint(rootArg, dir, head, name string) (string, string, error) {
	if rootArg == "" {
		return "", "", fmt.Errorf("%s endpoint root is required", name)
	}
	rootArg, err := safeRoot(rootArg)
	if err != nil {
		return "", "", fmt.Errorf("%s endpoint: %w", name, err)
	}
	resolvedRoot, err := git(rootArg, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", fmt.Errorf("%s endpoint: %w", name, err)
	}
	resolvedRoot, err = safeRoot(strings.TrimSpace(resolvedRoot))
	if err != nil {
		return "", "", fmt.Errorf("%s endpoint: %w", name, err)
	}
	if resolvedRoot != rootArg {
		return "", "", fmt.Errorf("%s endpoint %s is not the repository root %s", name, rootArg, resolvedRoot)
	}
	if !fullSHA.MatchString(head) {
		return "", "", fmt.Errorf("%s endpoint commit %q is not a full lowercase Git SHA", name, head)
	}
	resolvedHead, err := resolveCommit(rootArg, head)
	if err != nil || resolvedHead != head {
		return "", "", fmt.Errorf("%s endpoint commit %s does not resolve exactly", name, head)
	}
	actualHead, err := resolveCommit(rootArg, "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("%s endpoint HEAD: %w", name, err)
	}
	if actualHead != head {
		return "", "", fmt.Errorf("%s endpoint HEAD %s, want exact commit %s", name, actualHead, head)
	}
	if ref, err := git(rootArg, "symbolic-ref", "-q", "HEAD"); err == nil {
		return "", "", fmt.Errorf("%s endpoint is attached to mutable ref %s", name, strings.TrimSpace(ref))
	}
	if err := requireClean(rootArg); err != nil {
		return "", "", fmt.Errorf("%s endpoint: %w", name, err)
	}
	releaseDir := dir
	if !filepath.IsAbs(releaseDir) {
		releaseDir = filepath.Join(rootArg, releaseDir)
	}
	releaseDir, err = withinRoot(rootArg, releaseDir)
	if err != nil {
		return "", "", fmt.Errorf("%s endpoint: %w", name, err)
	}
	return rootArg, releaseDir, nil
}

func validateTransitionShape(previous, latest *Batch) error {
	if previous.Schema != latest.Schema {
		return fmt.Errorf("release batch schema changed from %d to %d", previous.Schema, latest.Schema)
	}
	if previous.Environment != latest.Environment {
		return fmt.Errorf("release batch environment changed from %q to %q", previous.Environment, latest.Environment)
	}
	if previous.Source != latest.Source {
		return fmt.Errorf("release batch source changed from %s to %s", previous.Source, latest.Source)
	}
	if !slices.Equal(previous.ExpectedComponents, latest.ExpectedComponents) {
		return fmt.Errorf("release batch expected component set changed from %v to %v", previous.ExpectedComponents, latest.ExpectedComponents)
	}
	if !mapsEqual(previous.Versions, latest.Versions) {
		return fmt.Errorf("release batch versions changed")
	}
	if !reflect.DeepEqual(previous.Components, latest.Components) {
		return fmt.Errorf("release batch component/source/metadata contract changed")
	}
	for name, recorded := range previous.Releases {
		current, ok := latest.Releases[name]
		if !ok {
			return fmt.Errorf("release record %s was deleted or rolled back to pending", name)
		}
		if current != recorded {
			return fmt.Errorf("release record %s repository/digest was replaced", name)
		}
	}
	if len(latest.Releases) < len(previous.Releases) {
		return fmt.Errorf("release record set shrank from %d to %d", len(previous.Releases), len(latest.Releases))
	}
	return nil
}

// ValidateBatchTransition proves two immutable Git endpoints independently,
// then permits only idempotence or additive completion of previously pending
// component records. All source, component, image, deployment and consumer
// authority comes from the servicerelease binary compiled at the pinned source.
func ValidateBatchTransition(previousRoot, latestRoot, dir, previousHead, latestHead string) (*Batch, *Batch, error) {
	previousRoot, previousDir, err := transitionEndpoint(previousRoot, dir, previousHead, "expected")
	if err != nil {
		return nil, nil, err
	}
	latestRoot, latestDir, err := transitionEndpoint(latestRoot, dir, latestHead, "latest")
	if err != nil {
		return nil, nil, err
	}
	if _, err := git(latestRoot, "merge-base", "--is-ancestor", previousHead, latestHead); err != nil {
		return nil, nil, fmt.Errorf("expected endpoint %s is not an ancestor of latest endpoint %s", previousHead, latestHead)
	}

	previous, err := readBatch(previousDir)
	if err != nil {
		return nil, nil, fmt.Errorf("expected endpoint: %w", err)
	}
	if err := validateHistoricalBatch(previousRoot, previousDir, previousHead, previous); err != nil {
		return nil, nil, fmt.Errorf("expected endpoint: %w", err)
	}
	latest, err := readBatch(latestDir)
	if err != nil {
		return nil, nil, fmt.Errorf("latest endpoint: %w", err)
	}
	if err := validateBatch(latestRoot, latestDir, latestHead, latest, true, ""); err != nil {
		return nil, nil, fmt.Errorf("latest endpoint: %w", err)
	}
	if err := validateTransitionShape(previous, latest); err != nil {
		return nil, nil, fmt.Errorf("release state transition: %w", err)
	}
	return previous, latest, nil
}
