package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VersionsFile, in the release directory, lists the versions the release PR
// prepares: component name to version.
const VersionsFile = "versions.json"

// ErrNothingToRelease reports that no component has changed since its last release.
var ErrNothingToRelease = errors.New("nothing to release")

// Prepare writes the release a plan describes into dir: the versions file and,
// for each component, its changelog section on top of dir/<component>.md. It
// returns the release PR's title and Markdown body.
func Prepare(dir, date string, plans []Plan) (title, body string, err error) {
	versions := map[string]string{}
	selected := map[string]Plan{}
	for _, p := range plans {
		if p.Next == "" {
			continue
		}
		if componentByName(p.Component) == nil {
			return "", "", fmt.Errorf("release plan contains unknown or aliased component %q", p.Component)
		}
		if _, duplicate := selected[p.Component]; duplicate {
			return "", "", fmt.Errorf("release plan contains duplicate component %q", p.Component)
		}
		if _, err := ParseVersion(p.Next); err != nil {
			return "", "", fmt.Errorf("release plan component %s: %w", p.Component, err)
		}
		selected[p.Component] = p
		versions[p.Component] = p.Next
	}
	if len(versions) == 0 {
		return "", "", ErrNothingToRelease
	}
	expected, err := expectedComponentSet(versions)
	if err != nil {
		return "", "", err
	}
	var names []string
	var b strings.Builder
	for _, component := range expected {
		p := selected[component]
		names = append(names, p.Component+" "+p.Next)
		section := changelogSection(p, date)
		if err := prependChangelog(filepath.Join(dir, p.Component+".md"), p.Component, section); err != nil {
			return "", "", err
		}
		b.WriteString(strings.Replace(section, "## ", "### "+p.Component+" ", 1))
		b.WriteString("\n")
	}
	raw, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := writeAtomicFile(filepath.Join(dir, VersionsFile), append(raw, '\n')); err != nil {
		return "", "", err
	}
	title = "release: " + strings.Join(names, ", ")
	body = "Merging this PR releases each service below: its image is built from the merge commit, pushed and tagged, and staging is pinned to its digest (docs/services/releasing.md).\n\n" + b.String()
	return title, body, nil
}

// maxListed bounds the commits a changelog section lists; a PR body holds at
// most 65536 characters.
const maxListed = 100

func changelogSection(p Plan, date string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s (%s)\n\n", p.Next, date)
	if p.Tag == "" {
		// The whole history so far; listing it would say nothing.
		noun := "commits"
		if len(p.Commits) == 1 {
			noun = "commit"
		}
		fmt.Fprintf(&b, "First release, from %d %s.\n", len(p.Commits), noun)
		return b.String()
	}
	for i, c := range p.Commits {
		if i == maxListed {
			fmt.Fprintf(&b, "- and %d more\n", len(p.Commits)-maxListed)
			break
		}
		fmt.Fprintf(&b, "- %s (%s)\n", c.Subject, c.SHA[:min(len(c.SHA), 8)])
	}
	return b.String()
}

func prependChangelog(path, component, section string) error {
	head := "# " + component + " changelog\n\n"
	old, err := readRegularFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rest := strings.TrimPrefix(string(old), head)
	return writeAtomicFile(path, []byte(head+section+"\n"+rest))
}

// Deploy pins a component's released image in an environment's value file,
// keeping the file's other values and comments.
func Deploy(root, environment, component, repository, tag, digest, source string) error {
	var c *Component
	for i := range Components {
		if Components[i].Name == component {
			c = &Components[i]
		}
	}
	if c == nil {
		return fmt.Errorf("no component %q", component)
	}
	if _, err := ParseVersion(tag); err != nil {
		return err
	}
	if repository == "" {
		return fmt.Errorf("repository is empty")
	}
	if !digestSHA.MatchString(digest) {
		return fmt.Errorf("digest %q is not sha256:<64 lowercase hex>", digest)
	}
	target := ComponentDeploy{
		Chart: c.Chart, ValuesFile: filepath.ToSlash(filepath.Join("deploy", "environments", environment, c.Deploy.File+".yaml")),
		Path: append([]string(nil), c.Deploy.Path...), RepositoryKey: c.Deploy.Repository,
		TagKey: c.Deploy.Tag, DigestKey: c.Deploy.Digest, SourceKey: c.Deploy.Source,
	}
	if target.SourceKey != "" && !fullSHA.MatchString(source) {
		return fmt.Errorf("source %q is not a full lowercase Git SHA", source)
	}
	return deployContract(root, target, repository, tag, digest, source)
}

// deployContract writes only the exact source-pinned deployment target supplied
// by the immutable batch contract.
func deployContract(root string, target ComponentDeploy, repository, tag, digest, source string) error {
	path, err := safeRepoPath(root, target.ValuesFile, false)
	if err != nil {
		return err
	}
	raw, err := readRegularFile(path)
	if err != nil {
		return err
	}
	out, err := mutateDeploymentValues(raw, target, repository, tag, digest, source)
	if err != nil {
		return err
	}
	return writeAtomicFile(path, out)
}
