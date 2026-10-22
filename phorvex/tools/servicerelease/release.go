package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
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
	var names []string
	var b strings.Builder
	for _, p := range plans {
		if p.Next == "" {
			continue
		}
		versions[p.Component] = p.Next
		names = append(names, p.Component+" "+p.Next)
		section := changelogSection(p, date)
		if err := prependChangelog(filepath.Join(dir, p.Component+".md"), p.Component, section); err != nil {
			return "", "", err
		}
		b.WriteString(strings.Replace(section, "## ", "### "+p.Component+" ", 1))
		b.WriteString("\n")
	}
	if len(versions) == 0 {
		return "", "", ErrNothingToRelease
	}
	raw, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(dir, VersionsFile), append(raw, '\n'), 0o644); err != nil {
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
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rest := strings.TrimPrefix(string(old), head)
	return os.WriteFile(path, []byte(head+section+"\n"+rest), 0o644)
}

// Pending is a prepared release whose tag does not exist yet.
type Pending struct {
	Component  string
	Version    string
	Dockerfile string
	Repository string
	// BuildArgs are sorted --build-arg values.
	BuildArgs []string
	// Target is the Dockerfile stage to build, or empty for the last.
	Target string
}

// PendingReleases lists the prepared releases in dir not yet tagged at head.
func PendingReleases(root, dir, head string) ([]Pending, error) {
	raw, err := os.ReadFile(filepath.Join(dir, VersionsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	versions := map[string]string{}
	if err := json.Unmarshal(raw, &versions); err != nil {
		return nil, fmt.Errorf("%s: %w", VersionsFile, err)
	}
	var out []Pending
	for _, c := range Components {
		v, ok := versions[c.Name]
		if !ok {
			continue
		}
		if _, err := ParseVersion(v); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", VersionsFile, c.Name, err)
		}
		if _, err := git(root, "rev-parse", "--verify", "--quiet", "refs/tags/"+c.Name+"-v"+v); err == nil {
			continue // released
		}
		p := Pending{Component: c.Name, Version: v, Dockerfile: c.Dockerfile, Repository: c.Repository, Target: c.Target}
		for k, val := range c.BuildArgs {
			p.BuildArgs = append(p.BuildArgs, k+"="+strings.ReplaceAll(val, "{version}", v))
		}
		sort.Strings(p.BuildArgs)
		out = append(out, p)
	}
	return out, nil
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
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return fmt.Errorf("digest %q is not sha256:<64 hex>", digest)
	}
	path := filepath.Join(root, "deploy", "environments", environment, c.Deploy.File+".yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a mapping", path)
	}
	node := doc.Content[0]
	for _, key := range c.Deploy.Path {
		node = mapping(node, key)
	}
	set(node, c.Deploy.Repository, repository)
	set(node, c.Deploy.Tag, tag)
	set(node, c.Deploy.Digest, digest)
	if c.Deploy.Source != "" {
		set(node, c.Deploy.Source, source)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// mapping returns the mapping under key in m, creating it, in block style.
func mapping(m *yaml.Node, key string) *yaml.Node {
	m.Style = 0
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if v.Kind != yaml.MappingNode {
				*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			v.Style = 0
			return v
		}
	}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	return v
}

// set sets key in m to a quoted string.
func set(m *yaml.Node, key, value string) {
	m.Style = 0
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v.LineComment = m.Content[i+1].LineComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}
