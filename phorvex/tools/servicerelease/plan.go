package main

import (
	"fmt"
	"os/exec"
	"reflect"
	"strings"
)

// Commit is one commit of a component's next release.
type Commit struct {
	SHA     string `json:"sha"`
	Subject string `json:"subject"`
	Bump    string `json:"bump"`
}

// Plan is a component's next release.
type Plan struct {
	Component string `json:"component"`
	// Tag and Current are its last release; empty before the first.
	Tag     string `json:"tag,omitempty"`
	Current string `json:"current,omitempty"`
	// Next is the version its next release takes; empty when nothing changed.
	Next    string   `json:"next,omitempty"`
	Bump    string   `json:"bump"`
	Commits []Commit `json:"commits"`
}

// Resolver lists a component's inputs; ResolveInputs reads the import graph.
type Resolver func(root string, c Component) (Inputs, error)

func git(root string, args ...string) (string, error) {
	// Paths are read verbatim, not C-quoted.
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	before, err := pathSnapshot(gitPath, false)
	if err != nil {
		return "", fmt.Errorf("git executable: %w", err)
	}
	cmd, cleanup, err := pinnedCommand(gitPath, append([]string{"-c", "core.quotePath=false"}, args...)...)
	if err != nil {
		return "", err
	}
	defer cleanup()
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	after, err := pathSnapshot(gitPath, false)
	if err != nil || !reflect.DeepEqual(before, after) {
		return "", fmt.Errorf("git executable identity changed during command")
	}
	return string(out), nil
}

// LastRelease returns the highest <name>-v<version> tag reachable from head.
func LastRelease(root, name, head string) (tag string, v Version, ok bool, err error) {
	out, err := git(root, "tag", "--list", name+"-v*", "--merged", head)
	if err != nil {
		return "", Version{}, false, err
	}
	for _, t := range strings.Fields(out) {
		tv, perr := ParseVersion(strings.TrimPrefix(t, name+"-v"))
		if perr != nil {
			continue // not a release tag of this component
		}
		if !ok || v.Less(tv) {
			tag, v, ok = t, tv, true
		}
	}
	return tag, v, ok, nil
}

type loggedCommit struct {
	sha, subject, body string
	files              []string
}

// commits lists the non-merge commits of base..head, or of all of head's history
// when base is empty, with the files each changed.
func commits(root, base, head string) ([]loggedCommit, error) {
	span := head
	if base != "" {
		span = base + ".." + head
	}
	out, err := git(root, "log", "--no-merges", "--no-renames", "--format=%x1e%H%x1f%s%x1f%b%x1f", "--name-only", span)
	if err != nil {
		return nil, err
	}
	var list []loggedCommit
	for _, record := range strings.Split(out, "\x1e") {
		fields := strings.SplitN(record, "\x1f", 4)
		if len(fields) != 4 {
			continue
		}
		c := loggedCommit{sha: fields[0], subject: fields[1], body: fields[2]}
		for _, f := range strings.Split(fields[3], "\n") {
			if f = strings.TrimSpace(f); f != "" {
				c.files = append(c.files, f)
			}
		}
		list = append(list, c)
	}
	return list, nil
}

// PlanReleases computes every component's next release at head. The inputs are
// those of head's import graph.
func PlanReleases(root, head string, resolve Resolver) ([]Plan, error) {
	var plans []Plan
	for _, c := range Components {
		in, err := resolve(root, c)
		if err != nil {
			return nil, err
		}
		tag, current, released, err := LastRelease(root, c.Name, head)
		if err != nil {
			return nil, err
		}
		log, err := commits(root, tag, head)
		if err != nil {
			return nil, err
		}
		p := Plan{Component: c.Name, Tag: tag, Commits: []Commit{}}
		bump := BumpNone
		for _, lc := range log {
			if !touches(in, lc.files) {
				continue
			}
			b := CommitBump(lc.subject, lc.body)
			if b > bump {
				bump = b
			}
			p.Commits = append(p.Commits, Commit{SHA: lc.sha, Subject: lc.subject, Bump: b.String()})
		}
		p.Bump = bump.String()
		switch {
		case !released:
			p.Next = c.Initial
		case bump != BumpNone:
			p.Current, p.Next = current.String(), current.Apply(bump).String()
		default:
			p.Current = current.String()
		}
		plans = append(plans, p)
	}
	return plans, nil
}

// Affected returns the components whose inputs a change from base to head touches.
func Affected(root, base, head string, resolve Resolver) ([]string, error) {
	out, err := git(root, "diff", "--no-renames", "--name-only", base, head)
	if err != nil {
		return nil, err
	}
	changed := strings.Split(strings.TrimSpace(out), "\n")
	var names []string
	for _, c := range Components {
		in, err := resolve(root, c)
		if err != nil {
			return nil, err
		}
		if touches(in, changed) {
			names = append(names, c.Name)
		}
	}
	return names, nil
}

func touches(in Inputs, files []string) bool {
	for _, f := range files {
		if in.Contains(f) {
			return true
		}
	}
	return false
}
