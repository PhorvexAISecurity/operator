package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a release version, major.minor.patch.
type Version struct{ Major, Minor, Patch int }

var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ParseVersion parses major.minor.patch, without a leading v.
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("version %q is not major.minor.patch", s)
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	return Version{n(1), n(2), n(3)}, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Less orders versions.
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

// Bump is how far a release moves the version.
type Bump int

const (
	BumpNone Bump = iota
	BumpPatch
	BumpMinor
	BumpMajor
)

func (b Bump) String() string { return [...]string{"none", "patch", "minor", "major"}[b] }

// conventionalRe matches a conventional-commit subject: type(scope)!: description.
var conventionalRe = regexp.MustCompile(`^([a-z]+)(\([^)]*\))?(!)?: `)

// CommitBump is the bump one commit that touches a component's inputs asks for.
// A breaking change (`!` or a BREAKING CHANGE footer) is major, a feature minor,
// and anything else patch: whatever its type, the commit changed what the image
// is built from.
func CommitBump(subject, body string) Bump {
	m := conventionalRe.FindStringSubmatch(subject)
	switch {
	case m != nil && m[3] == "!", strings.Contains(body, "BREAKING CHANGE:"), strings.Contains(body, "BREAKING-CHANGE:"):
		return BumpMajor
	case m != nil && m[1] == "feat":
		return BumpMinor
	}
	return BumpPatch
}

// Apply moves v by b. Before 1.0.0 a breaking change moves the minor version,
// as a feature does.
func (v Version) Apply(b Bump) Version {
	if v.Major == 0 && b == BumpMajor {
		b = BumpMinor
	}
	switch b {
	case BumpMajor:
		return Version{v.Major + 1, 0, 0}
	case BumpMinor:
		return Version{v.Major, v.Minor + 1, 0}
	case BumpPatch:
		return Version{v.Major, v.Minor, v.Patch + 1}
	}
	return v
}
