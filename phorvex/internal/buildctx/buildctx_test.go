// Package buildctx holds a build-context regression: every local `replace`
// target a module needs must actually be COPYed into the image stage that
// compiles that module.
//
// This exists because a local `go build` cannot see the problem. Adding
// `replace github.com/phorvex/metricvalidity => ../build/metricvalidity` to
// phorvex/go.mod builds perfectly on a developer machine and in preflight, and
// then fails at `go mod download` inside every image whose build context does
// not contain that directory. The images are also the only place CI compiles
// this Go code at all, so the failure would land in the release build.
package buildctx

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot is this module's parent: phorvex/internal/buildctx -> repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "docker")); err != nil {
		t.Fatalf("cannot locate the repo root from this package: %v", err)
	}
	return root
}

// buildStage is one image stage that compiles a Go module.
type buildStage struct {
	dockerfile string
	// module is the module directory, relative to the repo root, that the stage
	// builds in.
	module string
}

// stages are the image stages that compile Go code from this repo. The
// dockerfile inventory below asserts this list stays complete, so a new image
// cannot silently escape the check.
var stages = []buildStage{
	{"deploy/docker/operator.Dockerfile", "phorvex"},
	{"deploy/docker/console.Dockerfile", "phorvex"},
	{"deploy/docker/console.Dockerfile", "build/test-harness"},
}

var (
	copyRe    = regexp.MustCompile(`(?m)^COPY\s+(.+)$`)
	replaceRe = regexp.MustCompile(`(?m)^\s*replace\s+\S+\s+=>\s+(\.\S*)`)
)

// copiedPaths returns the repo-relative source paths a Dockerfile COPYs in.
func copiedPaths(t *testing.T, dockerfile string) []string {
	t.Helper()
	b, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range copyRe.FindAllStringSubmatch(string(b), -1) {
		fields := strings.Fields(m[1])
		// Drop flags (--from=..., --chmod=...) and the final destination.
		var srcs []string
		for _, f := range fields {
			if strings.HasPrefix(f, "--") {
				continue
			}
			srcs = append(srcs, f)
		}
		if len(srcs) < 2 {
			continue
		}
		out = append(out, srcs[:len(srcs)-1]...)
	}
	return out
}

// localReplaces returns each local (relative-path) replace target of a module,
// resolved to a repo-relative directory.
func localReplaces(t *testing.T, root, module string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, module, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range replaceRe.FindAllStringSubmatch(string(b), -1) {
		abs := filepath.Clean(filepath.Join(root, module, m[1]))
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			t.Fatalf("replace target %q escapes the repo: %v", m[1], err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// covers reports whether a COPY source list brings `want` into the context.
func covers(copied []string, want string) bool {
	for _, c := range copied {
		c = filepath.ToSlash(filepath.Clean(strings.TrimSuffix(c, "/")))
		if c == want || strings.HasPrefix(want+"/", c+"/") {
			return true
		}
	}
	return false
}

// Every local replace target of every module an image stage builds must be in
// that image's build context.
func TestImageBuildContextsContainEveryLocalReplaceTarget(t *testing.T) {
	root := repoRoot(t)
	for _, s := range stages {
		t.Run(filepath.Base(s.dockerfile)+":"+s.module, func(t *testing.T) {
			copied := copiedPaths(t, filepath.Join(root, s.dockerfile))
			targets := localReplaces(t, root, s.module)
			if len(targets) == 0 {
				t.Fatalf("fixture relevance: %s/go.mod declares no local replace, so this check proves nothing", s.module)
			}
			for _, want := range targets {
				if !covers(copied, want) {
					t.Errorf("%s builds %s, whose go.mod replaces a module with the local path %q, "+
						"but that path is never COPYed into the build context.\n"+
						"`go mod download` fails on a missing replace target, so this image cannot build.\n"+
						"COPY sources present: %v", s.dockerfile, s.module, want, copied)
				}
			}
			// The module itself must be in the context too.
			if !covers(copied, s.module) {
				t.Errorf("%s builds %s but never COPYs it", s.dockerfile, s.module)
			}
		})
	}
}

// The stage inventory above must stay complete: a new Go-building Dockerfile
// that nobody adds here would escape the check entirely.
func TestEveryDeployDockerfileIsCovered(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "deploy", "docker"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, s := range stages {
		known[filepath.Base(s.dockerfile)] = true
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".Dockerfile") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "deploy", "docker", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "go build") && !strings.Contains(string(b), "go mod download") {
			continue // not a Go build stage
		}
		if !known[e.Name()] {
			t.Errorf("deploy/docker/%s compiles Go but is not listed in `stages`, so its build context "+
				"is never checked for local replace targets", e.Name())
		}
	}
}
