package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// repoRoot is the repository root: phorvex/tools/servicerelease -> ../../..
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "docker")); err != nil {
		t.Fatalf("cannot locate the repository root: %v", err)
	}
	return root
}

func component(t *testing.T, name string) Component {
	t.Helper()
	for _, c := range Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component %s", name)
	return Component{}
}

var (
	buildRe   = regexp.MustCompile(`go build[^\n]*?((?:\s+\.?/?cmd[^\s&]*)+)\s*(?:&&|\n|$)`)
	workdirRe = regexp.MustCompile(`(?m)^WORKDIR /workspace/(\S+)$`)
)

// dockerBuilds reads the main packages each Go module stage of a Dockerfile builds.
func dockerBuilds(t *testing.T, root, dockerfile, service string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, dockerfile))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\\\n", " ")
	out := map[string][]string{}
	module := ""
	for _, line := range strings.Split(text, "\n") {
		if m := workdirRe.FindStringSubmatch(line); m != nil {
			module = m[1]
		}
		for _, m := range buildRe.FindAllStringSubmatch(line, -1) {
			for _, pkg := range strings.Fields(m[1]) {
				pkg = strings.ReplaceAll(pkg, "${SERVICE}", service)
				pkg = "./" + strings.TrimPrefix(strings.TrimSuffix(pkg, "/main.go"), "./")
				out[module] = append(out[module], pkg)
			}
		}
	}
	return out
}

// The components build exactly what their images build.
func TestComponentsBuildWhatTheirImagesBuild(t *testing.T) {
	root := repoRoot(t)
	images := map[string]bool{}
	for _, c := range Components {
		images[c.Image] = true
		want := map[string][]string{}
		for _, b := range c.Builds {
			want[b.Module] = append(want[b.Module], b.Packages...)
		}
		got := dockerBuilds(t, root, c.Dockerfile, c.Name)
		for m := range want {
			slices.Sort(want[m])
			slices.Sort(got[m])
		}
		if len(got) != len(want) {
			t.Errorf("%s: %s builds modules %v, the component %v", c.Name, c.Dockerfile, got, want)
		}
		for m := range want {
			if !slices.Equal(got[m], want[m]) {
				t.Errorf("%s: %s builds %v in %s, the component %v", c.Name, c.Dockerfile, got[m], m, want[m])
			}
		}
		for _, p := range append(c.Paths, c.Chart) {
			if _, err := os.Stat(filepath.Join(root, p)); p != "" && err != nil {
				t.Errorf("%s: input %s: %v", c.Name, p, err)
			}
		}
		if _, err := ParseVersion(c.Initial); err != nil {
			t.Error(c.Name, err)
		}
	}
	// Every image PR validation builds is a component, and every component an image.
	raw, err := os.ReadFile(filepath.Join(root, ".github/workflows/pr-validation.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`image: \[([^\]]*)\]`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("pr-validation.yml has no images matrix")
	}
	var matrix []string
	for _, i := range strings.Split(m[1], ",") {
		matrix = append(matrix, strings.TrimSpace(i))
	}
	for _, i := range matrix {
		if !images[i] {
			t.Errorf("image %s is built but released by no component", i)
		}
	}
	if len(matrix) != len(images) {
		t.Errorf("images matrix %v, components %v", matrix, images)
	}
}

// A service's inputs follow its binaries' import graph.
func TestInputsFollowTheImportGraph(t *testing.T) {
	root := repoRoot(t)
	inputs := map[string]Inputs{}
	for _, c := range Components {
		in, err := ResolveInputs(root, c)
		if err != nil {
			t.Fatal(err)
		}
		inputs[c.Name] = in
	}
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"phorvex/internal/brainsvc/server.go", []string{"brain", "console", "manager"}},
		{"phorvex/internal/sensorsvc/server.go", []string{"console", "manager", "sensor"}},
		{"phorvex/internal/actuatorsvc/server.go", []string{"actuator", "console", "manager"}},
		{"phorvex/internal/wire/wire.go", []string{"actuator", "brain", "console", "manager", "sensor"}},
		{"phorvex/cmd/brain/main.go", []string{"brain"}},
		{"phorvex/go.mod", []string{"actuator", "brain", "console", "manager", "sensor"}},
		{"libs/logging/logging.go", []string{"actuator", "brain", "console", "manager", "sensor"}},
		{"deploy/charts/phorvex-sensor/values.yaml", []string{"sensor"}},
		{"phorvex/charts/phorvex/values.yaml", []string{"manager"}},
		{"deploy/docker/service.Dockerfile", []string{"actuator", "brain", "sensor"}},
		{"dashboard-web/package.json", []string{"console"}},
		{"phorvex/internal/brainsvc/server_test.go", nil},
		{"docs/services/brain.md", nil},
	} {
		var got []string
		for _, c := range Components {
			if inputs[c.Name].Contains(tc.path) {
				got = append(got, c.Name)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s is an input of %v, want %v", tc.path, got, tc.want)
		}
		if strings.HasSuffix(tc.path, ".go") && !strings.HasSuffix(tc.path, "_test.go") {
			if _, err := os.Stat(filepath.Join(root, tc.path)); err != nil {
				t.Errorf("fixture relevance: %v", err)
			}
		}
	}
}

func TestCommitBump(t *testing.T) {
	for _, tc := range []struct {
		subject, body string
		want          Bump
	}{
		{"fix(brain): keep the cost learner", "", BumpPatch},
		{"feat(charts): add the sensor chart", "", BumpMinor},
		{"feat!: drop the v1 contract", "", BumpMajor},
		{"refactor(sensor): split the projection", "BREAKING CHANGE: the snapshot shape changes", BumpMajor},
		{"test(charts): prove the split", "", BumpPatch},
		{"Merge the release", "", BumpPatch},
	} {
		if got := CommitBump(tc.subject, tc.body); got != tc.want {
			t.Errorf("CommitBump(%q) = %s, want %s", tc.subject, got, tc.want)
		}
	}
}

func TestVersionApply(t *testing.T) {
	for _, tc := range []struct {
		from string
		bump Bump
		want string
	}{
		{"0.1.0", BumpPatch, "0.1.1"},
		{"0.1.3", BumpMinor, "0.2.0"},
		{"0.1.3", BumpMajor, "0.2.0"}, // before 1.0.0 a breaking change moves the minor version
		{"1.4.2", BumpMajor, "2.0.0"},
		{"1.4.2", BumpMinor, "1.5.0"},
		{"1.4.2", BumpNone, "1.4.2"},
	} {
		v, err := ParseVersion(tc.from)
		if err != nil {
			t.Fatal(err)
		}
		if got := v.Apply(tc.bump).String(); got != tc.want {
			t.Errorf("%s + %s = %s, want %s", tc.from, tc.bump, got, tc.want)
		}
	}
	for _, bad := range []string{"v1.0.0", "1.0", "01.0.0", "1.0.0-rc1"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
}

// A release plan on a throwaway repository: only commits touching a
// component's inputs count, from its last tag on.
func TestPlanReleases(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit := func(file, message string) {
		t.Helper()
		path := filepath.Join(dir, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(message + "\n")
		_ = f.Close()
		run("add", "-A")
		run("commit", "-q", "-m", message)
	}
	run("init", "-q", "-b", "main")
	commit("brain/a.go", "feat(brain): first")
	commit("shared/s.go", "fix: shared")
	run("tag", "brain-v0.1.0")
	commit("docs/x.md", "docs: unrelated")
	commit("shared/s.go", "fix(shared): again")
	commit("brain/a.go", "feat(brain)!: new contract")
	commit("sensor/b.go", "feat(sensor): first")

	inputs := map[string]Inputs{
		"brain":  {Dirs: []string{"brain", "shared"}},
		"sensor": {Dirs: []string{"sensor", "shared"}},
	}
	resolve := func(_ string, c Component) (Inputs, error) { return inputs[c.Name], nil }
	saved := Components
	Components = []Component{{Name: "brain", Initial: "0.1.0"}, {Name: "sensor", Initial: "0.1.0"}}
	defer func() { Components = saved }()

	plans, err := PlanReleases(dir, "HEAD", resolve)
	if err != nil {
		t.Fatal(err)
	}
	brain, sensor := plans[0], plans[1]
	if brain.Tag != "brain-v0.1.0" || brain.Current != "0.1.0" || brain.Next != "0.2.0" || brain.Bump != "major" || len(brain.Commits) != 2 {
		t.Errorf("brain plan = %+v", brain)
	}
	// Never released: the first release takes the initial version, with every commit on its inputs.
	if sensor.Tag != "" || sensor.Next != "0.1.0" || len(sensor.Commits) != 3 {
		t.Errorf("sensor plan = %+v", sensor)
	}

	affected, err := Affected(dir, "HEAD~2", "HEAD", resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(affected, []string{"brain", "sensor"}) {
		t.Errorf("affected = %v", affected)
	}
	affected, err = Affected(dir, "HEAD~4", "HEAD~3", resolve)
	if err != nil || len(affected) != 0 {
		t.Errorf("a docs-only change affects %v (%v)", affected, err)
	}
}
