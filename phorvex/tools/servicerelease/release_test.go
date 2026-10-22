package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every value the release writes is a value its chart reads, in a file the
// environment's Applications read.
func TestReleasesPinValuesTheChartsRead(t *testing.T) {
	root := repoRoot(t)
	for _, c := range Components {
		if c.Repository != "phorvex/"+c.Name {
			t.Errorf("%s: repository %q, want phorvex/%s", c.Name, c.Repository, c.Name)
		}
		chart := c.Chart
		if chart == "" {
			chart = "phorvex/charts/phorvex" // the console's
		}
		raw, err := os.ReadFile(filepath.Join(root, chart, "values.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var values map[string]any
		if err := yaml.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		node := values
		for _, key := range c.Deploy.Path {
			next, ok := node[key].(map[string]any)
			if !ok {
				t.Fatalf("%s: %s has no %v", c.Name, chart, c.Deploy.Path)
			}
			node = next
		}
		for _, key := range []string{c.Deploy.Repository, c.Deploy.Tag, c.Deploy.Digest, c.Deploy.Source} {
			if _, ok := node[key]; key != "" && !ok {
				t.Errorf("%s: %s has no %v.%s", c.Name, chart, c.Deploy.Path, key)
			}
		}
		for _, env := range []string{"staging"} {
			if _, err := os.Stat(filepath.Join(root, "deploy/environments", env, c.Deploy.File+".yaml")); err != nil {
				t.Errorf("%s: %v", c.Name, err)
			}
		}
	}
}

func TestPrepareWritesVersionsAndChangelogs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "brain.md"), []byte("# brain changelog\n\n## 0.1.0 (2026-10-01)\n\nFirst release.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plans := []Plan{
		{Component: "manager", Tag: "manager-v0.5.0", Current: "0.5.0", Bump: "none", Commits: []Commit{}},
		{Component: "brain", Tag: "brain-v0.1.0", Current: "0.1.0", Next: "0.2.0", Bump: "minor",
			Commits: []Commit{{SHA: "0123456789abcdef", Subject: "feat(brain): faster decisions", Bump: "minor"}}},
		{Component: "sensor", Next: "0.1.0", Bump: "patch", Commits: []Commit{{SHA: "fedcba9876543210", Subject: "fix(sensor): x", Bump: "patch"}}},
	}
	title, body, err := Prepare(dir, "2026-10-21", plans)
	if err != nil {
		t.Fatal(err)
	}
	if title != "release: brain 0.2.0, sensor 0.1.0" {
		t.Errorf("title = %q", title)
	}
	if !strings.Contains(body, "### brain 0.2.0 (2026-10-21)") || !strings.Contains(body, "- feat(brain): faster decisions (01234567)") {
		t.Errorf("body = %q", body)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, VersionsFile))
	var versions map[string]string
	if err := json.Unmarshal(raw, &versions); err != nil || versions["brain"] != "0.2.0" || versions["sensor"] != "0.1.0" || len(versions) != 2 {
		t.Errorf("versions = %s (%v)", raw, err)
	}
	brain, _ := os.ReadFile(filepath.Join(dir, "brain.md"))
	want := "# brain changelog\n\n## 0.2.0 (2026-10-21)\n\n- feat(brain): faster decisions (01234567)\n\n## 0.1.0 (2026-10-01)\n\nFirst release.\n"
	if string(brain) != want {
		t.Errorf("brain.md =\n%s\nwant\n%s", brain, want)
	}
	sensor, _ := os.ReadFile(filepath.Join(dir, "sensor.md"))
	if string(sensor) != "# sensor changelog\n\n## 0.1.0 (2026-10-21)\n\nFirst release, from 1 commit.\n\n" {
		t.Errorf("sensor.md = %q", sensor)
	}
	long := Plan{Component: "brain", Tag: "brain-v0.2.0", Current: "0.2.0", Next: "0.2.1", Bump: "patch"}
	for i := range maxListed + 5 {
		long.Commits = append(long.Commits, Commit{SHA: fmt.Sprintf("%016x", i), Subject: "fix: n", Bump: "patch"})
	}
	if section := changelogSection(long, "2026-10-22"); strings.Count(section, "\n- ") != maxListed+1 || !strings.HasSuffix(section, "- and 5 more\n") {
		t.Errorf("a long section lists %d entries:\n%s", strings.Count(section, "\n- "), section)
	}
	if _, _, err := Prepare(t.TempDir(), "2026-10-21", plans[:1]); err != ErrNothingToRelease {
		t.Errorf("an unchanged plan prepared a release: %v", err)
	}
}

func TestPendingReleasesSkipsTaggedVersions(t *testing.T) {
	dir := t.TempDir()
	gitIn := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	gitIn("init", "-q", "-b", "main")
	gitIn("commit", "-q", "--allow-empty", "-m", "start")
	gitIn("tag", "brain-v0.2.0")
	release := filepath.Join(dir, "release")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, VersionsFile), []byte(`{"brain": "0.2.0", "sensor": "0.1.0", "console": "0.5.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pending, err := PendingReleases(dir, release, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pending {
		names = append(names, p.Component+" "+p.Version+" "+strings.Join(p.BuildArgs, ","))
	}
	if want := []string{"sensor 0.1.0 SERVICE=sensor", "console 0.5.1 CONSOLE_VERSION=0.5.1"}; !slices.Equal(names, want) {
		t.Errorf("pending = %v, want %v", names, want)
	}
}

func TestDeployPinsTheImageAndKeepsTheFile(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, "deploy/environments/staging")
	if err := os.MkdirAll(env, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"brain.yaml":   "# The brain chart's own staging values.\n{}\n",
		"manager.yaml": "# The manager chart's values.\nphorvex:\n  leaderElect: true # kept\n",
	} {
		if err := os.WriteFile(filepath.Join(env, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	repo := "registry.example/phorvex/"
	if err := Deploy(root, "staging", "brain", repo+"brain", "0.2.0", digest, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := Deploy(root, "staging", "manager", repo+"manager", "0.5.1", digest, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := Deploy(root, "staging", "console", repo+"console", "0.5.2", digest, "def"); err != nil {
		t.Fatal(err)
	}
	brain, _ := os.ReadFile(filepath.Join(env, "brain.yaml"))
	want := "# The brain chart's own staging values.\nimage:\n  repository: \"registry.example/phorvex/brain\"\n  tag: \"0.2.0\"\n  digest: \"" + digest + "\"\n"
	if string(brain) != want {
		t.Errorf("brain.yaml =\n%s\nwant\n%s", brain, want)
	}
	manager, _ := os.ReadFile(filepath.Join(env, "manager.yaml"))
	var values struct {
		Phorvex struct {
			LeaderElect bool `yaml:"leaderElect"`
			Image       map[string]string
			Console     struct{ Image map[string]string }
		}
	}
	if err := yaml.Unmarshal(manager, &values); err != nil {
		t.Fatal(err)
	}
	if !values.Phorvex.LeaderElect || values.Phorvex.Image["tag"] != "0.5.1" || values.Phorvex.Image["releaseSourceSHA"] != "abc" ||
		values.Phorvex.Console.Image["tag"] != "0.5.2" || values.Phorvex.Console.Image["releaseDigest"] != digest {
		t.Errorf("manager.yaml =\n%s", manager)
	}
	if !strings.Contains(string(manager), "# The manager chart's values.") || !strings.Contains(string(manager), "# kept") {
		t.Errorf("comments lost:\n%s", manager)
	}
	for _, bad := range [][]string{{"brain", "0.2.0", "latest"}, {"brain", "v0.2.0", digest}, {"nobody", "0.1.0", digest}} {
		if err := Deploy(root, "staging", bad[0], repo+bad[0], bad[1], bad[2], ""); err == nil {
			t.Errorf("Deploy%v accepted", bad)
		}
	}
}

func TestPullRequestsUpsert(t *testing.T) {
	var calls []string
	var open []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		switch {
		case r.Method == "GET":
			_ = json.NewEncoder(w).Encode(open)
		case r.Method == "POST":
			open = []map[string]any{{"number": 7, "html_url": "https://example.invalid/pull/7"}}
			_ = json.NewEncoder(w).Encode(open[0])
		case r.Method == "PATCH":
			_ = json.NewEncoder(w).Encode(open[0])
		}
	}))
	defer srv.Close()
	g := PullRequests{API: srv.URL, Repository: "PhorvexSecurity/operator-refactored", Token: "token"}
	for range 2 {
		u, err := g.Upsert("release/next", "main", "release: brain 0.2.0", "body")
		if err != nil || u != "https://example.invalid/pull/7" {
			t.Fatalf("Upsert = %q, %v", u, err)
		}
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		http.Error(w, `{"message":"GitHub Actions is not permitted to create or approve pull requests."}`, http.StatusForbidden)
	}))
	defer refusing.Close()
	if _, err := (PullRequests{API: refusing.URL, Repository: g.Repository, Token: "token"}).Upsert("release/next", "main", "t", "b"); !errors.Is(err, ErrCreateRefused) {
		t.Errorf("a refused create = %v, want ErrCreateRefused", err)
	}
	if err := g.Dispatch("pr-validation.yml", "release/next"); err != nil {
		t.Fatal(err)
	}
	if last := calls[len(calls)-1]; last != `POST /repos/PhorvexSecurity/operator-refactored/actions/workflows/pr-validation.yml/dispatches {"ref":"release/next"}` {
		t.Errorf("dispatch = %q", last)
	}
	calls = calls[:len(calls)-1]
	if len(calls) != 4 || !strings.HasPrefix(calls[0], "GET /repos/PhorvexSecurity/operator-refactored/pulls?base=main&head=PhorvexSecurity%3Arelease%2Fnext&state=open") ||
		!strings.HasPrefix(calls[1], "POST /repos/PhorvexSecurity/operator-refactored/pulls ") || !strings.HasPrefix(calls[3], "PATCH /repos/PhorvexSecurity/operator-refactored/pulls/7 ") {
		t.Errorf("calls = %q", calls)
	}
}
