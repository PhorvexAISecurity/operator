/*
 * Phorvex — M-21 R1-1: no entrypoint may act on an unresolvable actuator selector.
 *
 * This is a CLI-LEVEL regression: it builds the real operator binary and runs it against
 * an isolated recording fake Kubernetes API, so it asserts what the PROCESS does, not what
 * a parser returns. That distinction is the finding: validation lived only inside the
 * runner's checked constructor, and --integration-emit / --native-demo / an empty-namespace
 * --scan never reach it. With PHORVEX_ACTUATOR=phoenixx the binary previously exited 0 and
 * POSTed both an AdaptiveMovingTargetDefense and a SecurityEvent.
 *
 * No real cluster is used and nothing outside the test's own temporary directories is touched.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const amtdGroup = "amtd.r6security.com"

// recordingAPI is a fake API server that serves just enough discovery for the Phoenix
// adapter and RECORDS every mutating call, so "did this process mutate?" is answerable.
type recordingAPI struct {
	mu       sync.Mutex
	mutating []string
}

func (a *recordingAPI) record(kind string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mutating = append(a.mutating, kind)
}

func (a *recordingAPI) calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.mutating...)
}

func (a *recordingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gv := amtdGroup + "/v1beta1"
	version := map[string]any{"groupVersion": gv, "version": "v1beta1"}
	group := map[string]any{"kind": "APIGroup", "apiVersion": "v1", "name": amtdGroup,
		"versions": []any{version}, "preferredVersion": version}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.Method != http.MethodGet {
		var obj map[string]any
		_ = json.NewDecoder(r.Body).Decode(&obj)
		kind, _ := obj["kind"].(string)
		a.record(r.Method + " " + kind)
		meta, _ := obj["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
			obj["metadata"] = meta
		}
		meta["uid"], meta["resourceVersion"] = "fake-uid", "1"
		if name, _ := meta["name"].(string); name == "" {
			gen, _ := meta["generateName"].(string)
			meta["name"] = gen + "probe"
		}
		reply(http.StatusCreated, obj)
		return
	}
	switch path := strings.Split(r.URL.Path, "?")[0]; path {
	case "/api":
		reply(200, map[string]any{"kind": "APIVersions", "apiVersion": "v1", "versions": []string{"v1"}})
	case "/api/v1":
		resource := func(name, kind string, namespaced bool) map[string]any {
			return map[string]any{"name": name, "singularName": "", "namespaced": namespaced,
				"kind": kind, "verbs": []string{"get", "list"}}
		}
		reply(200, map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "v1", "resources": []any{
			resource("namespaces", "Namespace", false), resource("pods", "Pod", true),
		}})
	case "/api/v1/namespaces/ns":
		reply(200, map[string]any{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": "ns", "uid": "namespace-uid", "resourceVersion": "1"},
		})
	case "/api/v1/namespaces/ns/pods/p1":
		reply(200, map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"namespace": "ns", "name": "p1", "uid": "pod-uid", "resourceVersion": "1"},
		})
	case "/apis":
		reply(200, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{group}})
	case "/apis/" + amtdGroup:
		reply(200, group)
	case "/apis/" + gv:
		resource := func(name, kind string, namespaced bool) map[string]any {
			return map[string]any{"name": name, "singularName": "", "namespaced": namespaced,
				"kind": kind, "verbs": []string{"get", "list", "create", "update"}}
		}
		reply(200, map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": gv,
			"resources": []any{
				resource("adaptivemovingtargetdefenses", "AdaptiveMovingTargetDefense", true),
				resource("securityevents", "SecurityEvent", false),
			}})
	default:
		reply(404, map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure",
			"reason": "NotFound", "code": 404})
	}
}

// buildOperator compiles the real binary under test.
func buildOperator(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "operator")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build operator: %v\n%s", err, out)
	}
	return bin
}

func writeKubeconfig(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig.json")
	cfg := map[string]any{
		"apiVersion": "v1", "kind": "Config", "current-context": "fake",
		"clusters": []any{map[string]any{"name": "fake", "cluster": map[string]any{"server": server}}},
		"users":    []any{map[string]any{"name": "fake", "user": map[string]any{}}},
		"contexts": []any{map[string]any{"name": "fake",
			"context": map[string]any{"cluster": "fake", "user": "fake"}}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type runResult struct {
	exit   int
	stdout string
	stderr string
}

func runOperator(t *testing.T, bin, kubeconfig, selector string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig, "PHORVEX_ACTUATOR="+selector)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("operator %v did not exit within the timeout; an invalid selector must fail fast", args)
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run operator %v: %v", args, err)
	}
	return runResult{exit: code, stdout: out.String(), stderr: errb.String()}
}

// TestOneShotEntrypointsRejectInvalidSelectorBeforeAnyMutation is the R1-1 regression.
// Every actual entrypoint must refuse an unresolvable selector BEFORE it touches the API.
func TestOneShotEntrypointsRejectInvalidSelectorBeforeAnyMutation(t *testing.T) {
	api := &recordingAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	bin := buildOperator(t)
	kubeconfig := writeKubeconfig(t, server.URL)

	entrypoints := []struct {
		name string
		args []string
	}{
		{"integration-emit", []string{"--integration-emit", "--emit-namespace=ns", "--emit-pod=p1", "--emit-matchlabels=app=demo"}},
		{"native-demo", []string{"--native-demo", "--native-demo-namespace=phorvex-actuator-demo"}},
		{"scan", []string{"--scan", "--scan-namespace=ns"}},
		{"scan-empty-namespace", []string{"--scan"}},
		{"ablation", []string{"--ablation", "--ablation-namespace=ns"}},
		{"epss-feed", []string{"--epss-feed"}},
		{"controller", nil},
	}
	for _, tc := range entrypoints {
		t.Run(tc.name, func(t *testing.T) {
			before := len(api.calls())
			got := runOperator(t, bin, kubeconfig, "phoenixx", tc.args...)
			if got.exit == 0 {
				t.Fatalf("%s exited 0 on an unresolvable selector\nstdout: %s\nstderr: %s", tc.name, got.stdout, got.stderr)
			}
			if after := api.calls(); len(after) != before {
				t.Fatalf("%s performed %d mutating API call(s) on an unresolvable selector: %v",
					tc.name, len(after)-before, after[before:])
			}
			// The message must be actionable and must name the variable, not a generic failure.
			for _, want := range []string{"PHORVEX_ACTUATOR", "phoenixx", "phoenix", "native", "hybrid"} {
				if !strings.Contains(got.stderr, want) {
					t.Fatalf("%s error must mention %q; got: %s", tc.name, want, got.stderr)
				}
			}
		})
	}
}

// TestIntegrationEmitStillEmitsOnValidConfiguration is the positive control that makes the
// test above meaningful: the same fixture, the same binary, a VALID selector — the
// documented Seam-1 behavior is preserved and both resources really are created.
func TestIntegrationEmitStillEmitsOnValidConfiguration(t *testing.T) {
	api := &recordingAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	bin := buildOperator(t)
	kubeconfig := writeKubeconfig(t, server.URL)

	// Both the explicit default and an omitted selector must keep working.
	for _, selector := range []string{"phoenix", ""} {
		name := selector
		if name == "" {
			name = "omitted-uses-default"
		}
		t.Run(name, func(t *testing.T) {
			before := len(api.calls())
			got := runOperator(t, bin, kubeconfig, selector,
				"--integration-emit", "--emit-namespace=ns", "--emit-pod=p1", "--emit-matchlabels=app=demo")
			if got.exit != 0 {
				t.Fatalf("valid selector %q must still emit; exit=%d\nstdout: %s\nstderr: %s",
					selector, got.exit, got.stdout, got.stderr)
			}
			created := api.calls()[before:]
			for _, want := range []string{"POST AdaptiveMovingTargetDefense", "POST SecurityEvent"} {
				if !containsCall(created, want) {
					t.Fatalf("valid selector %q must still create %s; recorded %v", selector, want, created)
				}
			}
		})
	}
}

// TestResolvedBackendIsLoggedAtStartup: every valid branch is observable, including the
// default one that used to resolve in total silence — and it is observable on an entrypoint
// that constructs no runner, which is where the logging used to be.
func TestResolvedBackendIsLoggedAtStartup(t *testing.T) {
	api := &recordingAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	bin := buildOperator(t)
	kubeconfig := writeKubeconfig(t, server.URL)

	for _, tc := range []struct{ selector, wantBackend, wantSource string }{
		{"", "phoenix", "default"},
		{"native", "native", "explicit"},
		{"hybrid", "hybrid", "explicit"},
		{"phoenix", "phoenix", "explicit"},
	} {
		name := tc.selector
		if name == "" {
			name = "omitted"
		}
		t.Run(name, func(t *testing.T) {
			// --integration-emit is used because the resolution log must be emitted BEFORE
			// any entrypoint dispatches, including ones that build no runner at all.
			got := runOperator(t, bin, kubeconfig, tc.selector,
				"--integration-emit", "--emit-namespace=ns", "--emit-pod=p1", "--emit-matchlabels=app=demo")
			logs := got.stderr + got.stdout
			if !strings.Contains(logs, tc.wantBackend) || !strings.Contains(logs, tc.wantSource) {
				t.Fatalf("startup must log backend %q and source %q; got: %s",
					tc.wantBackend, tc.wantSource, lastLines(logs, 12))
			}
		})
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return fmt.Sprintf("%s", strings.Join(lines, "\n"))
}
