// Package auditguard exercises CEL from the actual shipped Helm chart. It has no
// runtime admission implementation: Kubernetes evaluates the rendered policy.
package auditguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type object = map[string]any

func repository(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate chart test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(here), "../../.."))
}

func render(t *testing.T, release, namespace, version, chart string, flags ...string) ([]object, error) {
	t.Helper()
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Fatal("auditguard requires real Helm rendering: install Helm 3.16.4 or set HELM_BIN")
		}
	}
	args := []string{"template", release, chart, "--namespace", namespace, "--kube-version", version}
	args = append(args, flags...)
	cmd := exec.Command(helm, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("helm template: %w: %s", err, stderr.String())
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var docs []object
	for {
		var doc object
		if err := decoder.Decode(&doc); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(doc) != 0 {
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

func enabled(t *testing.T, release, namespace string, extra ...string) []object {
	t.Helper()
	args := []string{"--set", "phorvex.audit.enabled=true,phorvex.audit.volumeGuard.enabled=true"}
	args = append(args, extra...)
	docs, err := render(t, release, namespace, "1.30.0", filepath.Join(repository(t), "phorvex/charts/phorvex"), args...)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

func resource(t *testing.T, docs []object, kind string, guardOnly bool) object {
	t.Helper()
	var found []object
	for _, doc := range docs {
		if doc["kind"] != kind {
			continue
		}
		if guardOnly {
			labels, _ := doc["metadata"].(object)["labels"].(object)
			if labels["phorvex.ai/policy"] != "audit-volume-guard" {
				continue
			}
		}
		found = append(found, doc)
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s (guard=%v), got %d", kind, guardOnly, len(found))
	}
	return found[0]
}

func clone(t *testing.T, source object) object {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var out object
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func deploymentPod(t *testing.T, docs []object) object {
	t.Helper()
	var matches []object
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		labels, _ := d["spec"].(object)["template"].(object)["metadata"].(object)["labels"].(object)
		if labels["app.kubernetes.io/component"] == "manager" {
			matches = append(matches, d)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("want exactly one manager Deployment, got %d", len(matches))
	}
	d := matches[0]
	p := clone(t, d["spec"].(object)["template"].(object))
	m := p["metadata"].(object)
	m["namespace"] = d["metadata"].(object)["namespace"]
	m["name"] = d["metadata"].(object)["name"].(string) + "-65dff7c6c5-fixture"
	m["ownerReferences"] = []any{object{"apiVersion": "apps/v1", "kind": "ReplicaSet", "controller": true,
		"name": d["metadata"].(object)["name"].(string) + "-65dff7c6c5", "uid": "existing-replicaset-uid"}}
	p["apiVersion"], p["kind"] = "v1", "Pod"
	return p
}

func firstOwner(p object) object {
	return p["metadata"].(object)["ownerReferences"].([]any)[0].(object)
}

func evaluate(t *testing.T, expression string, p object, namespace string) bool {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType), cel.Variable("request", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile shipped CEL: %v\n%s", issues.Err(), expression)
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := program.Eval(object{"object": p, "request": object{"namespace": namespace}})
	if err != nil {
		t.Fatalf("CEL must return a bounded boolean, not an evaluation error: %v\n%s", err, expression)
	}
	value, ok := result.Value().(bool)
	if !ok {
		t.Fatalf("CEL returned non-boolean %T", result.Value())
	}
	return value
}

func admission(t *testing.T, policy object, p object, namespace string) (matched bool, rejected []int) {
	t.Helper()
	spec := policy["spec"].(object)
	for _, condition := range spec["matchConditions"].([]any) {
		if !evaluate(t, condition.(object)["expression"].(string), p, namespace) {
			return false, nil
		}
	}
	for index, validation := range spec["validations"].([]any) {
		if !evaluate(t, validation.(object)["expression"].(string), p, namespace) {
			rejected = append(rejected, index)
		}
	}
	return true, rejected
}

// The audit volume guard is opt-in. M-94's SecurityEvent creator-identity policy is NOT:
// it is the only thing that makes a phorvex.ai/creator-identity annotation trustworthy while
// the mutating stamp endpoint is down, so the default chart (which ships a non-empty
// trustedDetectors allowlist) must install it. That policy requires Kubernetes >=1.30, which
// is why the default render is exercised at 1.30 rather than 1.29 here.
func TestAuditVolumeGuardDisabledByDefault(t *testing.T) {
	docs, err := render(t, "portable", "anywhere", "1.30.0", filepath.Join(repository(t), "phorvex/charts/phorvex"))
	if err != nil {
		t.Fatal(err)
	}
	identityPolicies := 0
	for _, doc := range docs {
		if !strings.HasPrefix(doc["kind"].(string), "ValidatingAdmissionPolicy") {
			continue
		}
		labels, _ := doc["metadata"].(object)["labels"].(object)
		if labels["phorvex.ai/policy"] == "securityevent-identity" {
			identityPolicies++
			continue
		}
		t.Fatalf("default chart must not install admission guard %v", doc["metadata"].(object)["name"])
	}
	if identityPolicies != 2 {
		t.Fatalf("default chart must install the M-94 identity policy AND its binding, got %d", identityPolicies)
	}
	p := resource(t, docs, "Deployment", false)["spec"].(object)["template"].(object)["spec"].(object)
	if selector, present := p["nodeSelector"]; present && len(selector.(object)) > 0 {
		t.Fatal("generic chart must not pin the EKS system pool")
	}
}

func TestAuditVolumeGuardRequiresStableAPIAndPersistentAudit(t *testing.T) {
	for _, tc := range []struct{ name, version, settings, message string }{
		{"old-kubernetes", "1.29.9", "phorvex.audit.enabled=true", "Kubernetes >=1.30"},
		{"audit-disabled", "1.30.0", "phorvex.audit.enabled=false", "audit.enabled=true"},
		{"persistence-disabled", "1.30.0", "phorvex.audit.enabled=true,phorvex.audit.persistence.enabled=false", "audit.persistence.enabled=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := render(t, "p", "n", tc.version, filepath.Join(repository(t), "phorvex/charts/phorvex"),
				"--set", "phorvex.audit.volumeGuard.enabled=true,"+tc.settings)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected explicit incompatible configuration rejection %q; got %v", tc.message, err)
			}
		})
	}
}

func TestAuditVolumeGuardNarrowManifestAndOrdering(t *testing.T) {
	docs := enabled(t, "phorvex", "phorvex-system")
	p, b := resource(t, docs, "ValidatingAdmissionPolicy", true), resource(t, docs, "ValidatingAdmissionPolicyBinding", true)
	pm, bm := p["metadata"].(object), b["metadata"].(object)
	ps, bs := p["spec"].(object), b["spec"].(object)
	if pm["name"] != bm["name"] || bs["policyName"] != pm["name"] || len(pm["name"].(string)) > 63 {
		t.Fatal("policy and binding names must match and remain bounded")
	}
	if pm["annotations"].(object)["argocd.argoproj.io/sync-wave"] != "-2" || bm["annotations"].(object)["argocd.argoproj.io/sync-wave"] != "-1" {
		t.Fatal("policy must precede binding, and binding must precede Deployment")
	}
	if ps["failurePolicy"] != "Fail" || !reflect.DeepEqual(bs["validationActions"], []any{"Deny"}) {
		t.Fatal("guard must fail closed and deny")
	}
	rules := ps["matchConstraints"].(object)
	wantRules := []any{object{"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE"}, "resources": []any{"pods"}, "scope": "Namespaced"}}
	if rules["matchPolicy"] != "Exact" || !reflect.DeepEqual(rules["resourceRules"], wantRules) {
		t.Fatalf("guard must match only core/v1 Pod CREATE, never UPDATE or subresources: %#v", rules)
	}
}

func TestConsoleHistoryCapacityUsesChartFirstCompatibleEnvironment(t *testing.T) {
	docs := enabled(t, "phorvex", "phorvex-system", "--set", "phorvex.console.enabled=true,phorvex.console.auditTransport.serverSecretName=server,phorvex.console.auditTransport.clientSecretName=client,phorvex.console.auditTransport.serverDNSName=server.test,phorvex.console.auditTransport.clientDNSName=client.test")
	var consoleContainer object
	for _, doc := range docs {
		if doc["kind"] != "Deployment" {
			continue
		}
		spec := doc["spec"].(object)["template"].(object)["spec"].(object)
		for _, raw := range spec["containers"].([]any) {
			container := raw.(object)
			if container["name"] != "console" {
				continue
			}
			environment, _ := container["env"].([]any)
			for _, rawEnv := range environment {
				if rawEnv.(object)["name"] == "PHORVEX_CONSOLE_HISTORY_MAX_BYTES" {
					consoleContainer = container
				}
			}
		}
	}
	if consoleContainer == nil {
		t.Fatal("rendered console container unavailable")
	}
	for _, raw := range consoleContainer["args"].([]any) {
		if strings.HasPrefix(raw.(string), "-history-") {
			t.Fatalf("chart-first rollout sent a new history CLI flag to an older image: %q", raw)
		}
	}
	environment := map[string]string{}
	for _, raw := range consoleContainer["env"].([]any) {
		entry := raw.(object)
		name, _ := entry["name"].(string)
		value, _ := entry["value"].(string)
		environment[name] = value
	}
	if environment["PHORVEX_CONSOLE_HISTORY_MAX_BYTES"] != "2147483648" ||
		environment["PHORVEX_CONSOLE_HISTORY_MIN_FREE_BYTES"] != "536870912" {
		t.Fatalf("rendered history capacity environment = %#v", environment)
	}
}

func TestAuditVolumeGuardCEL(t *testing.T) {
	docs := enabled(t, "phorvex", "phorvex-system", "--set", "phorvex.console.enabled=true,phorvex.console.auditTransport.serverSecretName=server,phorvex.console.auditTransport.clientSecretName=client,phorvex.console.auditTransport.serverDNSName=server.test,phorvex.console.auditTransport.clientDNSName=client.test")
	policy, original := resource(t, docs, "ValidatingAdmissionPolicy", true), deploymentPod(t, docs)
	if matched, denied := admission(t, policy, original, "phorvex-system"); !matched || len(denied) != 0 {
		t.Fatalf("real rendered Deployment Pod must pass: matched=%v rejected=%v", matched, denied)
	}
	for _, tc := range []struct {
		name     string
		mutate   func(object)
		rejected int
	}{
		{"no-owner", func(p object) { delete(p["metadata"].(object), "ownerReferences") }, 0},
		{"empty-owner-list", func(p object) { p["metadata"].(object)["ownerReferences"] = []any{} }, 0},
		{"missing-controller", func(p object) { delete(firstOwner(p), "controller") }, 0},
		{"non-controller", func(p object) { firstOwner(p)["controller"] = false }, 0},
		{"wrong-api", func(p object) { firstOwner(p)["apiVersion"] = "batch/v1" }, 0},
		{"missing-api", func(p object) { delete(firstOwner(p), "apiVersion") }, 0},
		{"job-owner", func(p object) { firstOwner(p)["kind"] = "Job" }, 0},
		{"missing-kind", func(p object) { delete(firstOwner(p), "kind") }, 0},
		{"empty-uid", func(p object) { firstOwner(p)["uid"] = "" }, 0},
		{"missing-uid", func(p object) { delete(firstOwner(p), "uid") }, 0},
		{"wrong-prefix", func(p object) { firstOwner(p)["name"] = "other-deployment-65dff7c6c5" }, 0},
		{"prefix-needs-suffix", func(p object) { firstOwner(p)["name"] = "phorvex-phorvex-" }, 0},
		{"missing-owner-name", func(p object) { delete(firstOwner(p), "name") }, 0},
		{"wrong-sa", func(p object) { p["spec"].(object)["serviceAccountName"] = "default" }, 1},
		{"missing-sa", func(p object) { delete(p["spec"].(object), "serviceAccountName") }, 1},
		{"wrong-app-label", func(p object) { p["metadata"].(object)["labels"].(object)["app.kubernetes.io/name"] = "helper" }, 2},
		{"missing-app-label", func(p object) { delete(p["metadata"].(object)["labels"].(object), "app.kubernetes.io/name") }, 2},
		{"wrong-instance", func(p object) { p["metadata"].(object)["labels"].(object)["app.kubernetes.io/instance"] = "other" }, 2},
		{"missing-instance", func(p object) { delete(p["metadata"].(object)["labels"].(object), "app.kubernetes.io/instance") }, 2},
		{"missing-labels", func(p object) { delete(p["metadata"].(object), "labels") }, 2},
		{"no-manager", func(p object) {
			p["spec"].(object)["containers"] = []any{object{"name": "scan", "image": "python:3.11-slim"}}
		}, 3},
		{"no-containers", func(p object) { delete(p["spec"].(object), "containers") }, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := clone(t, original)
			tc.mutate(p)
			matched, denied := admission(t, policy, p, "phorvex-system")
			if !matched || !reflect.DeepEqual(denied, []int{tc.rejected}) {
				t.Fatalf("isolated predicate must reject: matched=%v rejected=%v want=[%d]", matched, denied, tc.rejected)
			}
		})
	}
	for _, readonly := range []bool{false, true} {
		t.Run(fmt.Sprintf("observed-sleeper-readonly-%v", readonly), func(t *testing.T) {
			p := object{"metadata": object{"name": "audit-scan-k3-l3", "labels": clone(t, original["metadata"].(object)["labels"].(object))},
				"spec": object{"serviceAccountName": "default", "containers": []any{object{"name": "scan", "image": "python:3.11-slim", "command": []any{"sleep", "172800"}}},
					"volumes": []any{object{"name": "audit", "persistentVolumeClaim": object{"claimName": "phorvex-phorvex-audit", "readOnly": readonly}}}}}
			matched, denied := admission(t, policy, p, "phorvex-system")
			if !matched || !reflect.DeepEqual(denied, []int{0, 1, 3}) {
				t.Fatalf("copied labels/readOnly must not admit sleeper: matched=%v rejected=%v", matched, denied)
			}
		})
	}
	t.Run("missing-metadata-is-bounded-denial", func(t *testing.T) {
		p := clone(t, original)
		delete(p, "metadata")
		matched, denied := admission(t, policy, p, "phorvex-system")
		if !matched || !reflect.DeepEqual(denied, []int{0, 2}) {
			t.Fatalf("missing metadata must reject without CEL errors: matched=%v rejected=%v", matched, denied)
		}
	})
	// This guard is intentionally NOT controller authentication: the same Pod
	// shape can be forged by a privileged creator. Keep that limit test-visible.
	t.Run("forged-controller-shape-is-not-authenticated", func(t *testing.T) {
		p := clone(t, original)
		firstOwner(p)["uid"] = "forged-nonempty-uid"
		_, denied := admission(t, policy, p, "phorvex-system")
		if len(denied) != 0 {
			t.Fatal("test documents shape-only semantics, not an identity proof")
		}
	})
	for _, tc := range []struct {
		name, namespace string
		mutate          func(object)
	}{
		{"other-namespace", "unrelated", func(object) {}},
		{"other-pvc", "phorvex-system", func(p object) {
			p["spec"].(object)["volumes"] = []any{object{"persistentVolumeClaim": object{"claimName": "unrelated"}}}
		}},
		{"no-volumes", "phorvex-system", func(p object) { delete(p["spec"].(object), "volumes") }},
		{"emptydir-only", "phorvex-system", func(p object) { p["spec"].(object)["volumes"] = []any{object{"name": "cache", "emptyDir": object{}}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := clone(t, original)
			delete(p["metadata"].(object), "ownerReferences")
			tc.mutate(p)
			if matched, denied := admission(t, policy, p, tc.namespace); matched || len(denied) != 0 {
				t.Fatalf("unrelated Pod must be unaffected: matched=%v rejected=%v", matched, denied)
			}
		})
	}
}

func TestAuditVolumeGuardCustomReleaseNamespaceAndOperatorOnly(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range []struct{ release, namespace string }{
		{"custom-release", "custom-namespace"},
		{"custom-release", "custom-namespace-other"},
		{"same-long-release-prefix-aaaaaaaa", "same-long-namespace-prefix-aaaa"},
		{"same-long-release-prefix-bbbbbbbb", "same-long-namespace-prefix-bbbb"},
	} {
		t.Run(tc.release+"-"+tc.namespace, func(t *testing.T) {
			docs := enabled(t, tc.release, tc.namespace, "--set", "phorvex.console.enabled=false")
			policy, pod := resource(t, docs, "ValidatingAdmissionPolicy", true), deploymentPod(t, docs)
			name := policy["metadata"].(object)["name"].(string)
			if seen[name] || len(name) > 63 {
				t.Fatalf("cluster policy name collision or oversized name: %s", name)
			}
			seen[name] = true
			if len(pod["spec"].(object)["containers"].([]any)) != 1 {
				t.Fatal("fixture must be actual operator-only deployment")
			}
			if matched, denied := admission(t, policy, pod, tc.namespace); !matched || len(denied) != 0 {
				t.Fatalf("custom release's derived service account and operator-only Pod must pass: matched=%v rejected=%v", matched, denied)
			}
		})
	}
}

func TestAuditVolumeGuardEKSUsesVendoredChartAndSystemPool(t *testing.T) {
	root := repository(t)
	docs, err := render(t, "phorvex", "phorvex-system", "1.30.0", filepath.Join(root, "deploy/helm/phorvex-stack"),
		"-f", filepath.Join(root, "deploy/helm/phorvex-stack/values.yaml"), "-f", filepath.Join(root, "deploy/helm/phorvex-stack/values-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	policy := resource(t, docs, "ValidatingAdmissionPolicy", true)
	resource(t, docs, "ValidatingAdmissionPolicyBinding", true)
	pod := deploymentPod(t, docs)
	if matched, denied := admission(t, policy, pod, "phorvex-system"); !matched || len(denied) != 0 {
		t.Fatalf("real EKS vendored Deployment must pass: matched=%v rejected=%v", matched, denied)
	}
	var manager object
	for _, candidate := range docs {
		if candidate["kind"] == "Deployment" {
			labels, _ := candidate["spec"].(object)["template"].(object)["metadata"].(object)["labels"].(object)
			if labels["app.kubernetes.io/component"] == "manager" {
				manager = candidate
			}
		}
	}
	if manager == nil {
		t.Fatal("manager Deployment missing")
	}
	d := manager["spec"].(object)
	spec := pod["spec"].(object)
	if !reflect.DeepEqual(spec["nodeSelector"], object{"node-type": "system"}) {
		t.Fatalf("EKS operator/console must select system pool: %#v", spec["nodeSelector"])
	}
	wantToleration := object{"key": "CriticalAddonsOnly", "operator": "Equal", "value": "true", "effect": "NoSchedule"}
	found := false
	for _, value := range spec["tolerations"].([]any) {
		found = found || reflect.DeepEqual(value, wantToleration)
	}
	if !found || d["strategy"].(object)["type"] != "Recreate" || d["replicas"] != float64(1) {
		t.Fatal("preserve CriticalAddonsOnly toleration, Recreate and one replica")
	}
	var auditPVC, consolePVC object
	for _, candidate := range docs {
		if candidate["kind"] != "PersistentVolumeClaim" {
			continue
		}
		switch candidate["metadata"].(object)["name"] {
		case "phorvex-phorvex-audit":
			auditPVC = candidate
		case "phorvex-phorvex-console-state":
			consolePVC = candidate
		}
	}
	if auditPVC == nil || !reflect.DeepEqual(auditPVC["spec"].(object)["accessModes"], []any{"ReadWriteOnce"}) {
		t.Fatal("audit PVC name and RWO access mode must remain unchanged")
	}
	if consolePVC == nil || consolePVC["metadata"].(object)["name"] == auditPVC["metadata"].(object)["name"] {
		t.Fatal("console state must use a separate PVC from the protected manager audit")
	}
}
