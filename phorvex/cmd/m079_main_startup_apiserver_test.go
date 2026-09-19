package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

const m079MainValues = `
phorvex:
  actuator: native
  operatorNamespace: operator
  actuatorNamespaces: [tenant]
  audit:
    enabled: false
  servingSecurity:
    mode: legacy-plaintext
`

const m079MainMIGValues = m079MainValues + `
  mig:
    profiles:
      content: |
        {"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}
    nodeExec:
      enabled: true
      exclusiveMaintenance: true
      namespace: gpu-system
      daemonSetName: phorvex-mig-agent
      serviceAccountName: phorvex-mig-agent
      gpuContainer: gpu-tools
      helperContainer: allocation-helper
      gpuImage:
        repository: vendor.example/gpu-tools
        digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      gpuCommand: ["/gpu-agent"]
      allocationHelperPath: /phorvex-mig-allocation-helper
      podResourcesMountPath: /var/lib/kubelet/pod-resources
      execTimeout: 5s
      allocationReadTimeout: 3s
      allocationReleaseTimeout: 45s
`

// TestM079RenderedMainStartupSelectsMIGAuthorization launches the actual manager
// entrypoint against an isolated RBAC API server. It proves that the rendered
// --mig-node-exec flag selects the optional startup authorization and that the full
// rendered policy reaches production WireRemoteNodeExec after that authorization.
// It does not open an SPDY stream or execute a GPU command.
func TestM079RenderedMainStartupSelectsMIGAuthorization(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires pinned local envtest API-server binaries")
	}
	defaultRender := m079RenderMainChart(t, m079MainValues)
	enabledRender := m079RenderMainChart(t, m079MainMIGValues)
	defaultArgs, _, defaultSA := m079MainRenderInputs(t, defaultRender)
	enabledArgs, profile, enabledSA := m079MainRenderInputs(t, enabledRender)
	if defaultSA != enabledSA || enabledSA == "" {
		t.Fatalf("rendered manager identities differ: default=%q enabled=%q", defaultSA, enabledSA)
	}
	if m079FindArg(defaultArgs, "--mig-node-exec") != "" {
		t.Fatalf("default rendered manager unexpectedly enables MIG node exec: %v", defaultArgs)
	}
	if got := m079FindArg(enabledArgs, "--mig-node-exec"); got != "true" {
		t.Fatalf("enabled rendered --mig-node-exec=%q", got)
	}
	if got := m079FindArg(enabledArgs, "--mig-profiles-file"); got != "/etc/phorvex-mig/profiles.json" || profile == "" {
		t.Fatalf("enabled rendered profile path=%q contentBytes=%d", got, len(profile))
	}

	localOnly := false
	environment := &envtest.Environment{UseExistingCluster: &localOnly, CRDDirectoryPaths: []string{"../config/crd/bases"}}
	environment.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = environment.Stop() })
	scheme := kruntime.NewScheme()
	for _, add := range []func(*kruntime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for _, namespace := range []string{"control", "operator", "tenant", "gpu-system"} {
		err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	m079InstallMainIdentity(t, ctx, admin, enabledRender)
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "m079-main"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode:     v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "model"}},
			Budget: v1alpha1.BudgetSpec{
				TickInterval:           metav1.Duration{Duration: 20 * time.Second},
				AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
				ProactiveFloor:         metav1.Duration{Duration: time.Hour},
			},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionMIGRebind}},
		},
	}
	if err := admin.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}

	restricted := rest.CopyConfig(config)
	restricted.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:control:" + enabledSA,
		Groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:control"},
	}
	kubeconfig := m079WriteMainKubeconfig(t, config, restricted.Impersonate)
	bin := buildOperator(t)
	profilePath := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	enabledArgs = m079ReplaceArg(enabledArgs, "--mig-profiles-file", profilePath)

	role := m079MainExecRole(t, ctx, admin)
	originalRules := append([]rbacv1.PolicyRule(nil), role.Rules...)
	role.Rules = m079WithoutMainExec(role.Rules)
	if err := admin.Update(ctx, role); err != nil {
		t.Fatal(err)
	}
	m079WaitMainExecReview(t, ctx, restricted, false)

	defaultOutput := m079RunMainUntil(t, bin, kubeconfig, defaultArgs, "startup authorization preflight passed")
	if strings.Contains(defaultOutput, "MIG agent execution") || strings.Contains(defaultOutput, "trusted MIG node-exec transport wired") {
		t.Fatalf("default startup selected MIG authorization or transport:\n%s", defaultOutput)
	}

	denied := m079RunMainToExit(t, bin, kubeconfig, enabledArgs)
	for _, want := range []string{"startup authorization preflight failed", "MIG agent execution", "pods/exec", "gpu-system"} {
		if !strings.Contains(denied, want) {
			t.Fatalf("enabled startup refusal does not contain %q:\n%s", want, denied)
		}
	}

	if err := admin.Get(ctx, client.ObjectKeyFromObject(role), role); err != nil {
		t.Fatal(err)
	}
	role.Rules = originalRules
	if err := admin.Update(ctx, role); err != nil {
		t.Fatal(err)
	}
	m079WaitMainExecReview(t, ctx, restricted, true)
	enabledOutput := m079RunMainUntil(t, bin, kubeconfig, enabledArgs, "trusted MIG node-exec transport wired")
	for _, want := range []string{"startup authorization preflight passed", "trusted MIG node-exec transport wired", "gpu-system", "phorvex-mig-agent"} {
		if !strings.Contains(enabledOutput, want) {
			t.Fatalf("enabled startup does not contain %q:\n%s", want, enabledOutput)
		}
	}
}

func m079RenderMainChart(t *testing.T, values string) []byte {
	t.Helper()
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("helm binary not found")
		}
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate chart")
	}
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	chart := filepath.Join(filepath.Dir(source), "..", "charts", "phorvex")
	cmd := exec.Command(helm, "template", "m079-main", chart, "--namespace", "control", "--values", valuesPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return out
}

func m079MainRenderInputs(t *testing.T, rendered []byte) (args []string, profile, serviceAccount string) {
	t.Helper()
	decoder := kyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		metadata, _ := raw["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		switch raw["kind"] {
		case "Deployment":
			spec := raw["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			serviceAccount, _ = spec["serviceAccountName"].(string)
			for _, entry := range spec["containers"].([]any) {
				container := entry.(map[string]any)
				if container["name"] != "manager" {
					continue
				}
				for _, arg := range container["args"].([]any) {
					args = append(args, arg.(string))
				}
			}
		case "ConfigMap":
			if strings.HasSuffix(name, "-mig-profiles") {
				profile = raw["data"].(map[string]any)["profiles.json"].(string)
			}
		}
	}
	if len(args) == 0 || serviceAccount == "" {
		t.Fatalf("rendered manager inputs incomplete: args=%d serviceAccount=%q", len(args), serviceAccount)
	}
	return args, profile, serviceAccount
}

func m079InstallMainIdentity(t *testing.T, ctx context.Context, admin client.Client, rendered []byte) {
	t.Helper()
	decoder := kyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	var identities, roles, bindings []client.Object
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var object client.Object
		switch raw["kind"] {
		case "ServiceAccount":
			object = &corev1.ServiceAccount{}
			identities = append(identities, object)
		case "ClusterRole":
			object = &rbacv1.ClusterRole{}
			roles = append(roles, object)
		case "Role":
			object = &rbacv1.Role{}
			roles = append(roles, object)
		case "ClusterRoleBinding":
			object = &rbacv1.ClusterRoleBinding{}
			bindings = append(bindings, object)
		case "RoleBinding":
			object = &rbacv1.RoleBinding{}
			bindings = append(bindings, object)
		default:
			continue
		}
		if err := json.Unmarshal(encoded, object); err != nil {
			t.Fatal(err)
		}
	}
	for _, objects := range [][]client.Object{identities, roles, bindings} {
		for _, object := range objects {
			if err := admin.Create(ctx, object); err != nil {
				t.Fatalf("create rendered %T %s/%s: %v", object, object.GetNamespace(), object.GetName(), err)
			}
		}
	}
}

func m079MainExecRole(t *testing.T, ctx context.Context, admin client.Client) *rbacv1.Role {
	t.Helper()
	var roles rbacv1.RoleList
	if err := admin.List(ctx, &roles, client.InNamespace("gpu-system")); err != nil {
		t.Fatal(err)
	}
	for i := range roles.Items {
		for _, rule := range roles.Items[i].Rules {
			if len(rule.Resources) == 1 && rule.Resources[0] == "pods/exec" {
				return &roles.Items[i]
			}
		}
	}
	t.Fatal("rendered gpu-system pods/exec Role missing")
	return nil
}

func m079WithoutMainExec(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	result := make([]rbacv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Resources) == 1 && rule.Resources[0] == "pods/exec" {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func m079WaitMainExecReview(t *testing.T, ctx context.Context, config *rest.Config, want bool) {
	t.Helper()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		review, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: "gpu-system", Verb: "create", Resource: "pods", Subresource: "exec",
		}}}, metav1.CreateOptions{})
		return err == nil && review.Status.Allowed == want, nil
	})
	if err != nil {
		t.Fatalf("pods/exec authorization did not become allowed=%v: %v", want, err)
	}
}

func m079WriteMainKubeconfig(t *testing.T, config *rest.Config, impersonate rest.ImpersonationConfig) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"local": {Server: config.Host, CertificateAuthorityData: config.CAData}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"manager": {
			ClientCertificateData: config.CertData, ClientKeyData: config.KeyData,
			Impersonate: impersonate.UserName, ImpersonateGroups: impersonate.Groups,
		}},
		Contexts:       map[string]*clientcmdapi.Context{"local": {Cluster: "local", AuthInfo: "manager"}},
		CurrentContext: "local",
	}
	if err := clientcmd.WriteToFile(kubeconfig, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func m079FindArg(args []string, key string) string {
	for _, arg := range args {
		if name, value, ok := strings.Cut(arg, "="); ok && name == key {
			return value
		}
	}
	return ""
}

func m079ReplaceArg(args []string, key, value string) []string {
	result := append([]string(nil), args...)
	for i, arg := range result {
		if name, _, ok := strings.Cut(arg, "="); ok && name == key {
			result[i] = key + "=" + value
			return result
		}
	}
	return append(result, key+"="+value)
}

type m079LockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *m079LockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *m079LockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func m079MainCommand(bin, kubeconfig string, args []string, output *m079LockedBuffer) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig, "PHORVEX_ACTUATOR=native")
	cmd.Stdout, cmd.Stderr = output, output
	return cmd
}

func m079RunMainToExit(t *testing.T, bin, kubeconfig string, args []string) string {
	t.Helper()
	var output m079LockedBuffer
	cmd := m079MainCommand(bin, kubeconfig, args, &output)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("manager unexpectedly exited successfully:\n%s", output.String())
		}
		return output.String()
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("manager did not reach expected startup refusal:\n%s", output.String())
	}
	return ""
}

func m079RunMainUntil(t *testing.T, bin, kubeconfig string, args []string, marker string) string {
	t.Helper()
	var output m079LockedBuffer
	cmd := m079MainCommand(bin, kubeconfig, args, &output)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			got := output.String()
			if strings.Contains(got, marker) {
				return got
			}
			t.Fatalf("manager exited before %q: %v\n%s", marker, err, got)
		case <-ticker.C:
			if got := output.String(); strings.Contains(got, marker) {
				_ = cmd.Process.Kill()
				<-done
				return output.String()
			}
		case <-deadline.C:
			_ = cmd.Process.Kill()
			<-done
			t.Fatalf("manager did not reach %q:\n%s", marker, output.String())
		}
	}
}
