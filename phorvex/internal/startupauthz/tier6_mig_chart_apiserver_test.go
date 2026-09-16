package startupauthz

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
)

func renderTier6MIGChart(t *testing.T, release, controlNamespace, managerSA, operatorNamespace, tenantNamespace, agentNamespace, agentDaemonSet, agentSA string) []byte {
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
	chart := filepath.Join(filepath.Dir(source), "..", "..", "charts", "phorvex")
	digest := "sha256:" + strings.Repeat("a", 64)
	args := []string{"template", release, chart, "--namespace", controlNamespace,
		"--set-string", "phorvex.serviceAccountName=" + managerSA,
		"--set-string", "phorvex.operatorNamespace=" + operatorNamespace,
		"--set-string", "phorvex.actuatorNamespaces[0]=" + tenantNamespace,
		"--set", "phorvex.mig.nodeExec.enabled=true",
		"--set", "phorvex.mig.nodeExec.exclusiveMaintenance=true",
		"--set-string", "phorvex.mig.nodeExec.namespace=" + agentNamespace,
		"--set-string", "phorvex.mig.nodeExec.daemonSetName=" + agentDaemonSet,
		"--set-string", "phorvex.mig.nodeExec.serviceAccountName=" + agentSA,
		"--set-string", "phorvex.mig.nodeExec.gpuImage.repository=vendor.example/gpu-tools",
		"--set-string", "phorvex.mig.nodeExec.gpuImage.digest=" + digest,
		"--set-string", "phorvex.mig.nodeExec.gpuCommand[0]=/gpu-agent",
	}
	cmd := exec.Command(helm, args...)
	var rendered, diagnostics bytes.Buffer
	cmd.Stdout = &rendered
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template: %v\n%s", err, diagnostics.String())
	}
	return rendered.Bytes()
}

func TestTier6RenderedCustomManagerMIGAgentBootAuthorization(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated API server")
	}
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly, CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})

	scheme := kruntime.NewScheme()
	for _, add := range []func(*kruntime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	for _, name := range []string{"tier6-control", "tier6-operator", "tier6-tenant", "tier6-gpu", "tier6-gpu-wrong"} {
		err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}

	const (
		managerSA      = "tier6-custom-manager"
		agentNamespace = "tier6-gpu"
		agentDaemonSet = "tier6-mig-agent"
	)
	rendered := renderTier6MIGChart(t, "tier6", "tier6-control", managerSA, "tier6-operator", "tier6-tenant", agentNamespace, agentDaemonSet, "tier6-agent")
	installRenderedIdentity(t, ctx, admin, rendered, false)
	managerReader, managerReviews, err := bootIdentity(cfg, scheme, "tier6-control", managerSA)
	if err != nil {
		t.Fatal(err)
	}
	active := policy("tier6-tenant", "mig", v1alpha1.ModeActive, v1alpha1.ActionMIGRebind)
	if err := admin.Create(ctx, active); err != nil {
		t.Fatal(err)
	}

	checkUntil := func(config Config, wantError string) error {
		t.Helper()
		var last error
		err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
			_, last = Check(ctx, managerReader, managerReviews.AuthorizationV1().SelfSubjectAccessReviews(), config)
			if wantError == "" {
				return last == nil, nil
			}
			return last != nil && strings.Contains(last.Error(), wantError), nil
		})
		if err != nil {
			t.Fatalf("startup authorization did not converge to error containing %q: last=%v poll=%v", wantError, last, err)
		}
		return last
	}
	base := Config{
		Backend: actuator.BackendNative, OperatorNamespace: "tier6-operator", Timeout: 2 * time.Second,
		MIGAgent: &MIGAgentAccess{Namespace: agentNamespace, DaemonSet: agentDaemonSet},
	}
	checkUntil(base, "")

	roleKey := client.ObjectKey{Namespace: agentNamespace, Name: "tier6-phorvex-mig-agent-client"}
	agentRole := &rbacv1.Role{}
	if err := admin.Get(ctx, roleKey, agentRole); err != nil {
		t.Fatal(err)
	}
	originalRules := append([]rbacv1.PolicyRule(nil), agentRole.Rules...)
	agentRole.Rules = nil
	for _, rule := range originalRules {
		if len(rule.Resources) == 1 && rule.Resources[0] == "pods/exec" {
			continue
		}
		agentRole.Rules = append(agentRole.Rules, rule)
	}
	if err := admin.Update(ctx, agentRole); err != nil {
		t.Fatal(err)
	}
	if denied := checkUntil(base, "pods/exec"); denied == nil || !strings.Contains(denied.Error(), "denied") {
		t.Fatalf("missing pods/exec was not denied: %v", denied)
	}
	if err := admin.Get(ctx, roleKey, agentRole); err != nil {
		t.Fatal(err)
	}
	agentRole.Rules = originalRules
	if err := admin.Update(ctx, agentRole); err != nil {
		t.Fatal(err)
	}
	checkUntil(base, "")

	wrongName := base
	wrongName.MIGAgent = &MIGAgentAccess{Namespace: agentNamespace, DaemonSet: "other-agent"}
	if denied := checkUntil(wrongName, "daemonsets"); denied == nil || !strings.Contains(denied.Error(), "denied") {
		t.Fatalf("wrong DaemonSet name was not denied: %v", denied)
	}
	wrongScope := base
	wrongScope.MIGAgent = &MIGAgentAccess{Namespace: "tier6-gpu-wrong", DaemonSet: agentDaemonSet}
	if denied := checkUntil(wrongScope, `namespace="tier6-gpu-wrong"`); denied == nil || !strings.Contains(denied.Error(), "denied") {
		t.Fatalf("wrong agent namespace was not denied: %v", denied)
	}
}
