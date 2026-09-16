package startupauthz

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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
)

func renderBootChart(t *testing.T, release, namespace, managerSA, operatorNS, tenant string) []byte {
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
	args := []string{"template", release, chart, "--namespace", namespace,
		"--set-string", "phorvex.serviceAccountName=" + managerSA,
		"--set-string", "phorvex.operatorNamespace=" + operatorNS}
	if tenant != "" {
		args = append(args, "--set-string", "phorvex.actuatorNamespaces[0]="+tenant)
	}
	cmd := exec.Command(helm, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return out
}

func installRenderedIdentity(t *testing.T, ctx context.Context, admin client.Client, rendered []byte, omitJournal bool) string {
	t.Helper()
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	var serviceAccount string
	var identities, roles, bindings []client.Object
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(doc) == 0 {
			continue
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		metadata, _ := doc["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if omitJournal && strings.HasSuffix(name, "-operation-journal") {
			continue
		}
		switch doc["kind"] {
		case "ServiceAccount":
			var object corev1.ServiceAccount
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(object.Name, "console") {
				serviceAccount = object.Name
			}
			identities = append(identities, &object)
		case "ClusterRole":
			var object rbacv1.ClusterRole
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			roles = append(roles, &object)
		case "Role":
			var object rbacv1.Role
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			roles = append(roles, &object)
		case "ClusterRoleBinding":
			var object rbacv1.ClusterRoleBinding
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, &object)
		case "RoleBinding":
			var object rbacv1.RoleBinding
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, &object)
		}
	}
	for _, set := range [][]client.Object{identities, roles, bindings} {
		for _, object := range set {
			if err := admin.Create(ctx, object); err != nil {
				t.Fatalf("create rendered %T %s/%s: %v", object, object.GetNamespace(), object.GetName(), err)
			}
		}
	}
	return serviceAccount
}

func bootIdentity(cfg *rest.Config, scheme *kruntime.Scheme, namespace, name string) (client.Client, *kubernetes.Clientset, error) {
	restricted := rest.CopyConfig(cfg)
	restricted.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + namespace + ":" + name,
		Groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + namespace},
	}
	reader, err := client.New(restricted, client.Options{Scheme: scheme})
	if err != nil {
		return nil, nil, err
	}
	reviews, err := kubernetes.NewForConfig(restricted)
	return reader, reviews, err
}

func TestRenderedManagerIdentityDrivesBootAdmission(t *testing.T) {
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
	for _, add := range []func(*kruntime.Scheme) error{corev1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme, v1alpha1.AddToScheme} {
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
	createNamespace := func(name string) {
		t.Helper()
		err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	createPolicy := func(namespace, name string, action v1alpha1.ActionType) *v1alpha1.PhorvexPolicy {
		t.Helper()
		object := policy(namespace, name, v1alpha1.ModeActive, action)
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	deletePolicy := func(object *v1alpha1.PhorvexPolicy) {
		t.Helper()
		if err := admin.Delete(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	waitBoot := func(reader client.Reader, reviews *kubernetes.Clientset, config Config, wantAllow bool, deniedContains string) error {
		t.Helper()
		var last error
		err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
			_, last = Check(ctx, reader, reviews.AuthorizationV1().SelfSubjectAccessReviews(), config)
			if wantAllow {
				return last == nil, nil
			}
			return last != nil && strings.Contains(last.Error(), deniedContains), nil
		})
		if err != nil {
			t.Fatalf("boot verdict did not become allow=%v: last=%v poll=%v", wantAllow, last, err)
		}
		return last
	}

	for _, namespace := range []string{"control", "operator", "tenant"} {
		createNamespace(namespace)
	}
	rendered := renderBootChart(t, "configured", "control", "custom-manager", "operator", "tenant")
	if managerSA := installRenderedIdentity(t, ctx, admin, rendered, false); managerSA != "custom-manager" {
		t.Fatalf("rendered manager ServiceAccount = %q", managerSA)
	}
	managerReader, managerReviews, err := bootIdentity(cfg, scheme, "control", "custom-manager")
	if err != nil {
		t.Fatal(err)
	}
	configured := createPolicy("tenant", "configured", v1alpha1.ActionQuarantine)
	waitBoot(managerReader, managerReviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"}, true, "")
	configured.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionRotate}
	if err := admin.Update(ctx, configured); err != nil {
		t.Fatal(err)
	}
	waitBoot(managerReader, managerReviews, Config{Backend: actuator.BackendHybrid, OperatorNamespace: "operator"}, true, "")
	deletePolicy(configured)

	for _, namespace := range []string{"control-no-journal", "operator-no-journal", "tenant-no-journal"} {
		createNamespace(namespace)
	}
	withoutJournal := renderBootChart(t, "no-journal", "control-no-journal", "manager-no-journal", "operator-no-journal", "tenant-no-journal")
	installRenderedIdentity(t, ctx, admin, withoutJournal, true)
	missingReader, missingReviews, err := bootIdentity(cfg, scheme, "control-no-journal", "manager-no-journal")
	if err != nil {
		t.Fatal(err)
	}
	missing := createPolicy("tenant-no-journal", "missing", v1alpha1.ActionQuarantine)
	if bootErr := waitBoot(missingReader, missingReviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator-no-journal"}, false, "/configmaps"); bootErr == nil || !strings.Contains(bootErr.Error(), "/configmaps") {
		t.Fatalf("missing journal denial = %v", bootErr)
	}
	deletePolicy(missing)

	for _, namespace := range []string{"control-default", "operator-default", "tenant-default"} {
		createNamespace(namespace)
	}
	defaultRender := renderBootChart(t, "default-scope", "control-default", "manager-default", "operator-default", "")
	installRenderedIdentity(t, ctx, admin, defaultRender, false)
	defaultReader, defaultReviews, err := bootIdentity(cfg, scheme, "control-default", "manager-default")
	if err != nil {
		t.Fatal(err)
	}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-default", Name: "target", Labels: map[string]string{"state": "before"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "example.invalid/fixture"}}}}
	if err := admin.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	denied := createPolicy("tenant-default", "denied", v1alpha1.ActionQuarantine)
	if bootErr := waitBoot(defaultReader, defaultReviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator-default"}, false, "/pods:update"); bootErr == nil || !strings.Contains(bootErr.Error(), "denied") {
		t.Fatalf("default tenant boot denial = %v", bootErr)
	}
	unchanged := &corev1.Pod{}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(target), unchanged); err != nil {
		t.Fatal(err)
	}
	if unchanged.Labels["state"] != "before" {
		t.Fatalf("target mutated before boot refusal: %+v", unchanged.Labels)
	}
	var policies networkingv1.NetworkPolicyList
	if err := admin.List(ctx, &policies, client.InNamespace("tenant-default")); err != nil || len(policies.Items) != 0 {
		t.Fatalf("network policy mutation preceded boot refusal: count=%d err=%v", len(policies.Items), err)
	}
	deletePolicy(denied)
}
