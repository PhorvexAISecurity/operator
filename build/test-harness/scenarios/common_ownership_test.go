package scenarios

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

type ownershipGuard struct{}

func (ownershipGuard) AssertMutationAllowed(string) error { return nil }

type ownershipLogger struct{ commands []string }

func (*ownershipLogger) Logf(string, ...any)  {}
func (l *ownershipLogger) Command(s string)   { l.commands = append(l.commands, s) }
func (l *ownershipLogger) Commands() []string { return l.commands }
func (*ownershipLogger) RawLogPath() string   { return "" }

func ownershipEnv(t *testing.T, objects ...runtime.Object) (*core.Env, *k8sfake.Clientset) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID("namespace-1")}}
	all := append([]runtime.Object{ns}, objects...)
	kube := k8sfake.NewSimpleClientset(all...)
	env := &core.Env{
		Kube:   kube,
		Config: config.TargetConfig{Namespace: "sandbox", Context: "test", OwnedAck: true},
		Log:    &ownershipLogger{}, Guard: ownershipGuard{}, ScenarioName: "ownership-case", Trial: 7,
	}
	if err := env.EnsureNamespace(t.Context()); err != nil {
		t.Fatal(err)
	}
	return env, kube
}

func assignCreateUIDs(kube *k8sfake.Clientset) {
	var n int
	kube.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		n++
		pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
		pod.UID = types.UID("created-pod-" + string(rune('a'+n)))
		pod.Status.Phase = corev1.PodRunning
		return false, nil, nil
	})
}

func TestDeployTargetRefusesForeignPredecessorWithoutMutation(t *testing.T) {
	foreign := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "victim", Namespace: "sandbox", UID: types.UID("foreign"), Finalizers: []string{"foreign.example/hold"},
	}}
	env, kube := ownershipEnv(t, foreign)
	before := foreign.DeepCopy()
	mutations := 0
	kube.PrependReactor("delete", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		mutations++
		return true, nil, errors.New("unexpected delete")
	})
	kube.PrependReactor("patch", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		mutations++
		return true, nil, errors.New("unexpected patch")
	})
	if _, err := deployTarget(t.Context(), env, "victim", "", nil); err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("deployTarget error=%v, want adoption refusal", err)
	}
	after, err := kube.CoreV1().Pods("sandbox").Get(t.Context(), "victim", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mutations != 0 || !reflect.DeepEqual(before, after) {
		t.Fatalf("foreign pod mutated: requests=%d before=%#v after=%#v", mutations, before, after)
	}
}

func TestDeployTargetDoesNotUseStaleSameAppPodForReadiness(t *testing.T) {
	env, kube := ownershipEnv(t, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "stale", Namespace: "sandbox", UID: types.UID("stale"), Labels: map[string]string{"app": "victim"},
	}, Status: corev1.PodStatus{Phase: corev1.PodRunning}})
	kube.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
		pod.UID = types.UID("fresh")
		pod.Status.Phase = corev1.PodPending
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if pod, err := deployTarget(ctx, env, "victim", "", nil); err == nil || pod != nil {
		t.Fatalf("deployTarget returned stale readiness: pod=%v err=%v", pod, err)
	}
}

func TestDeployTargetUnexpectedReadAndAmbiguousCreateDoNotAdoptOrRetry(t *testing.T) {
	t.Run("unexpected get", func(t *testing.T) {
		env, kube := ownershipEnv(t)
		creates := 0
		kube.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("read failed")
		})
		kube.PrependReactor("create", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			creates++
			return true, nil, nil
		})
		if _, err := deployPlain(t.Context(), env, "victim"); err == nil || creates != 0 {
			t.Fatalf("error=%v creates=%d, want read refusal before create", err, creates)
		}
	})
	t.Run("ambiguous create", func(t *testing.T) {
		env, kube := ownershipEnv(t)
		creates := 0
		kube.PrependReactor("create", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			creates++
			return true, nil, context.DeadlineExceeded
		})
		if _, err := deployPlain(t.Context(), env, "victim"); err == nil || creates != 1 {
			t.Fatalf("error=%v creates=%d, want one ambiguous create and refusal", err, creates)
		}
	})
}

func TestEnsureSAWithRBACCollisionRollsBackExactPartialCreate(t *testing.T) {
	foreignRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "attack-role", Namespace: "sandbox", UID: types.UID("foreign-role")}}
	env, kube := ownershipEnv(t, foreignRole)
	kube.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		sa := action.(ktesting.CreateAction).GetObject().(*corev1.ServiceAccount)
		sa.UID = types.UID("created-sa")
		return false, nil, nil
	})
	var deletedUID types.UID
	kube.PrependReactor("delete", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletedUID = *action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions.UID
		return false, nil, nil
	})
	if err := ensureSAWithRBAC(t.Context(), env, "attack"); err == nil || !strings.Contains(err.Error(), "refusing to adopt existing roles") {
		t.Fatalf("error=%v, want role collision refusal", err)
	}
	if deletedUID != types.UID("created-sa") {
		t.Fatalf("rollback UID=%q, want created-sa", deletedUID)
	}
	if _, err := kube.RbacV1().Roles("sandbox").Get(t.Context(), "attack-role", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign role changed: %v", err)
	}
	if _, err := kube.RbacV1().RoleBindings("sandbox").Get(t.Context(), "attack-rb", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("rolebinding unexpectedly created: %v", err)
	}
}

func TestEnsureSAWithRBACFinalizerHeldRollbackRetainsAuthority(t *testing.T) {
	oldTimeout := rbacRollbackTimeout
	rbacRollbackTimeout = 40 * time.Millisecond
	t.Cleanup(func() { rbacRollbackTimeout = oldTimeout })

	foreignRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "attack-role", Namespace: "sandbox", UID: types.UID("foreign-role")}}
	env, kube := ownershipEnv(t, foreignRole)
	kube.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		sa := action.(ktesting.CreateAction).GetObject().(*corev1.ServiceAccount)
		sa.UID = types.UID("created-sa")
		sa.Finalizers = []string{"test.example/hold"}
		return false, nil, nil
	})
	var deletedUID types.UID
	kube.PrependReactor("delete", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletedUID = *action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions.UID
		// Simulate an accepted deletion whose finalizer keeps the object present.
		return true, nil, nil
	})
	err := ensureSAWithRBAC(t.Context(), env, "attack")
	if err == nil || !strings.Contains(err.Error(), "remains") || !strings.Contains(err.Error(), "test.example/hold") {
		t.Fatalf("error=%v, want finalizer-held rollback refusal", err)
	}
	if deletedUID != types.UID("created-sa") {
		t.Fatalf("rollback UID=%q, want created-sa", deletedUID)
	}
	if uid, ok := env.CreatedUID("serviceaccounts", "attack"); !ok || uid != types.UID("created-sa") {
		t.Fatalf("retained authority=%q,%v, want created-sa,true", uid, ok)
	}
	sa, getErr := kube.CoreV1().ServiceAccounts("sandbox").Get(t.Context(), "attack", metav1.GetOptions{})
	if getErr != nil || sa.UID != types.UID("created-sa") || !reflect.DeepEqual(sa.Finalizers, []string{"test.example/hold"}) {
		t.Fatalf("held serviceaccount changed: sa=%#v err=%v", sa, getErr)
	}
}

func TestEnsureSAWithRBACRefusesRollbackAfterNamespaceReplacement(t *testing.T) {
	foreignRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "attack-role", Namespace: "sandbox", UID: types.UID("foreign-role")}}
	env, kube := ownershipEnv(t, foreignRole)
	kube.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		sa := action.(ktesting.CreateAction).GetObject().(*corev1.ServiceAccount)
		sa.UID = types.UID("created-sa")
		return false, nil, nil
	})
	replaced := false
	kube.PrependReactor("get", "roles", func(ktesting.Action) (bool, runtime.Object, error) {
		if !replaced {
			replaced = true
			resource := corev1.SchemeGroupVersion.WithResource("namespaces")
			if err := kube.Tracker().Delete(resource, "", "sandbox"); err != nil {
				t.Fatal(err)
			}
			if err := kube.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID("replacement-namespace")}}); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	deletes := 0
	kube.PrependReactor("delete", "serviceaccounts", func(ktesting.Action) (bool, runtime.Object, error) {
		deletes++
		return false, nil, nil
	})
	err := ensureSAWithRBAC(t.Context(), env, "attack")
	if err == nil || !strings.Contains(err.Error(), "refusing rollback delete") || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("error=%v, want replacement-namespace rollback refusal", err)
	}
	if deletes != 0 {
		t.Fatalf("rollback issued %d delete requests in a replacement namespace", deletes)
	}
	if uid, ok := env.CreatedUID("serviceaccounts", "attack"); !ok || uid != types.UID("created-sa") {
		t.Fatalf("retained authority=%q,%v, want created-sa,true", uid, ok)
	}
}

func ownedTestPod(env *core.Env, name, app string, uid types.UID) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: env.Config.Namespace, UID: uid, Labels: env.OwnedLabels(map[string]string{"app": app}),
	}}
}

func TestTeardownByAppUsesRecordedUIDAndPreservesForeignMatches(t *testing.T) {
	env, kube := ownershipEnv(t)
	owned := ownedTestPod(env, "owned", "victim", types.UID("owned-uid"))
	foreign := ownedTestPod(env, "foreign", "victim", types.UID("foreign-uid"))
	if _, err := kube.CoreV1().Pods("sandbox").Create(t.Context(), owned, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Pods("sandbox").Create(t.Context(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := env.RecordCreatedUID("pods", owned.Name, owned.UID); err != nil {
		t.Fatal(err)
	}
	var deletes []string
	kube.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		d := action.(ktesting.DeleteAction)
		deletes = append(deletes, d.GetName()+"/"+string(*d.GetDeleteOptions().Preconditions.UID))
		return false, nil, nil
	})
	err := teardownByApp(t.Context(), env, "victim")
	if err == nil || !strings.Contains(err.Error(), "refusing unrecorded pod foreign") {
		t.Fatalf("error=%v, want foreign refusal", err)
	}
	if !reflect.DeepEqual(deletes, []string{"owned/owned-uid"}) {
		t.Fatalf("deletes=%v", deletes)
	}
	if _, err := kube.CoreV1().Pods("sandbox").Get(t.Context(), "foreign", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign pod deleted: %v", err)
	}
}

func TestTeardownByAppUIDConflictLeavesReplacement(t *testing.T) {
	env, kube := ownershipEnv(t)
	pod := ownedTestPod(env, "victim", "victim", types.UID("original"))
	if _, err := kube.CoreV1().Pods("sandbox").Create(t.Context(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := env.RecordCreatedUID("pods", pod.Name, pod.UID); err != nil {
		t.Fatal(err)
	}
	kube.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		d := action.(ktesting.DeleteAction)
		if got := *d.GetDeleteOptions().Preconditions.UID; got != types.UID("original") {
			t.Fatalf("delete precondition UID=%q", got)
		}
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, "victim", errors.New("UID precondition failed"))
	})
	if err := teardownByApp(t.Context(), env, "victim"); err == nil || !apierrors.IsConflict(errors.Unwrap(err)) && !strings.Contains(err.Error(), "UID precondition failed") {
		t.Fatalf("error=%v, want UID conflict", err)
	}
	if _, err := kube.CoreV1().Pods("sandbox").Get(t.Context(), "victim", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod was deleted despite conflict: %v", err)
	}
}

func TestTeardownByAppAllowsFreshIdentityAfterVerifiedCleanup(t *testing.T) {
	env, kube := ownershipEnv(t)
	for _, uid := range []types.UID{"first", "second"} {
		pod := ownedTestPod(env, "victim", "victim", uid)
		if _, err := kube.CoreV1().Pods("sandbox").Create(t.Context(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := env.RecordCreatedUID("pods", pod.Name, pod.UID); err != nil {
			t.Fatal(err)
		}
		if err := teardownByApp(t.Context(), env, "victim"); err != nil {
			t.Fatalf("teardown UID %s: %v", uid, err)
		}
	}
}

func TestCreateFreshPodThenTeardownUsesCreateResponseAuthority(t *testing.T) {
	env, kube := ownershipEnv(t)
	kube.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
		pod.UID = types.UID("created-victim")
		pod.Status.Phase = corev1.PodRunning
		return false, nil, nil
	})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "victim", Namespace: "sandbox", Labels: env.OwnedLabels(map[string]string{"app": "victim"}),
	}}
	created, err := createFreshPod(t.Context(), env, pod, "ownership control")
	if err != nil {
		t.Fatal(err)
	}
	if created.UID != types.UID("created-victim") {
		t.Fatalf("created UID=%q", created.UID)
	}
	var deletedUID types.UID
	kube.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletedUID = *action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions.UID
		return false, nil, nil
	})
	if err := teardownByApp(t.Context(), env, "victim"); err != nil {
		t.Fatal(err)
	}
	if deletedUID != created.UID {
		t.Fatalf("teardown UID=%q, want %q", deletedUID, created.UID)
	}
	if _, ok := env.CreatedUID("pods", "victim"); ok {
		t.Fatal("teardown retained authority after verified absence")
	}
}

func TestTargetOwnershipActualAPIPreservesForeignFinalizerAndEnforcesUID(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Skip("KUBEBUILDER_ASSETS is required for the isolated API control")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("KUBEBUILDER_ASSETS must be absolute")
	}
	localOnly := false
	testAPI := &envtest.Environment{UseExistingCluster: &localOnly, BinaryAssetsDirectory: assets}
	restCfg, err := testAPI.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = testAPI.Stop() })
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ns, err := kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ownership-actual-api"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: ns.Name}, Log: &ownershipLogger{}, Guard: ownershipGuard{}, ScenarioName: "ownership-case", Trial: 1}
	if err := env.EnsureNamespace(ctx); err != nil {
		t.Fatal(err)
	}
	foreign, err := kube.CoreV1().Pods(ns.Name).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "victim", Namespace: ns.Name, Finalizers: []string{"foreign.example/hold"},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wrong := types.UID("wrong-uid")
	if err := kube.CoreV1().Pods(ns.Name).Delete(ctx, foreign.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &wrong}}); !apierrors.IsConflict(err) {
		t.Fatalf("wrong UID delete error=%v, want Conflict", err)
	}
	before := foreign.DeepCopy()
	if _, err := deployTarget(ctx, env, foreign.Name, "", nil); err == nil {
		t.Fatal("deployTarget adopted foreign actual-API pod")
	}
	after, err := kube.CoreV1().Pods(ns.Name).Get(ctx, foreign.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.UID != after.UID || !reflect.DeepEqual(before.Finalizers, after.Finalizers) || after.DeletionTimestamp != nil {
		t.Fatalf("foreign actual-API pod changed: before=%#v after=%#v", before, after)
	}
	// Test-only retirement after the assertions; production code never strips it.
	after.Finalizers = nil
	if _, err := kube.CoreV1().Pods(ns.Name).Update(ctx, after, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	_ = kube.CoreV1().Pods(ns.Name).Delete(ctx, foreign.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	_ = kube.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
}

func TestDeployTargetRefusesConcurrentAlreadyExistsWithoutAdoption(t *testing.T) {
	env, kube := ownershipEnv(t)
	creates := 0
	readsAfterCreate := 0
	kube.PrependReactor("create", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		creates++
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "pods"}, "victim")
	})
	kube.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		if creates > 0 {
			readsAfterCreate++
		}
		return false, nil, nil
	})
	if _, err := deployTarget(t.Context(), env, "victim", "", nil); err == nil || !apierrors.IsAlreadyExists(errors.Unwrap(err)) {
		t.Fatalf("error=%v, want AlreadyExists refusal", err)
	}
	if creates != 1 || readsAfterCreate != 0 {
		t.Fatalf("creates=%d readsAfterCreate=%d; ambiguous create was retried or adopted", creates, readsAfterCreate)
	}
}

func TestEnsureSAWithRBACRefusesEveryCollision(t *testing.T) {
	cases := []struct {
		name    string
		objects []runtime.Object
		creates int
		deletes int
	}{
		{"serviceaccount", []runtime.Object{&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "attack", Namespace: "sandbox", UID: "foreign-sa"}}}, 0, 0},
		{"rolebinding", []runtime.Object{&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "attack-rb", Namespace: "sandbox", UID: "foreign-rb"}}}, 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, kube := ownershipEnv(t, tc.objects...)
			creates, deletes := 0, 0
			kube.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				creates++
				obj := action.(ktesting.CreateAction).GetObject()
				switch v := obj.(type) {
				case *corev1.ServiceAccount:
					v.UID = "created-sa"
				case *rbacv1.Role:
					v.UID = "created-role"
				case *rbacv1.RoleBinding:
					v.UID = "created-rb"
				}
				return false, nil, nil
			})
			kube.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				deletes++
				if action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions == nil || action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions.UID == nil {
					t.Fatal("rollback delete lacked UID precondition")
				}
				return false, nil, nil
			})
			if err := ensureSAWithRBAC(t.Context(), env, "attack"); err == nil || !strings.Contains(err.Error(), "refusing to adopt existing") {
				t.Fatalf("error=%v, want collision refusal", err)
			}
			if creates != tc.creates || deletes != tc.deletes {
				t.Fatalf("creates/deletes=%d/%d want %d/%d", creates, deletes, tc.creates, tc.deletes)
			}
		})
	}
}
