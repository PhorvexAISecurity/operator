package mocks

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

type mockOwnershipGuard struct{}

func (mockOwnershipGuard) AssertMutationAllowed(string) error { return nil }

type mockOwnershipLogger struct{}

func (*mockOwnershipLogger) Logf(string, ...any) {}
func (*mockOwnershipLogger) Command(string)      {}
func (*mockOwnershipLogger) Commands() []string  { return nil }
func (*mockOwnershipLogger) RawLogPath() string  { return "" }

func mockOwnershipEnv(t *testing.T, objects ...runtime.Object) (*core.Env, *k8sfake.Clientset) {
	t.Helper()
	objects = append([]runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: "namespace-1"}}}, objects...)
	kube := k8sfake.NewSimpleClientset(objects...)
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &mockOwnershipLogger{}, Guard: mockOwnershipGuard{}, ScenarioName: "mock-case", Trial: 1}
	if err := env.EnsureNamespace(t.Context()); err != nil {
		t.Fatal(err)
	}
	return env, kube
}

func TestMockServerCreationBindsPodUIDAndRefusesPredecessor(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		env, kube := mockOwnershipEnv(t)
		kube.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
			pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
			pod.UID = "mock-pod-uid"
			pod.Status.Phase = corev1.PodRunning
			return false, nil, nil
		})
		kube.PrependReactor("create", "services", func(action ktesting.Action) (bool, runtime.Object, error) {
			svc := action.(ktesting.CreateAction).GetObject().(*corev1.Service)
			svc.UID = "mock-service-uid"
			return false, nil, nil
		})
		server, err := DeployMockInferenceServer(t.Context(), env)
		if err != nil {
			t.Fatal(err)
		}
		if uid, ok := env.CreatedUID("pods", server.PodName); !ok || uid != types.UID("mock-pod-uid") {
			t.Fatalf("created pod authority=%q,%v", uid, ok)
		}
	})
	t.Run("predecessor", func(t *testing.T) {
		foreign := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mock-infer-pod", Namespace: "sandbox", UID: "foreign", Finalizers: []string{"foreign/hold"}}}
		env, kube := mockOwnershipEnv(t, foreign)
		destructive := 0
		for _, verb := range []string{"delete", "patch"} {
			kube.PrependReactor(verb, "pods", func(ktesting.Action) (bool, runtime.Object, error) {
				destructive++
				return true, nil, errors.New("unexpected mutation")
			})
		}
		if _, err := DeployMockInferenceServer(context.Background(), env); err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
			t.Fatalf("error=%v, want predecessor refusal", err)
		}
		if destructive != 0 {
			t.Fatalf("destructive requests=%d", destructive)
		}
	})
}

func TestRequireCreatedPodCurrentRejectsMissingCreateResponse(t *testing.T) {
	env, _ := mockOwnershipEnv(t, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "mock", Namespace: "sandbox", UID: types.UID("current"),
	}})
	err := requireCreatedPodCurrent(t.Context(), env, "mock", nil)
	if err == nil || !strings.Contains(err.Error(), "no create-response identity") {
		t.Fatalf("error=%v, want missing identity refusal", err)
	}
}
