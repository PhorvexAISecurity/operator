package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func waitM013EventAuthorization(ctx context.Context, interval time.Duration, want bool, review func(context.Context, string) (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("waiting for events create/patch allowed=%t: %w", want, err)
	}
	verbs := []string{"create", "patch"}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		matched := true
		statuses := make(map[string]bool, len(verbs))
		for _, verb := range verbs {
			allowed, err := review(ctx, verb)
			if err != nil {
				return fmt.Errorf("review events %s: %w", verb, err)
			}
			statuses[verb] = allowed
			matched = matched && allowed == want
		}
		if matched {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for events create/patch allowed=%t (last=%v): %w", want, statuses, ctx.Err())
		case <-ticker.C:
		}
	}
}

type m013SARClient interface {
	Create(context.Context, client.Object, ...client.CreateOption) error
}

func reviewM013EventAuthorization(ctx context.Context, c m013SARClient, user string, groups []string, namespace, verb string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	sar := &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{
		User: user, Groups: groups,
		ResourceAttributes: &authv1.ResourceAttributes{Namespace: namespace, Verb: verb, Resource: "events"},
	}}
	if err := c.Create(ctx, sar); err != nil {
		return false, err
	}
	if sar.Status.EvaluationError != "" {
		return false, fmt.Errorf("authorization evaluation: %s", sar.Status.EvaluationError)
	}
	return sar.Status.Allowed, nil
}

type m013SARClientFunc func(context.Context, client.Object, ...client.CreateOption) error

func (f m013SARClientFunc) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return f(ctx, obj, opts...)
}

func TestM013AuthorizationReviewDistinguishesVerdictsAndEvaluationErrors(t *testing.T) {
	for _, tc := range []struct {
		name, evaluationError  string
		allowed, want, wantErr bool
	}{
		{name: "allowed", allowed: true, want: true},
		{name: "denied"},
		{name: "evaluation error", evaluationError: "authorizer unavailable", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := m013SARClientFunc(func(_ context.Context, obj client.Object, _ ...client.CreateOption) error {
				sar := obj.(*authv1.SubjectAccessReview)
				if sar.Spec.User != "writer" || sar.Spec.ResourceAttributes.Namespace != "m013" || sar.Spec.ResourceAttributes.Resource != "events" || sar.Spec.ResourceAttributes.Verb != "create" {
					t.Fatalf("imprecise review: %+v", sar.Spec)
				}
				sar.Status.Allowed = tc.allowed
				sar.Status.EvaluationError = tc.evaluationError
				return nil
			})
			got, err := reviewM013EventAuthorization(context.Background(), fake, "writer", []string{"group"}, "m013", "create")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("allowed=%t err=%v, want allowed=%t wantErr=%t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestM013AuthorizationWaitRejectsCancelledContextBeforeReview(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := waitM013EventAuthorization(ctx, time.Millisecond, true, func(context.Context, string) (bool, error) {
		calls++
		return true, nil
	})
	if err == nil || calls != 0 {
		t.Fatalf("cancelled wait err=%v reviews=%d", err, calls)
	}
}

func TestM013AuthorizationWaitsForBothVerbTransitions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		want     bool
		sequence [][2]bool
	}{
		{name: "delayed allow", want: true, sequence: [][2]bool{{false, false}, {true, false}, {true, true}}},
		{name: "delayed deny", want: false, sequence: [][2]bool{{true, true}, {false, true}, {false, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			review := func(_ context.Context, verb string) (bool, error) {
				round := calls / 2
				if round >= len(tc.sequence) {
					round = len(tc.sequence) - 1
				}
				index := 0
				if verb == "patch" {
					index = 1
				}
				calls++
				return tc.sequence[round][index], nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := waitM013EventAuthorization(ctx, time.Millisecond, tc.want, review); err != nil {
				t.Fatal(err)
			}
			if calls != len(tc.sequence)*2 {
				t.Fatalf("reviews=%d want=%d", calls, len(tc.sequence)*2)
			}
		})
	}
}

func TestM013RealEventSink(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated API server")
	}
	env := &envtest.Environment{}
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
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = authv1.AddToScheme(scheme)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	create := func(o client.Object) {
		t.Helper()
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m013"}})
	create(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "events", Namespace: "m013"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}}}})
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "events", Namespace: "m013"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "events"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "writer", Namespace: "m013"}}}
	create(binding)
	rc := rest.CopyConfig(cfg)
	rc.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:m013:writer", Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:m013"}}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatal(err)
	}
	review := func(reviewCtx context.Context, verb string) (bool, error) {
		return reviewM013EventAuthorization(reviewCtx, admin, rc.Impersonate.UserName, rc.Impersonate.Groups, "m013", verb)
	}
	waitAuthorization := func(label string, want bool) {
		t.Helper()
		waitCtx, waitCancel := context.WithTimeout(ctx, 8*time.Second)
		defer waitCancel()
		if err := waitM013EventAuthorization(waitCtx, 30*time.Millisecond, want, review); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	waitAuthorization("initial event permission did not propagate", true)
	var mu sync.Mutex
	logs := ""
	log := funcr.New(func(_, msg string) { mu.Lock(); logs += msg + "\n"; mu.Unlock() }, funcr.Options{})
	broadcaster := record.NewBroadcaster(record.WithContext(logr.NewContext(ctx, log)))
	defer broadcaster.Shutdown()
	broadcaster.StartRecordingToSink(&typedcore.EventSinkImpl{Interface: cs.CoreV1().Events("")})
	m := &Manager{ActuationRecorder: broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "phorvex-actuation"}), Log: log}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "m013"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "busybox"}}}}
	create(pod)
	target := actuationEventTarget(&model.WorkloadView{Pod: model.Pod{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}})
	zero := int64(0)
	if err := admin.Delete(ctx, pod, &client.DeleteOptions{GracePeriodSeconds: &zero}); err != nil {
		t.Fatal(err)
	}
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "m013"}, Spec: pod.Spec}
	create(replacement)
	if target.UID == replacement.UID {
		t.Fatal("replacement needs new UID")
	}
	wait := func(label string, fn func() bool) {
		t.Helper()
		until := time.Now().Add(8 * time.Second)
		for time.Now().Before(until) {
			if fn() {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal(label)
	}
	m.notifyActuation(target, model.ActionRotate, actuator.Result{Emitted: true}, nil)
	var events corev1.EventList
	wait("Event not persisted", func() bool { _ = admin.List(ctx, &events, client.InNamespace("m013")); return len(events.Items) > 0 })
	first := events.Items[0]
	if first.InvolvedObject.UID != target.UID || first.InvolvedObject.UID == replacement.UID || first.Namespace != "m013" || len(first.OwnerReferences) != 0 {
		t.Fatal(first)
	}
	m.notifyActuation(target, model.ActionRotate, actuator.Result{Emitted: true}, nil)
	wait("repeat was not patched", func() bool {
		_ = admin.List(ctx, &events, client.InNamespace("m013"))
		return len(events.Items) == 1 && events.Items[0].Count >= 2
	})
	if err := admin.Delete(ctx, binding); err != nil {
		t.Fatal(err)
	}
	waitAuthorization("event permission revocation did not propagate", false)
	start := time.Now()
	m.notifyActuation(target, model.ActionQuarantine, actuator.Result{Emitted: true}, nil)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("notification blocked on sink")
	}
	wait("denial diagnostic missing", func() bool { mu.Lock(); defer mu.Unlock(); return strings.Contains(logs, "Server rejected event") })
	restored := binding.DeepCopy()
	restored.ResourceVersion = ""
	restored.UID = ""
	create(restored)
	waitAuthorization("restored event permission did not propagate", true)
	m.notifyActuation(target, model.ActionIdentityRotate, actuator.Result{Emitted: true}, nil)
	wait("restored permission did not recover", func() bool {
		_ = admin.List(ctx, &events, client.InNamespace("m013"))
		for _, e := range events.Items {
			if strings.Contains(e.Message, "identity-rotate") {
				return true
			}
		}
		return false
	})
	t.Logf("persisted original UID %s after replacement UID %s; repeated Event patched; restricted sink denial logged; permission restoration recovered", target.UID, replacement.UID)
}
