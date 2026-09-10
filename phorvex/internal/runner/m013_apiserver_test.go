package runner

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
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
	time.Sleep(150 * time.Millisecond)
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
