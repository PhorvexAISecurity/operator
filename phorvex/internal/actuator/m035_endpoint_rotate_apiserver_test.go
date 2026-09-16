package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type m35ReplacementClient struct {
	client.Client
	replaceKind    string
	replacementUID types.UID
}

func (c *m35ReplacementClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	switch current := obj.(type) {
	case *corev1.Pod:
		if c.replaceKind != "Pod" {
			return c.Client.Update(ctx, obj, opts...)
		}
		stored := &corev1.Pod{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(current), stored); err != nil {
			return err
		}
		if err := c.Client.Delete(ctx, stored); err != nil {
			return err
		}
		if err := m35WaitAbsent(ctx, c.Client, stored); err != nil {
			return err
		}
		replacement := stored.DeepCopy()
		m35ClearServerIdentity(&replacement.ObjectMeta)
		replacement.Status = corev1.PodStatus{}
		if err := c.Client.Create(ctx, replacement); err != nil {
			return err
		}
		c.replacementUID = replacement.UID
		return c.Client.Update(ctx, current, opts...)
	case *corev1.Service:
		if c.replaceKind != "Service" {
			return c.Client.Update(ctx, obj, opts...)
		}
		stored := &corev1.Service{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(current), stored); err != nil {
			return err
		}
		if err := c.Client.Delete(ctx, stored); err != nil {
			return err
		}
		if err := m35WaitAbsent(ctx, c.Client, stored); err != nil {
			return err
		}
		replacement := stored.DeepCopy()
		m35ClearServerIdentity(&replacement.ObjectMeta)
		replacement.Spec.ClusterIP = corev1.ClusterIPNone
		replacement.Spec.ClusterIPs = nil
		replacement.Spec.IPFamilies = nil
		replacement.Spec.IPFamilyPolicy = nil
		replacement.Spec.HealthCheckNodePort = 0
		replacement.Status = corev1.ServiceStatus{}
		if err := c.Client.Create(ctx, replacement); err != nil {
			return err
		}
		c.replacementUID = replacement.UID
		return c.Client.Update(ctx, current, opts...)
	default:
		return c.Client.Update(ctx, obj, opts...)
	}
}

func m35ClearServerIdentity(meta *metav1.ObjectMeta) {
	meta.UID = ""
	meta.ResourceVersion = ""
	meta.Generation = 0
	meta.CreationTimestamp = metav1.Time{}
	meta.DeletionTimestamp = nil
	meta.DeletionGracePeriodSeconds = nil
	meta.ManagedFields = nil
}

func m35WaitAbsent(ctx context.Context, c client.Client, obj client.Object) error {
	return wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, 3*time.Second, true, func(ctx context.Context) (bool, error) {
		fresh := obj.DeepCopyObject().(client.Object)
		err := c.Get(ctx, client.ObjectKeyFromObject(obj), fresh)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

func m35CreateEndpointTarget(t *testing.T, ctx context.Context, c client.Client, namespace, name string) (*corev1.Pod, *corev1.Service) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{"app": name, labelRouteKey: "ep-old"},
			Annotations: map[string]string{
				annoRouteService: name + "-svc",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "test:unused"}}},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name + "-svc"},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  map[string]string{"app": name, labelRouteKey: "ep-old"},
			Ports:     []corev1.ServicePort{{Name: "http", Port: 80}},
		},
	}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	return pod, svc
}

func TestM035EndpointRotateActualAPIIdentityAndReadback(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API server")
	}
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer env.Stop()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m035-api"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}

	t.Run("confirmed-restitch", func(t *testing.T) {
		pod, svc := m35CreateEndpointTarget(t, ctx, c, ns.Name, "positive")
		native := &NativeActuator{Client: c, Reader: c}
		result, err := native.Actuate(ctx, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate})
		if err != nil || !result.Emitted || result.MutationKind != "reversible" || len(result.ObjectsTouched) != 2 {
			t.Fatalf("positive result=%+v err=%v", result, err)
		}
		gotPod, gotSvc := &corev1.Pod{}, &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), gotPod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(svc), gotSvc); err != nil {
			t.Fatal(err)
		}
		if gotPod.UID != pod.UID || gotSvc.UID != svc.UID || gotPod.Labels[labelRouteKey] == "ep-old" || gotSvc.Spec.Selector[labelRouteKey] != gotPod.Labels[labelRouteKey] || !endpointServiceSelectsPod(gotSvc, gotPod) {
			t.Fatalf("postcondition Pod=%s labels=%v Service=%s selector=%v", gotPod.UID, gotPod.Labels, gotSvc.UID, gotSvc.Spec.Selector)
		}
	})

	t.Run("same-name-pod-replacement", func(t *testing.T) {
		pod, _ := m35CreateEndpointTarget(t, ctx, c, ns.Name, "pod-replacement")
		writer := &m35ReplacementClient{Client: c, replaceKind: "Pod"}
		native := &NativeActuator{Client: writer, Reader: c}
		result, err := native.Actuate(ctx, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate})
		if !IsNoEffectRefusal(err) || result.Emitted || writer.replacementUID == "" || writer.replacementUID == pod.UID {
			t.Fatalf("replacement result=%+v err=%v oldUID=%s replacementUID=%s", result, err, pod.UID, writer.replacementUID)
		}
		got := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), got); err != nil {
			t.Fatal(err)
		}
		if got.UID != writer.replacementUID || got.Labels[labelRouteKey] != "ep-old" {
			t.Fatalf("same-name replacement mutated: uid=%s labels=%v", got.UID, got.Labels)
		}
	})

	t.Run("same-name-service-replacement-after-pod-write", func(t *testing.T) {
		pod, svc := m35CreateEndpointTarget(t, ctx, c, ns.Name, "service-replacement")
		writer := &m35ReplacementClient{Client: c, replaceKind: "Service"}
		native := &NativeActuator{Client: writer, Reader: c}
		result, err := native.Actuate(ctx, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate})
		if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" || writer.replacementUID == "" || writer.replacementUID == svc.UID {
			t.Fatalf("replacement result=%+v err=%v oldUID=%s replacementUID=%s", result, err, svc.UID, writer.replacementUID)
		}
		gotPod, gotSvc := &corev1.Pod{}, &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), gotPod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(svc), gotSvc); err != nil {
			t.Fatal(err)
		}
		if gotPod.Labels[labelRouteKey] == "ep-old" || gotSvc.UID != writer.replacementUID || gotSvc.Spec.Selector[labelRouteKey] != "ep-old" {
			t.Fatalf("replacement was mutated or partial Pod write lost: Pod=%v ServiceUID=%s selector=%v", gotPod.Labels, gotSvc.UID, gotSvc.Spec.Selector)
		}
	})
}
