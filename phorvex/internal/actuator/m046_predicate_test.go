package actuator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestM46HandlerUsesCanonicalMIGPredicate(t *testing.T) {
	tests := []struct {
		name       string
		requests   corev1.ResourceList
		limits     corev1.ResourceList
		wantReason string
	}{
		{
			name:       "canonical-limit",
			limits:     corev1.ResourceList{"nvidia.com/mig-1g.10gb": resource.MustParse("1")},
			wantReason: "transport unavailable",
		},
		{
			name:       "non-mig-nvidia-resource",
			requests:   corev1.ResourceList{"nvidia.com/mps": resource.MustParse("1")},
			wantReason: "has no MIG device",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns",
					Name:      "infer-" + tt.name,
					UID:       types.UID("m046-" + tt.name),
					Annotations: map[string]string{
						annoGPUID:      "0",
						annoMIGProfile: "2g.20gb",
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "gpu-a",
					Containers: []corev1.Container{{
						Name: "infer",
						Resources: corev1.ResourceRequirements{
							Requests: tt.requests,
							Limits:   tt.limits,
						},
					}},
				},
			}
			c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
			_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{
				Client: c,
				Reader: c,
				MIG:    &mockMIG{availErr: errors.New("probe stopped before mutation")},
			}, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionMIGRebind})
			if err == nil || !strings.Contains(err.Error(), tt.wantReason) {
				t.Fatalf("reason = %v, want substring %q", err, tt.wantReason)
			}
			var after corev1.Pod
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &after); err != nil {
				t.Fatalf("MIG predicate mutated or removed the pod: %v", err)
			}
			if after.UID != pod.UID || !reflect.DeepEqual(after.Spec, pod.Spec) ||
				!reflect.DeepEqual(after.Labels, pod.Labels) || !reflect.DeepEqual(after.Annotations, pod.Annotations) {
				t.Fatalf("MIG predicate mutated the pod: before=%+v after=%+v", pod, &after)
			}
		})
	}
}
