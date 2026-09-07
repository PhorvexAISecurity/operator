package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type missingColocationLists struct{ client.Client }

func (c missingColocationLists) List(ctx context.Context, l client.ObjectList, opts ...client.ListOption) error {
	switch l.(type) {
	case *v1alpha1.PhorvexPolicyList, *amtd.SecurityEventList:
		return fmt.Errorf("list unavailable")
	}
	return c.Client.List(ctx, l, opts...)
}
func TestColocationSnapshotRecordsCompleteness(t *testing.T) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "infra", Labels: map[string]string{"phorvex.ai/trust-class": "infrastructure"}}}, &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "infra"}}).Build()
	snap, err := CollectSnapshot(context.Background(), c, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.PodInventoryComplete || !snap.PolicyInventoryComplete || !snap.EventInventoryComplete || len(snap.Policies) != 1 || snap.NamespaceLabels["infra"]["phorvex.ai/trust-class"] != "infrastructure" {
		t.Fatalf("missing observation: %+v", snap)
	}
	snap, err = CollectSnapshot(context.Background(), missingColocationLists{c}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.PolicyInventoryComplete || snap.EventInventoryComplete {
		t.Fatal("failure became empty complete inventory")
	}
}
