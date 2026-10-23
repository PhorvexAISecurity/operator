package runner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
)

func TestActuationPreparedConditionIsCurrentGenerationAndRouteQualified(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", UID: "policy-uid", Generation: 8}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(policy).Build()
	e := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "p"}, uid: "policy-uid", tenant: "team", generation: 8}
	m := &Manager{Local: &inprocess.Services{Actuator: &routedDispatchFake{}}, Client: c}
	status := actionsSupportStatus{status: metav1.ConditionTrue, reason: "Supported", message: "capabilities present", preparation: &actuator.RoutePreparation{PhoenixErr: errors.New("selector has unproven Exists")}}
	m.updateStatus(t.Context(), e, 1, 1, 0, false, time.Unix(100, 0), status)
	var got v1alpha1.PhorvexPolicy
	if err := c.Get(t.Context(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "ActuationPrepared")
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.ObservedGeneration != 8 || !strings.Contains(cond.Message, "selector has unproven Exists") || !strings.Contains(cond.Message, "native route: prepared") {
		t.Fatalf("route refusal status = %+v", cond)
	}
	// A spec update between preparation and status write cannot attest the new
	// generation using the old route result.
	got.Generation = 9
	if err := c.Update(t.Context(), &got); err != nil {
		t.Fatal(err)
	}
	m.updateStatus(t.Context(), e, 1, 1, 0, false, time.Unix(101, 0), status)
	if err := c.Get(t.Context(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(got.Status.Conditions, "ActuationPrepared")
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "StalePreparation" || cond.ObservedGeneration != 9 {
		t.Fatalf("old preparation promoted to new generation: %+v", cond)
	}
	// A later tick with no preparation records Unknown, not the previous refusal.
	status.preparation = nil
	m.updateStatus(t.Context(), e, 1, 0, 0, true, time.Unix(102, 0), status)
	if err := c.Get(t.Context(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(got.Status.Conditions, "ActuationPrepared")
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "NotAttempted" {
		t.Fatalf("stale refusal survived unprepared tick: %+v", cond)
	}
}
