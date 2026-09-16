/*
 * Phorvex — M-18 (narrow ACTUATION companion): EventUID is read from the SAME successful
 * Create response that already supplies EventName. No extra read, no extra permission,
 * and nothing fabricated for a create that did not succeed.
 */

package actuator

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// m018Request is one rotate attempt against a pod.
func m018Request() Request {
	return Request{
		Tenant: "team-a", Namespace: "ns", Pod: "p1", TargetUID: "pod-uid",
		Action: model.ActionRotate, Reason: "test", Score: 0.5,
	}
}

// The UID the API server assigned is carried into the Result verbatim.
func TestM018ActuateCarriesServerAssignedEventUID(t *testing.T) {
	const uid = "b21c7f44-1111-4222-9333-444455556666"
	var reads int
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				obj.SetUID(types.UID(uid))
			}
			return nil
		},
		// NO EXTRA READS: enriching the record must not add a Get against the API.
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				reads++
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()

	res, err := NewPhoenixActuator(c).Actuate(context.Background(), m018Request())
	if err != nil {
		t.Fatalf("Actuate: %v", err)
	}
	if res.EventUID != uid {
		t.Fatalf("EventUID = %q, want %q", res.EventUID, uid)
	}
	if res.EventName == "" {
		t.Fatal("EventName empty; the fixture is not exercising the acknowledged response")
	}
	if reads != 0 {
		t.Fatalf("M-18 must not add SecurityEvent reads; saw %d", reads)
	}
	// The five original fields are unchanged by the companion addition.
	if res.AMTDName != "phorvex-ns-team-a" || res.RuleType != RuleTypeRotate ||
		res.RuleThreatLevel != RuleThreatLevel || res.RuleSource != RuleSource || !res.Emitted {
		t.Fatalf("existing Result fields changed: %+v", res)
	}
}

// A create that never succeeded yields NO identity at all — not a name, not a UID.
func TestM018FailedCreateYieldsNoEventIdentity(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: "amtd.r6security.com", Resource: "securityevents"},
					"", errors.New("denied"))
			}
			return c.Create(ctx, obj, opts...)
		},
	}).Build()

	res, err := NewPhoenixActuator(c).Actuate(context.Background(), m018Request())
	if err == nil {
		t.Fatal("expected the rejected create to error")
	}
	if res.EventUID != "" || res.EventName != "" || res.AMTDName != "" {
		t.Fatalf("fabricated identity for a failed create: %+v", res)
	}
}

// TRUTHFUL SCOPE: the SecurityEvent this attempt creates is cluster-scoped, and the AMTD
// is a namespaced, separately-maintained policy object — not something this attempt
// created or mutated. The record's amtdNamespace describes that context, nothing more.
func TestM018EventIsClusterScopedAndAMTDIsSeparatePolicySetup(t *testing.T) {
	var created []struct{ kind, namespace, name string }
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			kind := "AMTD"
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				kind = "SecurityEvent"
			}
			created = append(created, struct{ kind, namespace, name string }{
				kind, obj.GetNamespace(), obj.GetName()})
			return nil
		},
	}).Build()

	pa := NewPhoenixActuator(c)
	ctx := context.Background()
	if err := pa.EnsurePolicy(ctx, TenantTarget{
		Tenant: "team-a", Namespace: "ns",
		MatchLabels:    map[string]string{"app": "demo"},
		EnabledActions: map[model.Action]bool{model.ActionRotate: true},
	}); err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	amtdCreates := len(created)
	if amtdCreates == 0 {
		t.Fatal("fixture: EnsurePolicy created no AMTD")
	}

	if _, err := pa.Actuate(ctx, m018Request()); err != nil {
		t.Fatalf("Actuate: %v", err)
	}

	// The ATTEMPT created exactly one object, and it was the cluster-scoped event.
	attemptCreated := created[amtdCreates:]
	if len(attemptCreated) != 1 {
		t.Fatalf("the attempt created %d objects, want 1 (the SecurityEvent): %+v",
			len(attemptCreated), attemptCreated)
	}
	if attemptCreated[0].kind != "SecurityEvent" {
		t.Fatalf("the attempt created a %s; the AMTD must not be re-created per attempt",
			attemptCreated[0].kind)
	}
	if attemptCreated[0].namespace != "" {
		t.Fatalf("SecurityEvent is cluster-scoped but got namespace %q", attemptCreated[0].namespace)
	}
}

// The rule tuple is a LOGICAL matcher carried in the event spec — there is no Rule object
// to reference. Nothing in the result may imply one.
func TestM018RuleTupleIsLogicalNotAnAPIObject(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	res, err := NewPhoenixActuator(c).Actuate(context.Background(), m018Request())
	if err != nil {
		t.Fatalf("Actuate: %v", err)
	}
	// The Phoenix adapter touches no native objects and claims no rollback: the rule
	// identifiers must never be smuggled into the native object-reference surface.
	if len(res.ObjectsTouched) != 0 {
		t.Fatalf("rule/AMTD identifiers leaked into ObjectsTouched: %v", res.ObjectsTouched)
	}
	if res.Handler != "" || res.RollbackRef != "" || res.MutationKind != "" {
		t.Fatalf("native-actuator fields populated by the Phoenix path: %+v", res)
	}
}
