package runner

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func ksScheme() *runtime.Scheme { s := runtime.NewScheme(); _ = corev1.AddToScheme(s); return s }

// TestKillSwitchFailsClosedOnReadError — P4b FIX 1 (highest severity): when the kill-switch
// ConfigMap Get fails for a reason OTHER than NotFound (API hiccup / timeout / RBAC), Engaged
// must return TRUE (fail-CLOSED) — Phorvex must not actuate when it cannot read its own switch.
func TestKillSwitchFailsClosedOnReadError(t *testing.T) {
	// (a) API error on Get => ENGAGED (fail-closed).
	apiDown := fake.NewClientBuilder().WithScheme(ksScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return apierrors.NewServiceUnavailable("api server unreachable")
		},
	}).Build()
	if !(&KillSwitch{Client: apiDown, Namespace: "phorvex-system"}).Engaged(context.Background()) {
		t.Error("FAIL-OPEN: kill-switch read error did not engage (must fail-CLOSED)")
	}

	// (b) sentinel genuinely absent (NotFound) => NOT engaged (the normal case).
	empty := fake.NewClientBuilder().WithScheme(ksScheme()).Build()
	if (&KillSwitch{Client: empty, Namespace: "phorvex-system"}).Engaged(context.Background()) {
		t.Error("a missing sentinel must NOT engage the kill-switch")
	}

	// (c) sentinel present with engaged=true => engaged.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "phorvex-system", Name: DefaultKillSwitchName}, Data: map[string]string{"engaged": "true"}}
	on := fake.NewClientBuilder().WithScheme(ksScheme()).WithObjects(cm).Build()
	if !(&KillSwitch{Client: on, Namespace: "phorvex-system"}).Engaged(context.Background()) {
		t.Error("an engaged sentinel must engage the kill-switch")
	}

	// (d) [P4c D4] a client wired but NO namespace => the ConfigMap kill-switch is
	// non-functional (misconfig) => fail-CLOSED (engaged), NOT the old fail-open "not engaged".
	if !(&KillSwitch{Client: empty, Namespace: ""}).Engaged(context.Background()) {
		t.Error("a client with an empty namespace must fail-CLOSED (engaged), not silently disengage")
	}
	// (e) no client at all => static-only, ConfigMap path not in play => not engaged.
	if (&KillSwitch{Client: nil, Namespace: ""}).Engaged(context.Background()) {
		t.Error("no client => static-only kill-switch must report not-engaged")
	}
}
