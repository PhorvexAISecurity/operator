package runner

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func ksScheme() *runtime.Scheme { s := runtime.NewScheme(); _ = corev1.AddToScheme(s); return s }

type killSwitchWaitingReader struct{}

func (killSwitchWaitingReader) Get(ctx context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	<-ctx.Done()
	return ctx.Err()
}
func (killSwitchWaitingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	panic("unexpected list")
}

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

func TestKillSwitchObservationCausesAndAcceptedValues(t *testing.T) {
	const namespace = "phorvex-system"
	key := client.ObjectKey{Namespace: namespace, Name: DefaultKillSwitchName}
	newSwitch := func(data map[string]string) *KillSwitch {
		t.Helper()
		objects := []client.Object{}
		if data != nil {
			objects = append(objects, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}, Data: data})
		}
		return &KillSwitch{Client: fake.NewClientBuilder().WithScheme(ksScheme()).WithObjects(objects...).Build(), Namespace: namespace}
	}
	tests := []struct {
		name string
		ks   *KillSwitch
		want KillSwitchObservation
	}{
		{name: "nil", want: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
		{name: "static-only", ks: &KillSwitch{}, want: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
		{name: "static-engaged", ks: &KillSwitch{Static: true}, want: KillSwitchObservation{Engaged: true, Cause: KillSwitchStaticFlag}},
		{name: "missing-namespace", ks: &KillSwitch{Client: fake.NewClientBuilder().WithScheme(ksScheme()).Build()}, want: KillSwitchObservation{Engaged: true, Cause: KillSwitchMissingNamespace}},
		{name: "sentinel-absent", ks: newSwitch(nil), want: KillSwitchObservation{Cause: KillSwitchSentinelAbsent}},
		{name: "key-absent", ks: newSwitch(map[string]string{"costCalibration": "off"}), want: KillSwitchObservation{Cause: KillSwitchSentinelKeyAbsent}},
		{name: "true", ks: newSwitch(map[string]string{"engaged": "true"}), want: KillSwitchObservation{Engaged: true, Cause: KillSwitchSentinelEngaged}},
		{name: "capital-true", ks: newSwitch(map[string]string{"engaged": "True"}), want: KillSwitchObservation{Engaged: true, Cause: KillSwitchSentinelEngaged}},
		{name: "one", ks: newSwitch(map[string]string{"engaged": "1"}), want: KillSwitchObservation{Engaged: true, Cause: KillSwitchSentinelEngaged}},
		{name: "yes", ks: newSwitch(map[string]string{"engaged": "yes"}), want: KillSwitchObservation{Engaged: true, Cause: KillSwitchSentinelEngaged}},
		{name: "false", ks: newSwitch(map[string]string{"engaged": "false"}), want: KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}},
		{name: "capital-false", ks: newSwitch(map[string]string{"engaged": "False"}), want: KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}},
		{name: "zero", ks: newSwitch(map[string]string{"engaged": "0"}), want: KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}},
		{name: "no", ks: newSwitch(map[string]string{"engaged": "no"}), want: KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}},
		{name: "malformed", ks: newSwitch(map[string]string{"engaged": "TRUE"}), want: KillSwitchObservation{Engaged: true, Cause: KillSwitchMalformedValue}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got KillSwitchObservation
			if tc.ks == nil {
				got = (*KillSwitch)(nil).Observe(context.Background())
			} else {
				got = tc.ks.Observe(context.Background())
			}
			if got != tc.want {
				t.Fatalf("observation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestKillSwitchObservationReadErrorAndDeadlineAreFailClosed(t *testing.T) {
	apiDown := fake.NewClientBuilder().WithScheme(ksScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return apierrors.NewServiceUnavailable("api server unreachable")
		},
	}).Build()
	if got := (&KillSwitch{Client: apiDown, Namespace: "phorvex-system"}).Observe(context.Background()); got != (KillSwitchObservation{Engaged: true, Cause: KillSwitchReadError}) {
		t.Fatalf("API error observation = %+v", got)
	}

	start := time.Now()
	got := (&KillSwitch{Client: killSwitchWaitingReader{}, Namespace: "phorvex-system", ReadTimeout: 15 * time.Millisecond}).Observe(context.Background())
	if got != (KillSwitchObservation{Engaged: true, Cause: KillSwitchReadError}) {
		t.Fatalf("timeout observation = %+v", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded read took %v", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	got = (&KillSwitch{Client: killSwitchWaitingReader{}, Namespace: "phorvex-system", ReadTimeout: time.Second}).Observe(ctx)
	if got != (KillSwitchObservation{Engaged: true, Cause: KillSwitchReadError}) {
		t.Fatalf("cancelled observation = %+v", got)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("caller cancellation was ignored for %v", elapsed)
	}
}

func TestKillSwitchActuationObservationDoesNotChangeCalibrationSemantics(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "phorvex-system", Name: DefaultKillSwitchName},
		Data: map[string]string{
			"engaged":         "invalid",
			"costCalibration": "off",
		},
	}
	c := fake.NewClientBuilder().WithScheme(ksScheme()).WithObjects(cm).Build()
	ks := &KillSwitch{Client: c, Namespace: cm.Namespace}
	if got := ks.Observe(context.Background()); !got.Engaged || got.Cause != KillSwitchMalformedValue {
		t.Fatalf("malformed actuation sentinel did not fail closed: %+v", got)
	}
	if frozen, ok := ks.CalibrationFrozen(context.Background()); !ok || !frozen {
		t.Fatalf("independent calibration value was lost: frozen=%t ok=%t", frozen, ok)
	}

	apiDown := fake.NewClientBuilder().WithScheme(ksScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return apierrors.NewServiceUnavailable("api server unreachable")
		},
	}).Build()
	ks = &KillSwitch{Client: apiDown, Namespace: cm.Namespace}
	if got := ks.Observe(context.Background()); !got.Engaged || got.Cause != KillSwitchReadError {
		t.Fatalf("actuation read error did not fail closed: %+v", got)
	}
	if frozen, ok := ks.CalibrationFrozen(context.Background()); ok || frozen {
		t.Fatalf("calibration read uncertainty must preserve current state: frozen=%t ok=%t", frozen, ok)
	}
}
