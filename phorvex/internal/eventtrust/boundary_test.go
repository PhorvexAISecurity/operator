package eventtrust

import (
	"context"
	"testing"
	"time"

	admission "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// trustDetectors installs the detector allowlist for one test.
func trustDetectors(t *testing.T, ids ...string) {
	t.Helper()
	prev := EventTrust()
	t.Cleanup(func() { ConfigureEventTrust(prev) })
	ConfigureEventTrust(NewTrustedDetectors(ids))
}

func m99Webhook() *admission.MutatingWebhookConfiguration {
	fail := admission.Fail
	path := "/stamp-amtd-r6security-com-v1beta1-securityevent"
	return &admission.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "protected-stamp", CreationTimestamp: metav1.NewTime(time.Unix(100, 0))}, Webhooks: []admission.MutatingWebhook{{Name: "stamp-protected-outcomes.phorvex.ai", FailurePolicy: &fail, MatchConditions: []admission.MatchCondition{{Name: "protected-outcomes", Expression: ProtectedOutcomeMatch}}, ClientConfig: admission.WebhookClientConfig{CABundle: []byte("test-ca"), Service: &admission.ServiceReference{Namespace: "system", Name: "webhook", Path: &path}}, Rules: []admission.RuleWithOperations{{Operations: []admission.OperationType{admission.Create, admission.Update}, Rule: admission.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"v1beta1"}, Resources: []string{"securityevents"}}}}}}}
}

func TestM99BoundaryRequiresFailClosedScopedCreateAndUpdate(t *testing.T) {
	trustDetectors(t, "system:serviceaccount:vllm:detector-kv-canary")
	for _, mode := range []string{"ready", "absent", "failure-open", "update-gap", "object-selector", "match-gap", "unknown-epoch", "no-allowlist"} {
		t.Run(mode, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = admission.AddToScheme(scheme)
			cfg := m99Webhook()
			w := &cfg.Webhooks[0]
			switch mode {
			case "failure-open":
				v := admission.Ignore
				w.FailurePolicy = &v
			case "update-gap":
				w.Rules[0].Operations = []admission.OperationType{admission.Create}
			case "object-selector":
				w.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"skip": "true"}}
			case "match-gap":
				w.MatchConditions = nil
			case "unknown-epoch":
				cfg.CreationTimestamp = metav1.Time{}
			case "no-allowlist":
				trustDetectors(t)
			}
			b := fake.NewClientBuilder().WithScheme(scheme)
			if mode != "absent" {
				b.WithObjects(cfg)
			}
			ready, why, since := CheckExistentialBoundary(context.Background(), b.Build())
			if ready != (mode == "ready") || why == "" {
				t.Fatalf("ready=%v why=%s", ready, why)
			}
			if ready && since.IsZero() {
				t.Fatal("missing enforcement epoch")
			}
		})
	}
}
