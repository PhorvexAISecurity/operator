package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	admission "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM99OutcomeIngestPreservesRawUntrustedInventory(t *testing.T) {
	trustEvents(t, trustedSA)
	scheme := runtime.NewScheme()
	_ = amtdv1beta1.AddToScheme(scheme)
	trusted := seEvent("trusted", trustedSA, "detector", "ns/p")
	forged := seEvent("forged", untrustedSA, "TrustedDetector", "ns/p")
	broken := seEvent("broken", trustedSA, "detector", "ns/p")
	r := model.ProtectedOutcome{ID: "r", LossState: "unknown", RequiredKeys: []string{"audit-only"}}
	raw, _ := json.Marshal([]model.ProtectedOutcome{r})
	trusted.Annotations["phorvex.ai/protected-outcomes-v1"] = string(raw)
	forged.Annotations["phorvex.ai/protected-outcomes-v1"] = string(raw)
	broken.Annotations["phorvex.ai/protected-outcomes-v1"] = "[broken"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(trusted, forged, broken).Build()
	all, byPod, err := collectEvents(context.Background(), c, time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || len(byPod["ns/p"]) != 2 {
		t.Fatalf("inventory=%d belief=%d", len(all), len(byPod["ns/p"]))
	}
	for _, ev := range all {
		switch ev.Name {
		case "trusted", "forged":
			if len(ev.Outcomes) != 1 || ev.Outcomes[0].RequiredKeys[0] != "audit-only" {
				t.Fatal("raw outcome dropped")
			}
		case "broken":
			if ev.OutcomeParseError == "" {
				t.Fatal("malformed outcome silently ignored")
			}
		}
	}
}

func m99Webhook() *admission.MutatingWebhookConfiguration {
	fail := admission.Fail
	path := "/stamp-amtd-r6security-com-v1beta1-securityevent"
	return &admission.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "protected-stamp", CreationTimestamp: metav1.NewTime(time.Unix(100, 0))}, Webhooks: []admission.MutatingWebhook{{Name: "stamp-protected-outcomes.phorvex.ai", FailurePolicy: &fail, MatchConditions: []admission.MatchCondition{{Name: "protected-outcomes", Expression: ProtectedOutcomeMatch}}, ClientConfig: admission.WebhookClientConfig{CABundle: []byte("test-ca"), Service: &admission.ServiceReference{Namespace: "system", Name: "webhook", Path: &path}}, Rules: []admission.RuleWithOperations{{Operations: []admission.OperationType{admission.Create, admission.Update}, Rule: admission.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"v1beta1"}, Resources: []string{"securityevents"}}}}}}}
}

func TestM99BoundaryRequiresFailClosedScopedCreateAndUpdate(t *testing.T) {
	trustEvents(t, trustedSA)
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
				trustEvents(t)
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
