package ingest

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// event_trust_test.go — PHORVEXSEC-193 / M-94.
//
// Old behaviour (captured on main): an event with `source: K3Detector` — a self-declared string
// from an identity with no trust relationship — became belief evidence on the targeted pod, and
// a cluster-scoped target "/name" was turned into a bare key that matched nothing, silently.

const (
	trustedSA   = "system:serviceaccount:vllm:detector-kv-canary"
	untrustedSA = "system:serviceaccount:evil:squatter"
)

func trustEvents(t *testing.T, ids ...string) {
	t.Helper()
	prev := EventTrust()
	t.Cleanup(func() { ConfigureEventTrust(prev) })
	ConfigureEventTrust(NewTrustedDetectors(ids))
}

func seEvent(name, identity, source string, targets ...string) *amtdv1beta1.SecurityEvent {
	meta := metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(time.Date(2026, 9, 6, 11, 59, 0, 0, time.UTC))}
	if identity != "" {
		meta.Annotations = map[string]string{CreatorIdentityAnnotation: identity}
	}
	return &amtdv1beta1.SecurityEvent{
		ObjectMeta: meta,
		Spec: amtdv1beta1.SecurityEventSpec{Targets: targets,
			Rule: amtdv1beta1.Rule{Type: "Persistence", ThreatLevel: "critical", Source: source}},
	}
}

func collect(t *testing.T, objs ...*amtdv1beta1.SecurityEvent) ([]struct{ Name, Trust string }, map[string]int) {
	t.Helper()
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	all, byPod, err := collectEvents(context.Background(), b.Build(), time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	verdicts := make([]struct{ Name, Trust string }, 0, len(all))
	for _, e := range all {
		verdicts = append(verdicts, struct{ Name, Trust string }{e.Name, e.Trust})
	}
	counts := map[string]int{}
	for k, v := range byPod {
		counts[k] = len(v)
	}
	return verdicts, counts
}

// The ticket's exact live attack: a forged, unstamped event must not become evidence, while a
// real detector's stamped event still does (positive control for the null result).
func TestForgedEventSuppliesNoEvidenceWhileTrustedDetectorStillDoes(t *testing.T) {
	trustEvents(t, "vllm/detector-kv-canary")
	forged := seEvent("v10-forged", "", "K3Detector", "vllm/vllm-0")
	real := seEvent("kv-canary-1", trustedSA, "kv-canary", "vllm/vllm-0")
	verdicts, counts := collect(t, forged, real)

	if counts["vllm/vllm-0"] != 1 {
		t.Fatalf("evidence entries = %d, want exactly the trusted detector's 1 (old code: 2)", counts["vllm/vllm-0"])
	}
	got := map[string]string{}
	for _, v := range verdicts {
		got[v.Name] = v.Trust
	}
	if got["v10-forged"] != TrustUnstamped {
		t.Fatalf("forged event trust = %q, want %q", got["v10-forged"], TrustUnstamped)
	}
	if got["kv-canary-1"] != TrustTrusted {
		t.Fatalf("trusted detector event trust = %q, want %q", got["kv-canary-1"], TrustTrusted)
	}
	if len(verdicts) != 2 {
		t.Fatalf("both events must still be INGESTED and recorded (an injection attempt stays visible); got %d", len(verdicts))
	}
}

// A stamped identity that is not on the allowlist is untrusted — the stamp is a fact, not a pass.
func TestStampedButUnallowlistedIdentityIsUntrusted(t *testing.T) {
	trustEvents(t, "vllm/detector-kv-canary")
	_, counts := collect(t, seEvent("squat", untrustedSA, "kv-canary", "vllm/vllm-0"))
	if counts["vllm/vllm-0"] != 0 {
		t.Fatalf("an unallowlisted identity supplied %d evidence entries, want 0", counts["vllm/vllm-0"])
	}
}

// Fail-closed: no configured allowlist trusts no external detector.
func TestEmptyAllowlistIsFailClosed(t *testing.T) {
	trustEvents(t)
	verdicts, counts := collect(t, seEvent("any", trustedSA, "kv-canary", "vllm/vllm-0"))
	if counts["vllm/vllm-0"] != 0 || len(verdicts) != 1 || verdicts[0].Trust != TrustNoAllowed {
		t.Fatalf("empty allowlist: evidence=%d verdicts=%+v, want 0 evidence and %q", counts["vllm/vllm-0"], verdicts, TrustNoAllowed)
	}
}

// Phorvex's own actuation events remain excluded (no feedback loop) regardless of trust config.
func TestOwnEventsStillExcluded(t *testing.T) {
	trustEvents(t, "vllm/detector-kv-canary")
	own := seEvent("self", trustedSA, amtdv1beta1.PhorvexRuleSource, "vllm/vllm-0")
	verdicts, counts := collect(t, own)
	if len(verdicts) != 0 || counts["vllm/vllm-0"] != 0 {
		t.Fatalf("Phorvex's own event leaked into the stream: verdicts=%+v evidence=%d", verdicts, counts["vllm/vllm-0"])
	}
}

// A cluster-scoped ("/name") or bare ("name") target identifies no pod: recorded with a reason,
// never silently dropped, and never keyed to a pod that does not exist.
func TestClusterScopedTargetIsRecordedNotSilentlyDropped(t *testing.T) {
	trustEvents(t, "vllm/detector-kv-canary")
	ev := seEvent("cluster-ref", trustedSA, "kv-canary", "/vllm-0", "vllm-0", "vllm/vllm-0")
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	all, byPod, err := collectEvents(context.Background(),
		fake.NewClientBuilder().WithScheme(s).WithObjects(ev).Build(), time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || len(all[0].UnresolvedTargets) != 2 {
		t.Fatalf("unresolved targets = %v, want the two namespace-less refs recorded", all[0].UnresolvedTargets)
	}
	if len(byPod) != 1 || len(byPod["vllm/vllm-0"]) != 1 {
		t.Fatalf("byPod = %v, want only the resolvable ns/pod target (old code also produced a bare \"vllm-0\" key)", byPod)
	}
	if _, ok := byPod["vllm-0"]; ok {
		t.Fatal("a bare pod name must never become a key: it matches no pod and hides the reference")
	}
}

// The allowlist accepts the spellings a chart value and the API server each use.
func TestIdentitySpellingsAreEquivalent(t *testing.T) {
	for _, spelling := range []string{"vllm/detector-kv-canary", "vllm:detector-kv-canary", trustedSA} {
		if got := NormalizeIdentity(spelling); got != trustedSA {
			t.Fatalf("NormalizeIdentity(%q) = %q, want %q", spelling, got, trustedSA)
		}
	}
	allow := NewTrustedDetectors([]string{" vllm/detector-kv-canary , ", ""})
	if !allow.Allows(trustedSA) || allow.Allows(untrustedSA) || allow.Empty() {
		t.Fatalf("allowlist behaviour wrong: %v", allow.List())
	}
	if !NewTrustedDetectors([]string{"alice@example.com"}).Allows("alice@example.com") {
		t.Fatal("a non-ServiceAccount username must be matchable verbatim, not rewritten")
	}
}

// Idempotence: repeating the same tick yields the same verdicts and the same evidence.
func TestCollectEventsIsIdempotent(t *testing.T) {
	trustEvents(t, "vllm/detector-kv-canary")
	ev := seEvent("kv-canary-1", trustedSA, "kv-canary", "vllm/vllm-0")
	v1, c1 := collect(t, ev)
	v2, c2 := collect(t, ev)
	if len(v1) != len(v2) || v1[0] != v2[0] || c1["vllm/vllm-0"] != c2["vllm/vllm-0"] {
		t.Fatalf("not idempotent: %+v/%v vs %+v/%v", v1, c1, v2, c2)
	}
}
