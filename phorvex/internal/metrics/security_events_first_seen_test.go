package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func firstSeenValue(t *testing.T, namespace, trust string) float64 {
	t.Helper()
	var m dto.Metric
	if err := securityEventsFirstSeen.WithLabelValues(namespace, trust).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// An event consumed within one tick must still count, and an event listed on many ticks
// must count once: the Grafana "apps attacked" panels use increase() of this counter.
func TestSecurityEventFirstSeenCountsEachEventOnce(t *testing.T) {
	before := firstSeenValue(t, "fs-voice", "trusted")
	RecordSecurityEventFirstSeen("uid-fs-1", "trusted", []string{"fs-voice"})
	RecordSecurityEventFirstSeen("uid-fs-1", "trusted", []string{"fs-voice"})
	RecordSecurityEventFirstSeen("uid-fs-2", "trusted", []string{"fs-voice", "fs-voice"})
	if got := firstSeenValue(t, "fs-voice", "trusted") - before; got != 2 {
		t.Fatalf("fs-voice trusted first-seen = %v, want 2 (once per event UID and namespace)", got)
	}
	RecordSecurityEventFirstSeen("uid-fs-3", "untrusted-identity", []string{"fs-voice", "fs-mcp"})
	if firstSeenValue(t, "fs-voice", "untrusted-identity") != 1 || firstSeenValue(t, "fs-mcp", "untrusted-identity") != 1 {
		t.Fatal("an event targeting two namespaces must count once in each")
	}
	RecordSecurityEventFirstSeen("uid-fs-4", "trusted", nil)
	if firstSeenValue(t, "", "trusted") < 1 {
		t.Fatal("an event with no resolvable target must still be counted under an empty namespace")
	}
	RecordSecurityEventFirstSeen("", "trusted", []string{"fs-empty-uid"})
	if firstSeenValue(t, "fs-empty-uid", "trusted") != 0 {
		t.Fatal("an event without a UID cannot be deduplicated and must not be counted")
	}
}

// The trusted series for a policy namespace exists at 0 before its first event, so
// increase() over a window sees the first event instead of a series that starts at 1.
func TestPublishTickExposesTrustedFirstSeenAtZero(t *testing.T) {
	PublishTick("fs-tenant", "fs-quiet", "fs-policy", "fs-uid", nil, nil, 0, 0.01, "active", true)
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "phorvex_security_events_first_seen_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == "fs-quiet" && labels["trust"] == "trusted" && m.GetCounter().GetValue() == 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("PublishTick did not expose the fs-quiet trusted first-seen series at 0")
	}
}
