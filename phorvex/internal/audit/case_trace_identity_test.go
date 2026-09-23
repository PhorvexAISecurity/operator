package audit

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestCaseTraceGenericEventAuditProjectionRedactsAndPreservesIdentity(t *testing.T) {
	in := model.EventEvidence{
		Name: "owned-signal", EventUID: "event-uid", Source: "detector api_key=private-source", Type: "Panic",
		ThreatLevel: "critical", TrustVerdict: "trusted", CreatorIdentity: "detector token=private-creator",
		TargetPodUID: "pod-uid", TargetsPod: true, AgeSec: 1.234567, Weight: 0.987654, TimestampPresent: true,
	}
	got := roundEvents([]model.EventEvidence{in})
	if len(got) != 1 {
		t.Fatalf("events=%+v", got)
	}
	e := got[0]
	if strings.Contains(e.Source, "private-source") || strings.Contains(e.CreatorIdentity, "private-creator") ||
		!strings.Contains(e.Source, "[REDACTED]") || !strings.Contains(e.CreatorIdentity, "[REDACTED]") {
		t.Fatalf("generic event strings were not redacted: %+v", e)
	}
	if e.Name != in.Name || e.EventUID != in.EventUID || e.TargetPodUID != in.TargetPodUID || !e.TargetsPod || !e.TimestampPresent ||
		e.AgeSec != 1.2346 || e.Weight != 0.9877 {
		t.Fatalf("audit projection changed identity or numeric evidence: %+v", e)
	}
}
