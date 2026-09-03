package decision

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// PHORVEXSEC-194 / M-104 (ruling Q4, Zeinab's review): the decision trace must record the
// EPSS pair's PRESENCE explicitly — as inputs.epss.present / inputs.epssMultiplier.present —
// alongside the raw score, cvss, multiplier, reason and the feed-run time (epssScanTS).
func TestTraceRecordsEPSSPresenceExplicitly(t *testing.T) {
	pol := covPolicy(2)
	pol.TraceEnabled = true
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	hit := covView("hit", true, 2*time.Hour, false)
	hit.Physics = model.NeutralPhysics()
	hit.Physics.Scanned = true
	hit.Physics.EPSSPresent, hit.Physics.EPSSScore, hit.Physics.CVSS = true, 0.5, 5
	hit.Physics.EPSSMultiplier = 1.25
	hit.Physics.EPSSBasis, hit.Physics.EPSSScanTS = "exact", "2026-09-01T03:17:00Z"
	miss := covView("miss", true, 2*time.Hour, false)
	miss.Physics = model.NeutralPhysics()
	miss.Physics.Scanned = true
	miss.Physics.EPSSReason, miss.Physics.EPSSBasis = "absent", "miss"

	for _, d := range e.Decide([]*model.WorkloadView{hit, miss}, pol) {
		if d.Trace == nil {
			t.Fatalf("%s: trace missing", d.Pod)
		}
		raw, err := json.Marshal(d.Trace.Inputs)
		if err != nil {
			t.Fatal(err)
		}
		js := string(raw)
		switch d.Pod {
		case "hit":
			for _, want := range []string{`"epss":{"present":true,"value":0.5}`, `"cvss":{"present":true,"value":5}`, `"epssMultiplier":{"present":true,"value":1.25}`, `"epssScanTS":"2026-09-01T03:17:00Z"`, `"epssBasis":"exact"`} {
				if !strings.Contains(js, want) {
					t.Fatalf("hit trace lacks %s:\n%s", want, js)
				}
			}
			if strings.Contains(js, `"epssReason"`) {
				t.Fatalf("a present pair must carry no reason:\n%s", js)
			}
		case "miss":
			for _, want := range []string{`"epss":{"present":false,"value":0}`, `"epssMultiplier":{"present":false,"value":1}`, `"epssReason":"absent"`, `"epssBasis":"miss"`} {
				if !strings.Contains(js, want) {
					t.Fatalf("miss trace lacks %s:\n%s", want, js)
				}
			}
		}
	}
}
