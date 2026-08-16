package console

import (
	"strings"
	"testing"
)

// scenario_claims_test.go — PHVX-25a/26a item 4 (PHORVEXSEC-117 / PHORVEXSEC-121).
//
// The scenario metadata is customer-facing: it tells an operator which actuator answers which
// attack. Naming an action that cannot deliver is a claim, and it is read far more often than any
// report appendix. Neither warm-swap nor mig-rebind breaks GPU co-location on this fleet.

func TestCoLocationHasNoFalseRemedy(t *testing.T) {
	for _, scenario := range []string{"ai2-co-location-cross-tenant", "gpu-co-location", "co-location"} {
		got := expectedActuatorsFor(scenario)
		for _, a := range got {
			if a == "warm-swap" {
				t.Errorf("scenario %q offers warm-swap as a co-location remedy. Nothing constrains "+
					"where the scheduler places the shadow, so it may land on the same device — "+
					"PHVX-26a withdrew its co-residency cover for exactly this reason.", scenario)
			}
		}
		if len(got) > 0 && strings.Contains(scenario, "co-location") {
			t.Errorf("scenario %q names remedies %v, but co-residency is a PROVISIONING property "+
				"with no autonomous moving-target answer today", scenario, got)
		}
	}
}

// TestSideChannelRemedyIsMigRebindOnly pins the narrow true claim: mig-rebind severs the contention
// path, warm-swap does not address it at all.
func TestSideChannelRemedyIsMigRebindOnly(t *testing.T) {
	got := expectedActuatorsFor("ai-side-channel-timing")
	if len(got) != 1 || got[0] != "mig-rebind" {
		t.Fatalf("side-channel remedy = %v; want exactly [mig-rebind] — warm-swap performs a "+
			"cold-load-free cutover, which is valuable and unrelated to the contention path", got)
	}
}
