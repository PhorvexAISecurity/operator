/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func dur(d time.Duration) metav1.Duration { return metav1.Duration{Duration: d} }

// The per-service switch. An existing policy carries none of the budget fields,
// and must therefore report unconfigured — that is what keeps the budget path off
// and today's decisions unchanged.
func TestBudgetsAreUnconfiguredOnAnExistingPolicy(t *testing.T) {
	s := &PhorvexPolicySpec{SLO: SLOSpec{P99Ms: 250, MinAvailableReplicas: 2}}
	if s.BudgetsConfigured() {
		t.Fatal("a policy with only thresholds must not look budget-configured")
	}
}

// A window on its own is not a budget: there is still no denominator.
func TestWindowAloneIsNotEnough(t *testing.T) {
	s := &PhorvexPolicySpec{SLO: SLOSpec{Window: dur(720 * time.Hour)}}
	if s.BudgetsConfigured() {
		t.Fatal("a window with no budget in it is not configuration")
	}
}

// Nor is a budget without a window: a budget is meaningless without the span it
// is spent over.
func TestBudgetWithoutWindowIsNotEnough(t *testing.T) {
	s := &PhorvexPolicySpec{SLO: SLOSpec{DisruptionBudgetReplicaSeconds: 600}}
	if s.BudgetsConfigured() {
		t.Fatal("a budget with no window is not configuration")
	}
}

func TestAnyOneDimensionInAWindowConfiguresTheService(t *testing.T) {
	w := dur(720 * time.Hour)
	for name, slo := range map[string]SLOSpec{
		"availability": {Window: w, AvailabilityBudget: dur(30 * time.Minute)},
		"disruption":   {Window: w, DisruptionBudgetReplicaSeconds: 600},
		"latency":      {Window: w, LatencyBudget: "0.01"},
	} {
		s := &PhorvexPolicySpec{SLO: slo}
		if !s.BudgetsConfigured() {
			t.Fatalf("%s: expected configured", name)
		}
	}
}

// The reserve comes off the TOTAL, then consumption is subtracted:
// usable = (1 - reserve) * total - consumed.
func TestUsableBudgetTakesReserveFromTheTotal(t *testing.T) {
	s := &PhorvexPolicySpec{SLO: SLOSpec{ReserveFraction: "0.2"}}
	// 20% of 1000 is withheld, leaving 800, less 300 already spent.
	if got, want := s.UsableBudget(1000, 300), 500.0; got != want {
		t.Fatalf("usable = %v, want %v", got, want)
	}
	// Taking the reserve off the REMAINDER instead would have given
	// 0.8*(1000-300) = 560, which reserves less the more the budget burns.
	if got := s.UsableBudget(1000, 300); got == 560 {
		t.Fatal("reserve was applied to the remainder, not the total")
	}
}

func TestUsableBudgetNeverGoesNegative(t *testing.T) {
	s := &PhorvexPolicySpec{}
	if got := s.UsableBudget(100, 250); got != 0 {
		t.Fatalf("an overspent budget is empty, not owed: got %v", got)
	}
}

func TestReserveFractionRejectsNonsense(t *testing.T) {
	for _, in := range []string{"", "abc", "-0.5", "1", "1.5"} {
		s := &PhorvexPolicySpec{SLO: SLOSpec{ReserveFraction: in}}
		if got := s.EffectiveReserveFraction(); got != 0 {
			t.Fatalf("reserveFraction %q: expected no reserve, got %v", in, got)
		}
	}
	s := &PhorvexPolicySpec{SLO: SLOSpec{ReserveFraction: "0.25"}}
	if got, want := s.EffectiveReserveFraction(), 0.25; got != want {
		t.Fatalf("reserveFraction = %v, want %v", got, want)
	}
}

// No code defaults for budgets. An invented denominator would make every ratio
// look authoritative while meaning nothing.
func TestUnsetBudgetsHaveNoInventedDefault(t *testing.T) {
	s := &PhorvexPolicySpec{}
	if s.SLO.Window.Duration != 0 ||
		s.SLO.AvailabilityBudget.Duration != 0 ||
		s.SLO.DisruptionBudgetReplicaSeconds != 0 ||
		s.SLO.LatencyBudget != "" {
		t.Fatal("budget fields must stay zero when unset")
	}
	if s.EffectiveReserveFraction() != 0 {
		t.Fatal("reserve must default to nothing withheld")
	}
}
