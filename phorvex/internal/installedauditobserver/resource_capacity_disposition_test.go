package installedauditobserver

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestResourceCapacityDispositionRequiresV7AndUnscoredInfeasible(t *testing.T) {
	for _, tc := range []struct {
		name, schema, status string
		scored               *bool
		want                 bool
	}{
		{"v7", model.DecisionTraceSchemaV7, model.ActionStatusInfeasible, boolPtr(false), true},
		{"historical-v6", model.DecisionTraceSchemaV6, model.ActionStatusInfeasible, boolPtr(false), false},
		{"wrong-status", model.DecisionTraceSchemaV7, model.ActionStatusNoCover, boolPtr(false), false},
		{"scored", model.DecisionTraceSchemaV7, model.ActionStatusInfeasible, boolPtr(true), false},
		{"missing-scored", model.DecisionTraceSchemaV7, model.ActionStatusInfeasible, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeActionDisposition(tc.schema, tc.status, model.ExclusionResourceCapacity, tc.scored); got != tc.want {
				t.Fatalf("safeActionDisposition(%q,%q,resource-capacity,%v)=%v, want %v", tc.schema, tc.status, tc.scored, got, tc.want)
			}
		})
	}
}

func boolPtr(value bool) *bool { return &value }
