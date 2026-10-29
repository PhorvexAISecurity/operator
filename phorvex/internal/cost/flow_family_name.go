package cost

import "github.com/phorvex/phorvex/internal/model"

// ActionFlowFamily names the flow-cost family an action is routed to. It is a read-only
// view of flowFamilyForAction for exports; the routing table itself is unchanged.
func ActionFlowFamily(action model.Action) string {
	switch flowFamilyForAction(action) {
	case flowNone:
		return "none"
	case flowRespawn:
		return "respawn"
	case flowQuarantine:
		return "quarantine"
	case flowCutover:
		return "cutover"
	case flowKVResetMeasured:
		return "kv-reset-measured"
	case flowServingState:
		return "serving-state"
	case flowLightweight:
		return "lightweight"
	case flowStatefulRecovery:
		return "stateful-recovery"
	default:
		return "unknown"
	}
}
