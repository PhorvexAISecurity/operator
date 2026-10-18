package model

// Node, Service and telemetry-source observations the sensor shares with the
// dispatcher (ADR-0001). They live here so the dispatcher needs no sensor package.

// NodeInfo is the conservation-law substrate per node (allocatable vs the pods bound to
// it). GPU/MIG resource counts are integer device-plugin resources (measurable on kind
// with the device plugin; absent => 0).
type NodeInfo struct {
	Name                string
	AllocatableCPUMilli int64
	AllocatableMemBytes int64
	AllocatableGPU      int64
	MIGResources        map[string]int64  // nvidia.com/mig-* -> count (legal-partition geometry)
	Labels              map[string]string // node labels (instance-type / cloud markers; within the existing `list nodes` RBAC — no privilege delta)
	Schedulable         bool              // Ready and not spec.unschedulable
}

// ServiceInfo is the minimum read-only Service projection needed by capability status.
type ServiceInfo struct {
	Namespace string
	Name      string
	UID       string
	Selector  map[string]string
}

// SourceHealth is the per-tick verdict on a telemetry SOURCE (M-113/M-130): how many signal
// queries ran, how many failed, and the reason when the source as a whole is down. A source
// with every query failed is unreachable even if partial last-good data exists.
type SourceHealth struct {
	Source string
	Total  int
	Failed int
	// Reason is ReasonSourceUnreachable when Failed == Total > 0; "" when healthy or
	// only partially failed.
	Reason string
}

// Unreachable reports a whole-source failure this tick.
func (h SourceHealth) Unreachable() bool { return h.Total > 0 && h.Failed == h.Total }
