package model

import "time"

// WorkloadSpecObservation is read-only replay evidence. It is deliberately
// separate from Pod.DesiredReplicas, whose legacy producer counts observed pods.
// Known distinguishes a measured zero desired count from missing owner data.
// ObservedAt is the sensor snapshot time, not a claimed Kubernetes event time.
type WorkloadSpecObservation struct {
	Known           bool           `json:"known"`
	Reason          string         `json:"reason,omitempty"`
	Source          string         `json:"source"`
	ObservedAt      time.Time      `json:"observed_at"`
	PodUID          string         `json:"pod_uid"`
	Controller      ObjectIdentity `json:"controller"`
	Workload        ObjectIdentity `json:"workload"`
	ResourceVersion string         `json:"resource_version"`
	Generation      int64          `json:"generation"`
	SpecReplicas    int32          `json:"spec_replicas"`
}
