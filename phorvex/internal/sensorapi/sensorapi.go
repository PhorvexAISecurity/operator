// Package sensorapi is the contract between the dispatcher and the sensor
// (ADR-0001): one observation of the cluster per tick, and telemetry per policy.
// An observation is data only; the dispatcher combines it with the state it owns
// (exposure clocks, emit intents, failure cooldowns) to build the brain's views.
// internal/sensorsvc implements the contract in process, and over gRPC once the
// sensor runs as its own service.
package sensorapi

import (
	"context"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// Sensor observes the cluster and its telemetry.
type Sensor interface {
	// Observe takes the tick's cluster observation. An error means no observation:
	// the dispatcher skips the tick.
	Observe(ctx context.Context, req ObserveRequest) (*Observation, error)
	// Telemetry reads the named Pods' telemetry. The result is best effort: a
	// partial scrape still returns what it has, with the error.
	Telemetry(ctx context.Context, req TelemetryRequest) TelemetryResult
}

// Scope is one due policy's selection.
type Scope struct {
	Namespace string
	// Selector is a label selector in labels.Selector string form; empty selects
	// every Pod in the namespace.
	Selector string
}

// ObserveRequest carries the dispatcher's inputs to one observation.
type ObserveRequest struct {
	// Now is the tick time; the observation is stamped with it.
	Now time.Time
	// Scopes are the due policies. Owner evidence is read only for Pods a scope
	// selects.
	Scopes []Scope
	// ResolveOwners reads rotation-owner and warm-pool evidence, which only native
	// rotation consumes.
	ResolveOwners bool
}

// Observation is one tick's view of the cluster.
type Observation struct {
	Now time.Time

	Pods     []model.Pod
	Nodes    []model.NodeInfo
	Services []model.ServiceInfo
	// NamespaceLabels and NamespaceDryRun cover every namespace.
	NamespaceLabels map[string]map[string]string
	NamespaceDryRun map[string]model.ActuationBrakeObservation

	// Events is every SecurityEvent, EventByPod those targeting each Pod
	// ("namespace/name"), and EvidenceEvents the cluster-wide outcome evidence.
	Events          []model.SecurityEventInfo
	EventByPod      map[string][]model.SecurityEventInfo
	EvidenceEvents  []model.SecurityEventInfo
	PhoenixReceipts map[string]model.PhoenixExecutionReceipt

	PodInventoryComplete            bool
	PolicyInventoryComplete         bool
	EventInventoryComplete          bool
	PhoenixReceiptInventoryComplete bool

	// Context is each Pod's graph and event context, keyed "namespace/name".
	Context map[string]PodContext
	// Physics is the discovered physics witness per Pod; a Pod without one gets
	// model.NeutralPhysics. Platform names the adapter that derived it, and
	// GPUWitnessError says why the GPU half is absent when its feed failed.
	Physics         map[string]model.PhysicsWitness
	Platform        string
	GPUWitnessError string

	// PolicyMembership lists, per Pod, the tenants of the PhorvexPolicies whose
	// selector matches it. PolicySelectorsValid is false when a policy's selector
	// could not be parsed, so the membership is incomplete.
	PolicyMembership     map[string][]string
	PolicySelectorsValid bool
}

// PodContext is a Pod's position in the cluster graph and the events around it.
type PodContext struct {
	BlastRadius   float64
	NeighborCount int
	// Neighbors are the Pod's graph neighbours with their generic asset value.
	Neighbors []model.NeighborRef
	// Events are the Pod's own events, then each neighbour's with TargetsPod false.
	Events []model.SecurityEventInfo
	// InfectionFrontier is 1.5 when a neighbour has a high-severity foothold, else 1.
	InfectionFrontier float64
}

// TelemetryRequest names the Pods of one policy.
type TelemetryRequest struct {
	Namespace string
	Pods      []string
}

// TelemetryResult is one policy's telemetry.
type TelemetryResult struct {
	// Configured is false when no telemetry source is wired; nothing else is set.
	Configured bool
	// Telemetry is keyed by Pod name; it may be partial when Error is set.
	Telemetry map[string]model.Telemetry
	// Health is the source's verdict on this read.
	Health model.SourceHealth
	// Error describes a failed or partial read.
	Error string
}
