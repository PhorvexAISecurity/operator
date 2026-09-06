/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package ingest is the SIGNAL INGEST layer (PRD FR1): Prometheus metrics, the
// SecurityEvent CR stream, and the K8s graph (pods/labels/NetworkPolicy/RBAC/
// nodes/MIG). It projects live objects into the dependency-free model types the
// graph and decision engine consume.
package ingest

import (
	"context"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// MetricsSource is the swappable telemetry backend (FR1 Prometheus ingest). It is a
// registry member like the other Phorvex surfaces so a site can plug a different TSDB
// in one file. The default is the honest nil source (no backend => Telemetry.Present
// false; Phorvex NEVER fabricates a metric).
type MetricsSource interface {
	registry.Named
	// PodMetrics returns best-effort telemetry keyed by pod name for the given
	// namespace. A pod with no data is simply absent from the map.
	PodMetrics(ctx context.Context, namespace string, podNames []string) (map[string]model.Telemetry, error)
}

// SourceHealth is the per-tick verdict on a telemetry SOURCE (M-113/M-130): how many signal
// queries ran, how many failed, and the reason when the source as a whole is down. A source
// with every query failed is unreachable even if partial last-good data exists.
type SourceHealth struct {
	Source string
	Total  int
	Failed int
	// Reason is model.ReasonSourceUnreachable when Failed == Total > 0; "" when healthy or
	// only partially failed.
	Reason string
}

// Unreachable reports a whole-source failure this tick.
func (h SourceHealth) Unreachable() bool { return h.Total > 0 && h.Failed == h.Total }

// HealthReporter is implemented by sources that can report their last tick's health.
type HealthReporter interface {
	LastHealth() SourceHealth
}

// SourceRegistry holds the registered metrics sources.
var SourceRegistry = registry.New[MetricsSource]()

// absentSource is the explicit default: no telemetry backend configured.
type absentSource struct{}

func (absentSource) Name() string { return "none" }

func (absentSource) PodMetrics(_ context.Context, _ string, _ []string) (map[string]model.Telemetry, error) {
	return map[string]model.Telemetry{}, nil
}

func init() { SourceRegistry.Register(absentSource{}) }
