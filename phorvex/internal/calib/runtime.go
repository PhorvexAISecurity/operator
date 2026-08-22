/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	DefaultRefreshInterval = 30 * time.Minute
	DefaultSampleInterval  = 5 * time.Minute
	DefaultLookback        = 7 * 24 * time.Hour
	DefaultPercentile      = 0.95
	DefaultSaturationLimit = 0.10
	DefaultPersistence     = 3
)

var (
	DefaultPercentileGrid = []float64{0.90, 0.95, 0.975, 0.99}
	DefaultReadyGrid      = []float64{0.50, 0.75, 0.90, 0.95, 0.975, 0.99}
	DefaultCadences       = []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}
)

// RuntimeConfig controls the shadow runner. Learned values never enter production scoring.
type RuntimeConfig struct {
	RefreshInterval time.Duration
	SampleInterval  time.Duration
	Lookback        time.Duration
	ExportDir       string
	MinObservations int
	CoPercentile    float64
	DispPercentile  float64
	ReadyPercentile float64
	SaturationLimit float64
	Persistence     int
}

func (c RuntimeConfig) withDefaults() RuntimeConfig {
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = DefaultRefreshInterval
	}
	if c.SampleInterval <= 0 {
		c.SampleInterval = DefaultSampleInterval
	}
	if c.Lookback <= 0 {
		c.Lookback = DefaultLookback
	}
	if c.MinObservations <= 0 {
		c.MinObservations = 1
	}
	if c.CoPercentile <= 0 {
		c.CoPercentile = DefaultPercentile
	}
	if c.DispPercentile <= 0 {
		c.DispPercentile = DefaultPercentile
	}
	if c.ReadyPercentile <= 0 {
		c.ReadyPercentile = DefaultPercentile
	}
	if c.SaturationLimit <= 0 {
		c.SaturationLimit = DefaultSaturationLimit
	}
	if c.Persistence <= 0 {
		c.Persistence = DefaultPersistence
	}
	return c
}

// JointSweepRow evaluates one pair of co-residency and dispersion percentiles jointly.
type JointSweepRow struct {
	CoPercentile          float64 `json:"coPercentile"`
	DispersionPercentile  float64 `json:"dispersionPercentile"`
	CoScale               float64 `json:"coScale"`
	DispersionCap         float64 `json:"dispersionCap"`
	CoAtCeilingRatio      float64 `json:"coAtCeilingRatio"`
	DispAtCeilingRatio    float64 `json:"dispersionAtCeilingRatio"`
	DispStrictlyClipped   float64 `json:"dispersionStrictlyClippedRatio"`
	DistinctCapped        int     `json:"distinctCapped"`
	ClearsSaturationLimit bool    `json:"clearsSaturationLimit"`
}

// SweepJoint evaluates the ticket's percentile grid without activating any result.
func SweepJoint(nodes []NodeObservation, assets []AssetObservation, ps []float64, minObservations int, threshold float64, at time.Time) []JointSweepRow {
	rows := make([]JointSweepRow, 0, len(ps)*len(ps))
	for _, cp := range ps {
		for _, dp := range ps {
			j := CalibrateJoint(nodes, assets, cp, dp, minObservations, at)
			rows = append(rows, JointSweepRow{
				CoPercentile: cp, DispersionPercentile: dp,
				CoScale: j.CoResidency.Value, DispersionCap: j.Dispersion.Value,
				CoAtCeilingRatio:    j.CoResidency.Clip.AtCeilingRatio(),
				DispAtCeilingRatio:  j.Dispersion.Clip.AtCeilingRatio(),
				DispStrictlyClipped: j.Dispersion.Clip.StrictlyClippedRatio(),
				DistinctCapped:      j.DistinctCapped,
				ClearsSaturationLimit: j.CoResidency.Clip.AtCeilingRatio() <= threshold &&
					j.Dispersion.Clip.AtCeilingRatio() <= threshold,
			})
		}
	}
	return rows
}

// RefreshResult is the complete reproducible evidence from one shadow refresh.
type RefreshResult struct {
	GeneratedAt    time.Time
	EvidenceSource string
	EvidenceNote   string
	Nodes          []NodeObservation
	Assets         []AssetObservation
	Rotations      []RotationRecord
	Comparisons    []SelectionComparison
	Joint          JointReport
	ReadyDelay     ReadyDelayReport
	JointSweep     []JointSweepRow
	Cadence        []CadenceRow
}

// Runtime owns snapshot history, rotation outcomes, metrics, and raw export for the shadow path.
type Runtime struct {
	mu      sync.Mutex
	config  RuntimeConfig
	tracker *Tracker
	log     logr.Logger

	lastSample          time.Time
	lastRefresh         time.Time
	samples             []CadenceSample
	rotations           []RotationRecord
	pending             []SelectionComparison
	pendingAvailability int
	pendingSLO          int
	latest              RefreshResult
}

func NewRuntime(config RuntimeConfig, log logr.Logger) *Runtime {
	config = config.withDefaults()
	Register()
	return &Runtime{
		config: config, tracker: NewTracker(config.SaturationLimit, config.Persistence),
		log: log.WithName("calibration-shadow"),
	}
}

// Due reports whether a cluster snapshot is needed for the five-minute evidence sample.
func (r *Runtime) Due(now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSample.IsZero() || !now.Before(r.lastSample.Add(r.config.SampleInterval))
}

// ObserveRotation stores one raw outcome. The production normalizer is not changed.
func (r *Runtime) ObserveRotation(record RotationRecord) {
	if r == nil {
		return
	}
	if record.RecordedAt.IsZero() {
		switch {
		case !record.ReadyAt.IsZero():
			record.RecordedAt = record.ReadyAt
		case !record.CensorDeadline.IsZero():
			record.RecordedAt = record.CensorDeadline
		default:
			record.RecordedAt = record.StartedAt
		}
	}
	r.mu.Lock()
	r.rotations = append(r.rotations, record)
	r.mu.Unlock()
}

// ObserveValidation adds a production-vs-shadow optimizer comparison and hard-safety outcomes
// to the next cadence sample. Missing comparisons remain explicitly unavailable.
func (r *Runtime) ObserveValidation(comparison SelectionComparison, availabilityViolations, sloViolations int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	comparison.AvailabilityViolations = availabilityViolations
	comparison.SLOViolations = sloViolations
	r.pending = append(r.pending, comparison)
	r.pendingAvailability += availabilityViolations
	r.pendingSLO += sloViolations
	r.mu.Unlock()
}

func recordTime(record RotationRecord) time.Time {
	if !record.RecordedAt.IsZero() {
		return record.RecordedAt
	}
	if !record.ReadyAt.IsZero() {
		return record.ReadyAt
	}
	return record.StartedAt
}

// ObserveSnapshot samples history and, when due, performs a 30-minute shadow refresh.
func (r *Runtime) ObserveSnapshot(snap *ingest.Snapshot, witness map[string]model.PhysicsWitness) (RefreshResult, bool, error) {
	if r == nil || snap == nil {
		return RefreshResult{}, false, fmt.Errorf("calibration snapshot is nil")
	}
	now := snap.Now
	if now.IsZero() {
		return RefreshResult{}, false, fmt.Errorf("calibration snapshot has no observation time")
	}
	nodes := NodesFromSnapshot(snap)
	assets := AssetsFromSnapshot(snap, witness)

	r.mu.Lock()
	if !r.lastSample.IsZero() && now.Before(r.lastSample.Add(r.config.SampleInterval)) {
		latest := r.latest
		r.mu.Unlock()
		return latest, false, nil
	}
	cutoff := now.Add(-r.config.Lookback)
	keptRotations := r.rotations[:0]
	var newRotations []RotationRecord
	for _, record := range r.rotations {
		at := recordTime(record)
		if at.Before(cutoff) {
			continue
		}
		keptRotations = append(keptRotations, record)
		if r.lastSample.IsZero() || at.After(r.lastSample) {
			newRotations = append(newRotations, record)
		}
	}
	r.rotations = keptRotations
	r.samples = append(r.samples, CadenceSample{
		At: now, Nodes: nodes, Assets: assets, ReadyDelay: newRotations,
		OptimizerComparisons:   append([]SelectionComparison(nil), r.pending...),
		AvailabilityViolations: r.pendingAvailability, SLOViolations: r.pendingSLO,
	})
	r.pending = nil
	r.pendingAvailability, r.pendingSLO = 0, 0
	keptSamples := r.samples[:0]
	for _, sample := range r.samples {
		if !sample.At.Before(cutoff) {
			keptSamples = append(keptSamples, sample)
		}
	}
	r.samples = keptSamples
	r.lastSample = now
	if !r.lastRefresh.IsZero() && now.Before(r.lastRefresh.Add(r.config.RefreshInterval)) {
		latest := r.latest
		r.mu.Unlock()
		return latest, false, nil
	}
	r.lastRefresh = now
	rotations := append([]RotationRecord(nil), r.rotations...)
	history := append([]CadenceSample(nil), r.samples...)
	r.mu.Unlock()
	var comparisons []SelectionComparison
	for _, sample := range history {
		comparisons = append(comparisons, sample.OptimizerComparisons...)
	}

	joint := CalibrateJoint(nodes, assets, r.config.CoPercentile, r.config.DispPercentile, r.config.MinObservations, now)
	ready := CalibrateReadyDelay(rotations, DefaultReadyGrid, r.config.ReadyPercentile, now)
	result := RefreshResult{
		GeneratedAt: now, EvidenceSource: "runtime_cluster_snapshot",
		EvidenceNote: "collected by the running operator from its Kubernetes snapshot; learned values remain shadow-only",
		Nodes:        nodes, Assets: assets, Rotations: rotations, Comparisons: comparisons,
		Joint: joint, ReadyDelay: ready,
		JointSweep: SweepJoint(nodes, assets, DefaultPercentileGrid, r.config.MinObservations, r.config.SaturationLimit, now),
		Cadence:    EvaluateCadence(history, DefaultCadences, r.config.CoPercentile, r.config.DispPercentile, r.config.MinObservations, r.config.SaturationLimit),
	}
	r.tracker.ObserveScaleWithInvalid(joint.CoResidency, now, len(nodes)-joint.CoResidency.Clip.N)
	r.tracker.ObserveScaleWithInvalid(joint.Dispersion, now, len(snap.Pods)-len(assets))
	r.tracker.ObserveReadyDelay(ready, now)

	r.mu.Lock()
	r.latest = result
	r.mu.Unlock()

	var exportErr error
	if r.config.ExportDir != "" {
		exportErr = Export(r.config.ExportDir, result)
	}
	r.log.Info("shadow scale refresh",
		"coResidency", joint.CoResidency.Value, "coSource", joint.CoResidency.Source,
		"dispersion", joint.Dispersion.Value, "dispSource", joint.Dispersion.Source,
		"readyDelaySeconds", ready.Reference.Value, "readySource", ready.Reference.Source,
		"assets", len(assets), "nodes", len(nodes), "rotations", len(rotations))
	return result, true, exportErr
}

func (r *Runtime) Latest() RefreshResult {
	if r == nil {
		return RefreshResult{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest
}

// ShadowViews returns cloned workload views with the latest measured co-residency scale and
// dispersion cap. Production views are never mutated. A refresh must exist before a comparison
// is available; fallback scales still produce an explicit equal-to-production comparison.
func (r *Runtime) ShadowViews(views []*model.WorkloadView) ([]*model.WorkloadView, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	latest := r.latest
	r.mu.Unlock()
	if latest.GeneratedAt.IsZero() {
		return nil, false
	}
	namespaces := make(map[string]int, len(latest.Assets))
	for _, asset := range latest.Assets {
		namespaces[asset.Key] = asset.Namespaces
	}
	out := make([]*model.WorkloadView, 0, len(views))
	for _, view := range views {
		if view == nil {
			continue
		}
		clone := *view
		key := clone.Pod.Namespace + "/" + clone.Pod.Name
		namespaceCount, observed := namespaces[key]
		if !observed {
			out = append(out, &clone)
			continue
		}
		x := float64(namespaceCount - 1)
		if x < 0 {
			x = 0
		}
		clone.Physics.CoResidency = CoResidencyMultiplier(x, latest.Joint.CoResidency.Value)
		clone.Physics.DispersionCap = latest.Joint.Dispersion.Value
		out = append(out, &clone)
	}
	return out, true
}

// RotationRecords returns a lookback-filtered copy for tests, console/reporting, and audits.
func (r *Runtime) RotationRecords(now time.Time) []RotationRecord {
	if r == nil {
		return nil
	}
	cutoff := now.Add(-r.config.Lookback)
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RotationRecord, 0, len(r.rotations))
	for _, record := range r.rotations {
		if !recordTime(record).Before(cutoff) {
			out = append(out, record)
		}
	}
	return out
}

func sortedSelection(keys []string) []string {
	out := append([]string(nil), keys...)
	sort.Strings(out)
	return out
}
