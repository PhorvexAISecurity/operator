package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Math Lab capture and candidate first-veto metrics. Every label is a closed, bounded
// vocabulary (tenant x action x gate); per-pod identities belong in snapshots, not here.
var (
	candidatesGatedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_candidates_gated_total",
		Help: "Candidate (asset,action) pairs excluded per production tick, by the FIRST vetoing gate (G0..G9). Downstream gates of a vetoed candidate were not evaluated and are not counted.",
	}, []string{"tenant", "action", "first_gate"})
	mathLabSnapshots = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_mathlab_snapshots_total",
		Help: "Math Lab decision snapshots by capture result (queued|dropped_queue_full|dropped_too_large|encode_error|abandoned).",
	}, []string{"result"})
	mathLabCaptureSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "phorvex_mathlab_capture_seconds",
		Help:    "Time the decision tick spent copying inputs and outcomes into a Math Lab snapshot.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
	})
	mathLabSnapshotBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "phorvex_mathlab_snapshot_uncompressed_bytes",
		Help:    "Uncompressed size of one Math Lab snapshot payload.",
		Buckets: prometheus.ExponentialBuckets(16<<10, 2, 12),
	})
	mathLabStoreBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_mathlab_store_bytes", Help: "Bytes held by the Math Lab snapshot store."})
	mathLabStoreFiles = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_mathlab_store_files", Help: "Snapshots held by the Math Lab snapshot store."})
	mathLabStoreEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phorvex_mathlab_store_evicted_total", Help: "Oldest snapshots evicted to keep the store within its byte bound."})
	mathLabStoreWriteFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phorvex_mathlab_store_write_failures_total", Help: "Snapshots that could not be written to the store."})
)

func init() {
	crmetrics.Registry.MustRegister(candidatesGatedTotal, mathLabSnapshots, mathLabCaptureSeconds, mathLabSnapshotBytes,
		mathLabStoreBytes, mathLabStoreFiles, mathLabStoreEvicted, mathLabStoreWriteFailures)
}

// RecordCandidateGated counts one production first-veto exclusion.
func RecordCandidateGated(tenant, action, gate string) {
	if gate == "" {
		gate = "unattributed"
	}
	candidatesGatedTotal.WithLabelValues(tenant, action, gate).Inc()
}

// RecordMathLabCapture records one capture result.
func RecordMathLabCapture(result string, seconds float64, bytes int) {
	mathLabSnapshots.WithLabelValues(result).Inc()
	mathLabCaptureSeconds.Observe(seconds)
	if bytes > 0 {
		mathLabSnapshotBytes.Observe(float64(bytes))
	}
}

// RecordMathLabStore records the store state after one write attempt.
func RecordMathLabStore(files int, bytes int64, evicted int, failed bool) {
	if failed {
		mathLabStoreWriteFailures.Inc()
	} else {
		mathLabStoreFiles.Set(float64(files))
		mathLabStoreBytes.Set(float64(bytes))
	}
	if evicted > 0 {
		mathLabStoreEvicted.Add(float64(evicted))
	}
}
