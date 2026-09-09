package audit

import (
	"encoding/json"
	"io"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var persistenceErrors = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "phorvex_audit_persistence_errors_total",
	Help: "Observed failed audit record persistence attempts, not a census of missing records.",
})

func init() { crmetrics.Registry.MustRegister(persistenceErrors) }

// writeRecord serializes routing, writing, flushing and synchronization in this
// process. Only sinks exposing Sync can acknowledge synchronized persistence.
// Errors are returned and also reported independently of the audit file, including
// for callers that do not consume the return value. This does not gate mutations.
func (l *Logger) writeRecord(tenant string, rec any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.jsonOut
	if l.sinkFor != nil {
		if w := l.sinkFor(tenant); w != nil {
			out = w
		}
	}
	if out == nil {
		return nil
	}
	b, err := json.Marshal(rec)
	if err == nil {
		b = append(b, '\n')
		var n int
		n, err = out.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		if f, ok := out.(interface{ Flush() error }); ok {
			err = f.Flush()
		}
	}
	if err == nil {
		if s, ok := out.(interface{ Sync() error }); ok {
			err = s.Sync()
		}
	}
	if err != nil {
		persistenceErrors.Inc()
		l.log.Error(err, "audit persistence failed", "tenant", tenant)
	}
	return err
}
