/*
 * Phorvex — P-VCLUSTER O10: per-tenant audit isolation. A noisy tenant's volume (and its rotation)
 * must never evict or mix into another tenant's audit history.
 */

package audit

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

func TestO10_PerTenantAuditIsolation(t *testing.T) {
	sinks := map[string]*bytes.Buffer{"quiet": {}, "noisy": {}}
	router := func(tenant string) io.Writer {
		if b, ok := sinks[tenant]; ok {
			return b
		}
		return nil
	}
	l := New(logr.Discard(), nil)
	l.SetTenantSink(router)

	// the quiet tenant records a small, valuable audit history.
	for i := 0; i < 3; i++ {
		l.Record(model.Decision{Tenant: "quiet", Namespace: "q", Pod: fmt.Sprintf("p%d", i), Action: model.ActionRotate, Selected: true})
	}
	// the noisy tenant floods (on a SHARED sink + rotation this would evict the quiet history).
	for i := 0; i < 10_000; i++ {
		l.Record(model.Decision{Tenant: "noisy", Namespace: "n", Pod: fmt.Sprintf("p%d", i), Action: model.ActionRotate, Selected: true})
	}

	// the quiet tenant's history is INTACT (the flood went to the noisy sink, never the quiet one).
	if got := strings.Count(sinks["quiet"].String(), "\n"); got != 3 {
		t.Errorf("O10: quiet tenant's audit history must be intact (3 records); got %d — a noisy tenant evicted it", got)
	}
	// and there is NO cross-tenant mixing.
	if strings.Contains(sinks["quiet"].String(), `"tenant":"noisy"`) {
		t.Error("O10: a noisy tenant's record appeared in the quiet tenant's sink (cross-tenant audit mixing)")
	}
	if strings.Contains(sinks["noisy"].String(), `"tenant":"quiet"`) {
		t.Error("O10: a quiet tenant's record appeared in the noisy tenant's sink (cross-tenant audit mixing)")
	}
}

// Single-tenant / no-router default stays byte-identical: records go to the single shared sink.
func TestO10_DefaultSingleSinkUnchanged(t *testing.T) {
	var buf bytes.Buffer
	l := New(logr.Discard(), &buf) // no SetTenantSink => legacy single-sink path
	l.Record(model.Decision{Tenant: "only", Namespace: "ns", Pod: "p", Action: model.ActionRotate, Selected: true})
	if !strings.Contains(buf.String(), `"tenant":"only"`) {
		t.Errorf("default single-sink must still write to jsonOut: %q", buf.String())
	}
}
