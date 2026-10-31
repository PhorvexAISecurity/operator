package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type captureSink struct{ items []mathlab.Pending }

func (c *captureSink) Enqueue(p mathlab.Pending) bool { c.items = append(c.items, p); return true }

func stripAuditTime(t *testing.T, raw []byte) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not JSON: %v", err)
		}
		delete(rec, "time")
		b, _ := json.Marshal(rec)
		out = append(out, string(b))
	}
	return out
}

// Recording a tick must not change a single audited decision byte, and the recorded
// snapshot must replay to exactly what production decided.
func TestMathLabCaptureIsNonInterferingAndReplaysTheRunnerTick(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// Production sets the recon default before it builds the engine (NewManagerWithBackend);
	// the shared test helper builds the engine first, so pin the order here.
	recon.Registry.SetDefault("ucw-recon")
	run := func(withCapture bool) ([]string, *captureSink) {
		p := m140Policy("policy", "mathlab-capture", "mathlab-owner")
		p.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate), v1alpha1.ActionType(model.ActionQuarantine)}
		m, engine := m140BlockedTickManager(t, nil, p)
		m.Calibration = nil
		m.CaptureCostEvidence = withCapture
		engine.Now = func() time.Time { return now }
		var auditJSON bytes.Buffer
		m.Audit = audit.New(logr.Discard(), &auditJSON)
		sink := &captureSink{}
		if withCapture {
			rec, err := mathlab.NewRecorder(mathlab.Config{Policies: []string{"ns/policy"},
				GPUEnvelopeMax: cost.GPUEnvelopeMax()}, sink, nil)
			if err != nil {
				t.Fatal(err)
			}
			localServices(m).MathLab = rec
		}
		if err := m.Upsert(p); err != nil {
			t.Fatal(err)
		}
		entry := m.policies[client.ObjectKeyFromObject(p).String()]
		m.processTenant(context.Background(), m131Snapshot(now), entry, false)
		return stripAuditTime(t, auditJSON.Bytes()), sink
	}
	plain, _ := run(false)
	recorded, sink := run(true)
	if len(plain) == 0 || strings.Join(plain, "\n") != strings.Join(recorded, "\n") {
		t.Fatalf("capture changed the audited decisions:\nplain=%v\nrecorded=%v", plain, recorded)
	}
	if len(sink.items) != 1 {
		t.Fatalf("expected one snapshot, got %d", len(sink.items))
	}
	if h := sink.items[0].Header; h.ReconProfile != "ucw-recon" || h.ContextProvider == "" {
		t.Fatalf("snapshot did not record the engine profiles: recon=%q context=%q", h.ReconProfile, h.ContextProvider)
	}
	store, err := mathlab.OpenStore(t.TempDir(), 1<<30, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Enqueue(sink.items[0]) {
		t.Fatal("store queue refused the snapshot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go store.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(store.List(mathlab.ListFilter{})) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	list := store.List(mathlab.ListFilter{})
	if len(list) != 1 || !list[0].Header.Finalized {
		t.Fatalf("snapshot not stored/finalized: %+v", list)
	}
	raw, err := store.Read(list[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := mathlab.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Inputs.EndpointCostEvidence == nil || snap.Inputs.EndpointCostEvidence.EndpointLossStatus != "unavailable" || snap.Inputs.EndpointCostEvidence.Schema != "phorvex.endpoint-cost-evidence.v1" {
		t.Fatalf("manager capture did not reach recorder: %+v", snap.Inputs.EndpointCostEvidence)
	}
	rs, err := mathlab.Replay(snap, mathlab.ReplayOptions{Arms: []mathlab.Arm{{ID: "baseline"}}})
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].Status != mathlab.StatusOK || rs[0].Baseline == nil || !rs[0].Baseline.Reproduced {
		t.Fatalf("runner tick not reproduced: %s %v %+v", rs[0].Status, rs[0].Reasons, rs[0].Baseline)
	}
}
