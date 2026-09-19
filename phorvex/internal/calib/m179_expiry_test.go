package calib

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func m179Snapshot(at time.Time, tag string) (*ingest.Snapshot, map[string]model.PhysicsWitness) {
	node := "node-" + tag
	pod := model.Pod{Namespace: "tenant-" + tag, Name: "pod-" + tag, Node: node, Phase: "Running", HasGPU: true}
	key := pod.Namespace + "/" + pod.Name
	return &ingest.Snapshot{
			Now: at, Nodes: []ingest.NodeInfo{{Name: node, Schedulable: true}}, Pods: []model.Pod{pod},
		}, map[string]model.PhysicsWitness{
			key: {Scanned: true, ImageRarity: 1.25, EPSSMultiplier: 1.5, ModelRarity: 1.75},
		}
}

func m179Comparison(at time.Time, tag string) SelectionComparison {
	return SelectionComparison{
		At: at, Tenant: "tenant-" + tag,
		Production: []string{"prod-" + tag}, Shadow: []string{"shadow-" + tag},
		ProductionScores: []DecisionScore{{Key: "prod-score-" + tag, Action: "rotate", Selected: true, CoverageValue: 1, Cost: 2, Net: -1}},
		ShadowScores:     []DecisionScore{{Key: "shadow-score-" + tag, Action: "warm-swap", CoverageValue: 3, Cost: 1, Net: 2}},
	}
}

func m179Rotation(at time.Time, tag string) RotationRecord {
	return RotationRecord{
		ID: "rotation-" + tag, Tenant: "tenant-" + tag, Namespace: "namespace-" + tag,
		Pod: "pod-" + tag, Action: "rotate", StartedAt: at.Add(-time.Minute), RecordedAt: at,
		ReadyAt: at, Elapsed: time.Minute, Outcome: OutcomeObserved, ReferenceAtStart: 2 * time.Minute,
	}
}

func m179JSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func m179Observe(t *testing.T, runtime *Runtime, at time.Time, tag string) RefreshResult {
	t.Helper()
	runtime.ObserveValidation(m179Comparison(at, tag), len(tag), len(tag)+1)
	snapshot, witnesses := m179Snapshot(at, tag)
	result, refreshed, err := runtime.ObserveSnapshot(snapshot, witnesses)
	if err != nil || !refreshed {
		t.Fatalf("observe %s: refreshed=%v err=%v", tag, refreshed, err)
	}
	return result
}

func m179TailIsClear(t *testing.T, runtime *Runtime) {
	t.Helper()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for i, sample := range runtime.samples[len(runtime.samples):cap(runtime.samples)] {
		if !reflect.DeepEqual(sample, CadenceSample{}) {
			t.Fatalf("sample tail slot %d retained references: %+v", len(runtime.samples)+i, sample)
		}
	}
	for i, rotation := range runtime.rotations[len(runtime.rotations):cap(runtime.rotations)] {
		if !reflect.DeepEqual(rotation, RotationRecord{}) {
			t.Fatalf("rotation tail slot %d retained references: %+v", len(runtime.rotations)+i, rotation)
		}
	}
}

// This drives the real Runtime producers through two expiry boundaries. It checks
// strict-before cutoff semantics, stable order/content, released backing slots, and
// that clearing a discarded slot never clears nested data shared by returned results.
func TestM179RuntimeReleasesExpiredSlotsWithoutChangingRetainedEvidence(t *testing.T) {
	base := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	runtime := NewRuntime(RuntimeConfig{
		RefreshInterval: 5 * time.Minute, SampleInterval: 5 * time.Minute,
		Lookback: 10 * time.Minute, MinObservations: 1,
	}, logr.Discard())

	m179Observe(t, runtime, base, "oldest")
	runtime.ObserveRotation(m179Rotation(base.Add(5*time.Minute), "expired"))
	m179Observe(t, runtime, base.Add(5*time.Minute), "expired")
	runtime.ObserveRotation(m179Rotation(base.Add(10*time.Minute), "exact"))
	m179Observe(t, runtime, base.Add(10*time.Minute), "exact")
	runtime.ObserveRotation(m179Rotation(base.Add(15*time.Minute), "retained"))
	returnedBeforeExpiry := m179Observe(t, runtime, base.Add(15*time.Minute), "retained")
	returnedBeforeExpiryBytes := m179JSON(t, returnedBeforeExpiry)

	runtime.mu.Lock()
	var exactSampleBefore, retainedSampleBefore []byte
	for _, sample := range runtime.samples {
		switch sample.At {
		case base.Add(10 * time.Minute):
			exactSampleBefore = m179JSON(t, sample)
		case base.Add(15 * time.Minute):
			retainedSampleBefore = m179JSON(t, sample)
		}
	}
	var exactRotationBefore, retainedRotationBefore []byte
	for _, rotation := range runtime.rotations {
		switch rotation.ID {
		case "rotation-exact":
			exactRotationBefore = m179JSON(t, rotation)
		case "rotation-retained":
			retainedRotationBefore = m179JSON(t, rotation)
		}
	}
	runtime.mu.Unlock()
	if len(exactSampleBefore) == 0 || len(retainedSampleBefore) == 0 || len(exactRotationBefore) == 0 || len(retainedRotationBefore) == 0 {
		t.Fatal("fixture did not capture exact-cutoff and retained evidence before expiry")
	}

	result := m179Observe(t, runtime, base.Add(20*time.Minute), "current")
	if !reflect.DeepEqual(result, runtime.Latest()) {
		t.Fatal("public Latest differs from the completed refresh")
	}
	if got := []string{result.Comparisons[0].Tenant, result.Comparisons[1].Tenant, result.Comparisons[2].Tenant}; !reflect.DeepEqual(got, []string{"tenant-exact", "tenant-retained", "tenant-current"}) {
		t.Fatalf("retained comparisons/order=%v", got)
	}
	if len(result.Rotations) != 2 || result.Rotations[0].ID != "rotation-exact" || result.Rotations[1].ID != "rotation-retained" {
		t.Fatalf("retained rotations/order=%+v", result.Rotations)
	}
	if len(result.Nodes) != 1 || result.Nodes[0].Name != "node-current" || len(result.Assets) != 1 || result.Assets[0].Key != "tenant-current/pod-current" {
		t.Fatalf("current public snapshot nodes=%+v assets=%+v", result.Nodes, result.Assets)
	}
	if !reflect.DeepEqual(m179JSON(t, returnedBeforeExpiry), returnedBeforeExpiryBytes) {
		t.Fatal("expiry corrupted a previously returned refresh result")
	}

	runtime.mu.Lock()
	samples := append([]CadenceSample(nil), runtime.samples...)
	rotations := append([]RotationRecord(nil), runtime.rotations...)
	runtime.mu.Unlock()
	if len(samples) != 3 || len(rotations) != 2 {
		t.Fatalf("compacted lengths samples=%d rotations=%d", len(samples), len(rotations))
	}
	if !reflect.DeepEqual(m179JSON(t, samples[0]), exactSampleBefore) || !reflect.DeepEqual(m179JSON(t, samples[1]), retainedSampleBefore) {
		t.Fatal("retained sample bytes or stable order changed")
	}
	if !reflect.DeepEqual(m179JSON(t, rotations[0]), exactRotationBefore) || !reflect.DeepEqual(m179JSON(t, rotations[1]), retainedRotationBefore) {
		t.Fatal("retained rotation bytes or stable order changed")
	}
	m179TailIsClear(t, runtime)

	// A no-sample call returns the existing evidence unchanged. The next real sample
	// advances the cutoff, safely prunes again, and admits ordinary new evidence.
	beforeNoop := m179JSON(t, result)
	noDueSnapshot, noDueWitnesses := m179Snapshot(base.Add(20*time.Minute+time.Second), "ignored")
	noDue, refreshed, err := runtime.ObserveSnapshot(noDueSnapshot, noDueWitnesses)
	if err != nil || refreshed || !reflect.DeepEqual(m179JSON(t, noDue), beforeNoop) {
		t.Fatalf("no-expiry call changed result: refreshed=%v err=%v", refreshed, err)
	}
	runtime.ObserveRotation(m179Rotation(base.Add(25*time.Minute), "subsequent"))
	subsequent := m179Observe(t, runtime, base.Add(25*time.Minute), "subsequent")
	if got := []string{subsequent.Comparisons[0].Tenant, subsequent.Comparisons[1].Tenant, subsequent.Comparisons[2].Tenant}; !reflect.DeepEqual(got, []string{"tenant-retained", "tenant-current", "tenant-subsequent"}) {
		t.Fatalf("subsequent comparisons/order=%v", got)
	}
	if len(subsequent.Rotations) != 2 || subsequent.Rotations[0].ID != "rotation-retained" || subsequent.Rotations[1].ID != "rotation-subsequent" {
		t.Fatalf("subsequent rotations=%+v", subsequent.Rotations)
	}
	if !reflect.DeepEqual(m179JSON(t, returnedBeforeExpiry), returnedBeforeExpiryBytes) || !reflect.DeepEqual(m179JSON(t, result), beforeNoop) {
		t.Fatal("repeated pruning corrupted an earlier returned result")
	}
	m179TailIsClear(t, runtime)
}

func TestM179RuntimeConcurrentProducersReadersAndCompaction(t *testing.T) {
	base := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	runtime := NewRuntime(RuntimeConfig{
		RefreshInterval: time.Second, SampleInterval: time.Second,
		Lookback: 5 * time.Second, MinObservations: 1,
	}, logr.Discard())
	m179Observe(t, runtime, base, "initial")

	start := make(chan struct{})
	errs := make(chan error, 64)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 40; i++ {
				at := base.Add(time.Duration(i+1) * time.Second)
				switch worker {
				case 0:
					runtime.ObserveValidation(m179Comparison(at, fmt.Sprintf("producer-%d", i)), i%3, i%5)
				case 1:
					runtime.ObserveRotation(m179Rotation(at, fmt.Sprintf("rotation-%d", i)))
				case 2:
					snapshot, witnesses := m179Snapshot(at, fmt.Sprintf("snapshot-%d", i))
					if _, _, err := runtime.ObserveSnapshot(snapshot, witnesses); err != nil {
						errs <- err
					}
				case 3:
					_ = runtime.Latest()
					_ = runtime.RotationRecords(at)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	finalSnapshot, finalWitnesses := m179Snapshot(base.Add(time.Minute), "final")
	result, refreshed, err := runtime.ObserveSnapshot(finalSnapshot, finalWitnesses)
	if err != nil || !refreshed || result.GeneratedAt != finalSnapshot.Now {
		t.Fatalf("final refresh=%v generated=%v err=%v", refreshed, result.GeneratedAt, err)
	}
	m179TailIsClear(t, runtime)
}
