package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func resetAttackLedger(t *testing.T) {
	t.Helper()
	attackMu.Lock()
	attackList, attackLoaded = nil, false
	attackMu.Unlock()
	t.Cleanup(func() {
		attackMu.Lock()
		attackList, attackLoaded = nil, false
		attackMu.Unlock()
	})
}

func fixtureAttackServer(t *testing.T, defended *atomic.Bool) *Server {
	t.Helper()
	cfg := Config{Root: t.TempDir()}
	cfg.Exec = func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get deploy -o name"):
			return "deployment.apps/svc", nil
		case strings.Contains(joined, "readyReplicas"):
			return "1|1", nil
		case strings.Contains(joined, "kv-reset-epoch"):
			if defended != nil && defended.Load() {
				return "new", nil
			}
			return "old", nil
		case strings.Contains(joined, "get pod") && strings.Contains(joined, "-o name"):
			return "pod/svc-0", nil
		case strings.Contains(joined, "get pods -n phorvex-system"):
			return "", nil
		default:
			return "", errors.New("fixture has no resource")
		}
	}
	return &Server{cfg: cfg}
}

func attackHTTP(t *testing.T, s *Server, tenants []string) []attackRecord {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/attack-results", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalCtxKey{}, &Principal{Tenants: tenants}))
	w := httptest.NewRecorder()
	s.attackResults(w, req)
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Attacks []attackRecord `json:"attacks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Attacks
}

func TestAttackSnapshotsNestedOwnershipAndTenantHistory(t *testing.T) {
	resetAttackLedger(t)
	s := fixtureAttackServer(t, nil)
	attackLoaded = true
	r := &attackRecord{ID: "one", Namespace: "tenant-a", Status: "running", baseQuar: map[string]bool{"old": true}, baseNP: map[string]bool{"np": true}, Claim: &model.ClaimScope{DetectorSet: []string{"first"}}}
	publishAttack(r)
	r.Claim.DetectorSet[0] = "changed"
	r.baseQuar["old"] = false
	r.baseNP["np"] = false
	r.Status = "done"
	got := attackHTTP(t, s, []string{"tenant-a"})
	if len(got) != 1 || got[0].Status != "running" || got[0].Claim.DetectorSet[0] != "first" {
		t.Fatalf("mutable publication: %+v", got)
	}
	snap := attackSnapshots(&Principal{Tenants: []string{"tenant-a"}})[0]
	if !snap.baseQuar["old"] || !snap.baseNP["np"] {
		t.Fatalf("baseline maps aliased: %+v", snap)
	}
	snap.Claim.DetectorSet[0] = "reader changed"
	if attackHTTP(t, s, []string{"tenant-a"})[0].Claim.DetectorSet[0] != "first" {
		t.Fatal("reader mutated ledger claim")
	}
	publishAttack(&attackRecord{ID: "two", Namespace: "tenant-b", Status: "done"})
	if got := attackHTTP(t, s, []string{"tenant-a"}); len(got) != 1 || got[0].ID != "one" {
		t.Fatalf("tenant filter: %+v", got)
	}
	if got := attackHTTP(t, s, []string{"*"}); len(got) != 2 || got[0].ID != "two" {
		t.Fatalf("newest first control: %+v", got)
	}
	s.persistAttack(snap)
	attackMu.Lock()
	attackList, attackLoaded = nil, false
	attackMu.Unlock()
	got = attackHTTP(t, s, []string{"tenant-a"})
	if len(got) != 1 || got[0].Status != "done" || got[0].Claim.DetectorSet[0] != "reader changed" {
		t.Fatalf("history reload compatibility: %+v", got)
	}
}

func TestAttackWatcherHTTPPersistenceConcurrent(t *testing.T) {
	resetAttackLedger(t)
	var defended atomic.Bool
	s := fixtureAttackServer(t, &defended)
	attackLoaded = true
	r := &attackRecord{ID: "real-producer", FiredAt: time.Now().UTC().Format(time.RFC3339), Namespace: "tenant-a", Pod: "svc-0", Deploy: "svc", AttackID: "kvcache", UptimeBefore: 100, Status: "running", started: time.Now(), baseKVEpoch: "old"}
	publishAttack(r)
	// Nonconcurrent producer control: the unchanged epoch yields a correct LANDED record.
	control := &attackRecord{ID: "control", Namespace: "tenant-b", Pod: "svc-0", Deploy: "svc", AttackID: "kvcache", UptimeBefore: 100, Status: "running", started: time.Now(), baseKVEpoch: "old"}
	publishAttack(control)
	s.watchAttackUntil("", control, time.Now().Add(6*time.Millisecond), time.Millisecond)
	if got := attackHTTP(t, s, []string{"tenant-b"}); len(got) != 1 || got[0].Outcome != "LANDED" || got[0].Status != "done" {
		t.Fatalf("landed control: %+v", got)
	}
	var wg sync.WaitGroup
	watchDone := make(chan struct{})
	var sawTerminal atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		defended.Store(true)
		s.watchAttackUntil("", r, time.Now().Add(45*time.Millisecond), time.Millisecond)
		close(watchDone) // includes the terminal JSONL append
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10000; j++ {
				got := attackHTTP(t, s, []string{"tenant-a"})
				if len(got) != 1 || got[0].ID != r.ID {
					t.Errorf("HTTP reader: %+v", got)
					return
				}
				if got[0].Outcome == "DEFENDED" && (got[0].Action != "kv-reset" || !got[0].Actuated || got[0].TimeToDefendSec < 0) {
					t.Errorf("partial defense: %+v", got[0])
					return
				}
				if got[0].Status == "done" && (got[0].Outcome != "DEFENDED" || got[0].Containment != "flushed" || got[0].DwellOngoing) {
					t.Errorf("partial terminal: %+v", got[0])
					return
				}
				if got[0].Status == "done" {
					sawTerminal.Store(true)
				}
				select {
				case <-watchDone:
					// Read after the append as well, so these readers span both publication
					// and persistence even when the watcher wins the scheduler.
					for k := 0; k < 3; k++ {
						_ = attackHTTP(t, s, []string{"tenant-a"})
					}
					return
				default:
				}
			}
			t.Error("reader exhausted before watcher completed")
		}()
	}
	wg.Wait()
	if !sawTerminal.Load() {
		t.Fatal("no concurrent HTTP reader observed terminal publication")
	}
	got := attackHTTP(t, s, []string{"tenant-a"})
	if len(got) != 1 || got[0].Outcome != "DEFENDED" || got[0].Status != "done" || got[0].Containment != "flushed" {
		t.Fatalf("terminal producer: %+v", got)
	}
	b, err := os.ReadFile(s.attacksPath())
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var persisted attackRecord
		if err := json.Unmarshal([]byte(line), &persisted); err != nil {
			t.Fatalf("interleaved JSONL append: %v", err)
		}
		if persisted.ID == r.ID {
			seen = persisted.Status == "done" && persisted.Containment == "flushed"
		}
	}
	if !seen {
		t.Fatal("terminal producer did not persist")
	}
}

func TestAttackConcurrentJSONLAppendAndReload(t *testing.T) {
	resetAttackLedger(t)
	s := fixtureAttackServer(t, nil)
	const writers = 24
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.persistAttack(&attackRecord{ID: string(rune('a' + i)), Namespace: "tenant-a", Status: "done", Outcome: "LANDED", Action: "noop"})
		}(i)
	}
	wg.Wait()
	b, err := os.ReadFile(s.attacksPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != writers {
		t.Fatalf("appends: got %d, want %d", len(lines), writers)
	}
	for _, line := range lines {
		var rec attackRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Status != "done" {
			t.Fatalf("invalid append: %v %+v", err, rec)
		}
	}
	if got := attackHTTP(t, s, []string{"tenant-a"}); len(got) != writers {
		t.Fatalf("reload count: %d", len(got))
	}
}
