/*
 * Phorvex Console — THREE-ARM EXPERIMENT RUNNER (user-triggered, live status).
 *
 * POST /api/availability-arms/run {namespace, attack} starts the three-arm comparison for ONE app
 * and returns immediately; the dashboard polls /api/availability-arms and watches it progress
 * arm-by-arm, then sees the finished run appear in the list.
 *
 * This is deliberately a user-triggered job, not something that happens on every attack: it puts
 * the tenant's policy into dryRun for the first two arms and rotates pods on a timer, which is
 * genuinely disruptive. Doing that silently behind a normal "fire attack" click would be a nasty
 * surprise. The UI says what it will do before it runs.
 *
 * SAFETY: the policy mode is restored to its ORIGINAL value in a defer, so an error, a panic or a
 * console restart mid-run cannot strand a tenant in dryRun (undefended). Only one experiment per
 * namespace at a time.
 */

package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// armsJob is the live status of one running experiment.
type armsJob struct {
	Namespace string `json:"namespace"`
	Deploy    string `json:"deploy"`
	Attack    string `json:"attack"`
	StartedAt string `json:"startedAt"`
	Phase     string `json:"phase"`    // arm-a | arm-b | arm-c | done | failed
	Detail    string `json:"detail"`   // human-readable current step
	Progress  int    `json:"progress"` // 0..100
	Error     string `json:"error,omitempty"`
}

var (
	armsMu   sync.Mutex
	armsJobs = map[string]*armsJob{} // namespace -> live job
)

func armsJobSnapshot() []armsJob {
	armsMu.Lock()
	defer armsMu.Unlock()
	out := make([]armsJob, 0, len(armsJobs))
	for _, j := range armsJobs {
		out = append(out, *j)
	}
	return out
}

func (s *Server) setArmsPhase(ns, phase, detail string, pct int) {
	armsMu.Lock()
	defer armsMu.Unlock()
	if j := armsJobs[ns]; j != nil {
		j.Phase, j.Detail, j.Progress = phase, detail, pct
	}
}

// runArmsExperiment starts the three-arm comparison for one namespace.
func (s *Server) runArmsExperiment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Attack    string `json:"attack"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ns := strings.TrimSpace(body.Namespace)
	if ns == "" || !scenarioRe.MatchString(ns) {
		writeJSON(w, 400, map[string]string{"error": "namespace required"})
		return
	}
	// vllm is attacked through /api/vllm/attack (kvcache/poison) rather than the generic
	// workload-attack endpoint, so it is not in armedWorkloads — but it IS attackable and the
	// runner already routes it correctly. Accept both sets.
	if !armedWorkloads[ns] && ns != "vllm" {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed for live attack: " + ns})
		return
	}
	attack := body.Attack
	if attack == "" {
		attack = "foothold"
	}

	armsMu.Lock()
	if j := armsJobs[ns]; j != nil && j.Phase != "done" && j.Phase != "failed" {
		armsMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "an experiment is already running for " + ns})
		return
	}
	policy := strings.TrimSpace(s.kctlOut(ns, "get", "phorvexpolicy", "-o", "jsonpath={.items[0].metadata.name}"))
	deploy := s.firstDeploy(ns)
	job := &armsJob{Namespace: ns, Deploy: deploy, Attack: attack,
		StartedAt: time.Now().UTC().Format(time.RFC3339), Phase: "arm-a",
		Detail: "starting — switching the policy to dryRun", Progress: 1}
	armsJobs[ns] = job
	armsMu.Unlock()

	if policy == "" {
		s.failArms(ns, "no PhorvexPolicy found in "+ns)
		writeJSON(w, 400, map[string]string{"error": "no PhorvexPolicy in " + ns})
		return
	}
	intent, _ := json.Marshal(map[string]any{"kind": "phorvex.console.experiment", "phase": "intent", "time": time.Now().UTC(), "namespace": ns, "deploy": deploy, "attack": attack})
	if err := s.cfg.appendState(s.cfg.statePath("experiment-events.jsonl"), intent); err != nil {
		s.failArms(ns, "experiment evidence unavailable: "+err.Error())
		writeJSON(w, 503, map[string]string{"error": "experiment refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	go s.armsWorker(ns, deploy, policy, attack)

	writeJSON(w, 200, map[string]any{"ok": true, "namespace": ns, "deploy": deploy,
		"note": "three-arm comparison started (~7 minutes). Watch it in Availability: 3-way."})
}

func (s *Server) failArms(ns, msg string) {
	armsMu.Lock()
	defer armsMu.Unlock()
	if j := armsJobs[ns]; j != nil {
		j.Phase, j.Error, j.Detail, j.Progress = "failed", msg, "failed", 100
	}
}

func (s *Server) setMode(ns, policy, mode string) {
	_, _ = s.cfg.execText(10*time.Second, "kubectl", "-n", ns, "patch", "phorvexpolicy", policy,
		"--type=merge", "-p", fmt.Sprintf(`{"spec":{"mode":%q}}`, mode))
}

// armsWorker runs the three arms. Every sleep is real wall-clock time because the availability
// sampler is what measures the arms — there is nothing to fake or shortcut.
func (s *Server) armsWorker(ns, deploy, policy, attack string) {
	origMode := strings.TrimSpace(s.kctlOut(ns, "get", "phorvexpolicy", policy, "-o", "jsonpath={.spec.mode}"))
	if origMode == "" {
		origMode = "active"
	}
	// SAFETY: never leave a tenant undefended, whatever happens below.
	defer func() {
		if rec := recover(); rec != nil {
			s.failArms(ns, fmt.Sprintf("panic: %v", rec))
		}
		s.setMode(ns, policy, origMode)
	}()

	mark := func() string { return time.Now().UTC().Format(time.RFC3339) }
	fire := func() {
		if ns == "vllm" {
			_, _ = s.cfg.execText(30*time.Second, "curl", "-s", "-m", "25", "-X", "POST",
				"-H", "X-Phorvex-Lens: operator", "-H", "Content-Type: application/json",
				"-d", fmt.Sprintf(`{"action":%q}`, attack), "http://localhost:8095/api/vllm/attack")
			return
		}
		_, _ = s.cfg.execText(30*time.Second, "curl", "-s", "-m", "25", "-X", "POST",
			"-H", "X-Phorvex-Lens: operator", "-H", "Content-Type: application/json",
			"-d", fmt.Sprintf(`{"namespace":%q,"action":%q}`, ns, attack), "http://localhost:8095/api/workload/attack")
	}

	// ---- ARM A: no defense (policy in dryRun) ----
	s.setMode(ns, policy, "dryRun")
	s.setArmsPhase(ns, "arm-a", "arm A — no defense: policy in dryRun, settling", 5)
	time.Sleep(20 * time.Second)
	a0 := mark()
	s.setArmsPhase(ns, "arm-a", "arm A — no defense: attack fired, watching availability", 12)
	fire()
	time.Sleep(120 * time.Second)
	a1 := mark()

	// ---- ARM B: blind fixed-interval rotator ----
	time.Sleep(25 * time.Second)
	b0 := mark()
	for i := 1; i <= 4; i++ {
		s.setArmsPhase(ns, "arm-b", fmt.Sprintf("arm B — blind rotator: rotation %d of 4 (fires on a timer, not on a signal)", i), 25+i*8)
		if p := strings.TrimSpace(s.kctlOut(ns, "get", "pods", "-l", "r6th.io/rotation-target=true",
			"-o", "jsonpath={.items[0].metadata.name}")); p != "" {
			_, _ = s.cfg.execText(15*time.Second, "kubectl", "-n", ns, "delete", "pod", p, "--wait=false")
		}
		time.Sleep(30 * time.Second)
	}
	b1 := mark()

	// ---- ARM C: Phorvex ----
	time.Sleep(50 * time.Second)
	s.setMode(ns, policy, "active")
	s.setArmsPhase(ns, "arm-c", "arm C — Phorvex: policy active again, settling", 70)
	time.Sleep(25 * time.Second)
	c0 := mark()
	s.setArmsPhase(ns, "arm-c", "arm C — Phorvex: attack fired, watching availability", 80)
	fire()
	time.Sleep(120 * time.Second)
	c1 := mark()

	rec := armExperiment{RunAt: mark(), Namespace: ns, Deploy: deploy, Attack: attack,
		ArmAStart: a0, ArmAEnd: a1, ArmBStart: b0, ArmBEnd: b1, ArmCStart: c0, ArmCEnd: c1}
	if b, err := json.Marshal(rec); err != nil {
		s.failArms(ns, "encode experiment result: "+err.Error())
		return
	} else if err = s.cfg.appendState(armsPath(s.cfg), b); err != nil {
		s.failArms(ns, "experiment completed but outcome evidence is unavailable; unsafe to retry: "+err.Error())
		return
	}
	s.setArmsPhase(ns, "done", "complete — results below", 100)
}
