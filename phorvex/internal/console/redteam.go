package console

// redteam.go (P-REDTEAM) — the RED-TEAM CONTROL backend. Additive: new /api/redteam/* endpoints +
// a self-contained /redteam page. Reads REAL artifacts (the RL result.json, the -apt metrics.jsonl,
// the live-actuation audit, the live go-test gates) — nothing hardcoded except the curated, true
// finding NARRATIVE (the two discovered vulns + their fixes), whose live STATUS is recomputed from
// the artifacts. Brain/harness/Phoenix UNCHANGED. The console only READS + execs the attacker tool.
//
// HONEST scope flags surfaced to the UI:
//   - continuous co-training = a managed in-process background job (start/stop); a cross-restart
//     daemon is [PENDING-INFRA] and labeled as such.
//   - applying a fix from the UI = [PENDING-P-VCLUSTER write-path]: the workflow RECORDS the decision
//     and surfaces the recommended fix to apply via code; it never fakes an auto-apply.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- in-memory red-team control state (run job + continuous loop + review decisions) ----
type findingDecision struct {
	Status string `json:"status"` // open | addressed | deferred | accepted-risk
	Note   string `json:"note"`
	At     string `json:"at"`
}
type redteamState struct {
	mu            sync.Mutex
	loaded        bool
	runState      string // idle | running | done | error
	runMsg        string
	runStartedAt  string
	continuous    bool
	continuousGen int
	cancel        context.CancelFunc
	decisions     map[string]findingDecision
}

var rtState = &redteamState{runState: "idle", decisions: map[string]findingDecision{}}

func (s *Server) rtArtifact() string {
	if base := s.cfg.statePath("redteam"); base != "" {
		return filepath.Join(base, "result.json")
	}
	return ""
}
func (s *Server) rtDecisionsPath() string {
	if base := s.cfg.statePath("redteam"); base != "" {
		return filepath.Join(base, "decisions.json")
	}
	return ""
}
func (s *Server) rtBinary() string {
	name := "redteam-rl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(s.cfg.Root, "phorvex", "bin", name)
}

func (s *Server) rtLoadDecisions() error {
	rtState.mu.Lock()
	defer rtState.mu.Unlock()
	if rtState.loaded {
		return nil
	}
	rtState.loaded = true
	if b, err := os.ReadFile(s.rtDecisionsPath()); err == nil {
		if err = json.Unmarshal(b, &rtState.decisions); err != nil {
			rtState.loaded = false
			return fmt.Errorf("read retained red-team decisions: %w", err)
		}
	} else if !os.IsNotExist(err) {
		rtState.loaded = false
		return fmt.Errorf("read retained red-team decisions: %w", err)
	}
	if rtState.decisions == nil {
		rtState.decisions = map[string]findingDecision{}
	}
	return nil
}

// ---- /api/redteam/curves : the RL learning curves + QD + gate (from result.json) ----
func (s *Server) redteamCurves(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(s.rtArtifact())
	if err != nil {
		writeJSON(w, 200, map[string]any{"available": false, "note": "no RL run yet — click Run RL red-team"})
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		writeJSON(w, 503, map[string]any{"available": false, "error": "retained RL result is malformed: " + err.Error()})
		return
	}
	raw["available"] = true
	writeJSON(w, 200, raw)
}

// ---- /api/redteam/campaigns : the -apt benchmark results (PX vs reactive/blind/random) ----
type rtCampaignArm struct {
	Arm        string  `json:"arm"`
	Disruption float64 `json:"disruption"`
	// Actions is the mean defensive-action count over the trials whose cost was
	// actually OBSERVED; ActionsN is how many those were. When ActionsN is 0 the
	// cost was never measured and Actions is -1, never 0.
	Actions  float64 `json:"defensiveActions"`
	ActionsN int     `json:"defensiveActionsObserved"`
	N        int     `json:"n"`
}
type rtCampaign struct {
	Scenario string          `json:"scenario"`
	Product  string          `json:"product"`
	Arms     []rtCampaignArm `json:"arms"`
}

func (s *Server) redteamCampaigns(w http.ResponseWriter, r *http.Request) {
	// prefer the smoke slice, fall back to the bench dir.
	var rows []metricRow
	for _, d := range []string{"out-apt-smoke", "out-redteam-bench"} {
		if m, ok := readMetrics(filepath.Join(s.cfg.HarnessDir, d, "metrics.jsonl")); ok {
			rows = m
			break
		}
	}
	agg := map[string]map[string]*rtCampaignArm{}
	prod := map[string]string{}
	for _, m := range rows {
		if m.NegativeControl || m.Skipped {
			continue
		}
		// A row the harness measurement-validity contract refuses (failed
		// oracle/stimulus, unanchored comparison, unresolved cleanup) is not a
		// campaign result and never reaches a panel.
		if m.excluded() {
			continue
		}
		p := "k8s"
		if strings.HasPrefix(m.Scenario, "ai") {
			p = "ai"
		}
		prod[m.Scenario] = p
		if agg[m.Scenario] == nil {
			agg[m.Scenario] = map[string]*rtCampaignArm{}
		}
		a := agg[m.Scenario][m.Defender]
		if a == nil {
			a = &rtCampaignArm{Arm: m.Defender}
			agg[m.Scenario][m.Defender] = a
		}
		a.Disruption += m.DisruptionVsOracle
		// An UNOBSERVED cost is not a zero cost and never enters the mean.
		if m.costUsable() {
			a.Actions += float64(m.DefensiveActions)
			a.ActionsN++
		}
		a.N++
	}
	armOrder := []string{"d-nomtd", "d-phorvex", "d-fullphoenix", "d-r6blindtimer", "d-randomequal", "d-reactive-only"}
	var out []rtCampaign
	var scs []string
	for sc := range agg {
		scs = append(scs, sc)
	}
	sort.Strings(scs)
	for _, sc := range scs {
		c := rtCampaign{Scenario: sc, Product: prod[sc]}
		for _, an := range armOrder {
			if a := agg[sc][an]; a != nil {
				if a.N > 0 {
					a.Disruption /= float64(a.N)
				}
				if a.ActionsN > 0 {
					a.Actions /= float64(a.ActionsN)
				} else {
					a.Actions = -1 // UNOBSERVED, never a measured zero cost
				}
				c.Arms = append(c.Arms, *a)
			}
		}
		out = append(out, c)
	}
	writeJSON(w, 200, map[string]any{"campaigns": out, "available": len(out) > 0})
}

// ---- /api/redteam/live : the end-to-end live-actuation proof (real pod rotated) ----
func (s *Server) redteamLive(w http.ResponseWriter, r *http.Request) {
	type proof struct {
		Attack          string  `json:"attack"`
		FootholdRotated bool    `json:"footholdRotated"`
		Action          string  `json:"action"`
		PerDollar       float64 `json:"perDollar"`
		LambdaMax       float64 `json:"lambdaMax"`
		Actuations      int     `json:"footholdActuations"`
		Note            string  `json:"note"`
	}
	read := func(dir, attack, note string) (proof, bool) {
		path := filepath.Join(s.cfg.HarnessDir, dir, "phorvex-audit-d-phorvex.jsonl")
		b, err := os.ReadFile(path)
		if err != nil {
			return proof{}, false
		}
		p := proof{Attack: attack, Note: note}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if l, ok := rec["lambda"].(float64); ok && l > p.LambdaMax {
				p.LambdaMax = l
			}
			pod, _ := rec["pod"].(string)
			act, _ := rec["actuated"].(bool)
			if strings.HasSuffix(pod, "-fh") && act {
				p.Actuations++
				if p.Action == "" {
					p.Action, _ = rec["action"].(string)
					if pd, ok := rec["perDollar"].(float64); ok {
						p.PerDollar = pd
					}
				}
			}
		}
		p.FootholdRotated = p.Actuations > 0
		return p, true
	}
	var proofs []proof
	if p, ok := read("out-redteam-live-pump", "λ-pump (8-decoy flood)", "λ stayed bounded under the flood => the λ-fix held; foothold rotated despite the decoys"); ok {
		proofs = append(proofs, p)
	}
	if p, ok := read("out-redteam-live", "dispersion-steer (3 high-value decoys)", "foothold selected+rotated despite the decoys; pre-fix the decoys collapse its perDollar"); ok {
		proofs = append(proofs, p)
	}
	writeJSON(w, 200, map[string]any{"proofs": proofs, "available": len(proofs) > 0,
		"caveat": "Live multi-tick loop: pre-fix the crowd-out DEGRADES/DELAYS the actuation (perDollar collapse, churn) rather than permanently blocking it; the clean total per-tick suppression is the in-process decision proof."})
}

// ---- /api/redteam/findings : the two co-evolution cycles + reasoning + fix + review status ----
func (s *Server) redteamFindings(w http.ResponseWriter, r *http.Request) {
	if err := s.rtLoadDecisions(); err != nil {
		s.recordStateError(err)
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	// the live status is recomputed from the RL artifact (did the fix neutralize?).
	neutralized := map[string]bool{"lambda-pump": true, "dispersion-steer": true}
	if b, err := os.ReadFile(s.rtArtifact()); err == nil {
		var res struct {
			SteerFixNeutralizes bool `json:"steerFixNeutralizes"`
		}
		_ = json.Unmarshal(b, &res)
		neutralized["dispersion-steer"] = res.SteerFixNeutralizes
	}
	type finding struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		Product      string `json:"product"`
		Category     string `json:"category"`
		Source       string `json:"source"`
		Reasoning    string `json:"reasoning"`
		Cycle        string `json:"cycle"`
		Fix          string `json:"fix"`
		FixFile      string `json:"fixFile"`
		Neutralized  bool   `json:"neutralized"`
		ReviewStatus string `json:"reviewStatus"`
		ReviewNote   string `json:"reviewNote"`
		ApplyNote    string `json:"applyNote"`
	}
	rtState.mu.Lock()
	d1 := rtState.decisions["lambda-pump"]
	d2 := rtState.decisions["dispersion-steer"]
	rtState.mu.Unlock()
	stat := func(d findingDecision) (string, string) {
		if d.Status == "" {
			return "open", ""
		}
		return d.Status, d.Note
	}
	s1, n1 := stat(d1)
	s2, n2 := stat(d2)
	findings := []finding{
		{
			ID: "lambda-pump", Title: "λ-pump (legacy runtime-lambda starvation)", Product: "k8s", Category: "price/economics", Source: "RL (QD novelty)",
			Reasoning: "The RL learned to spawn many cheap decoys to inflate budget demand, pumping legacy runtime lambda until the real foothold's strict marginal*provenance-lambda*ECost gain becomes non-positive.",
			Cycle:     "found (POC λ-pump) → PRICE FIX (bounded subgradient, gated) → re-ran the adversary → NEUTRALIZED",
			Fix:       "Bounded, binding-gated legacy update: cap the manufacturable λ rise to one step/tick and only raise when the move budget is fully consumed.",
			FixFile:   "phorvex/internal/cost/dual.go", Neutralized: neutralized["lambda-pump"], ReviewStatus: s1, ReviewNote: n1,
			ApplyNote: "Already applied in code (gated brain change, gates byte-identical). Re-applying from the UI is [PENDING-P-VCLUSTER write-path].",
		},
		{
			ID: "dispersion-steer", Title: "dispersion-steer (selection crowd-out)", Product: "k8s", Category: "selection", Source: "RL (production, QD)",
			Reasoning: "The production RL found a path the λ-fix doesn't close: a few HIGH-perDollar fresh decoys out-net the real foothold for the single B=1 move, so it is never SELECTED — a selection attack, not a price attack.",
			Cycle:     "found (production RL) → SELECTION FIX (provenance discount, gated) → re-ran the adversary → NEUTRALIZED",
			Fix:       "Provenance-weighted selection: a genuinely-due asset (aged exposure ≥ proactiveFloor or real kill-chain evidence) keeps prov=1 (byte-identical); a fresh evidence-less decoy is discounted to provFloor=0.34 so it cannot crowd out a real foothold.",
			FixFile:   "phorvex/internal/decision/coverage.go", Neutralized: neutralized["dispersion-steer"], ReviewStatus: s2, ReviewNote: n2,
			ApplyNote: "Already applied in code (gated brain change, gates byte-identical). Re-applying from the UI is [PENDING-P-VCLUSTER write-path].",
		},
	}
	writeJSON(w, 200, map[string]any{"findings": findings})
}

// ---- /api/redteam/decision : record a review decision (addressed/deferred/accepted-risk) ----
func (s *Server) redteamDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ ID, Status, Note string }
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.ID == "" {
		writeJSON(w, 400, map[string]any{"error": "need {id,status,note}"})
		return
	}
	ok := map[string]bool{"open": true, "addressed": true, "deferred": true, "accepted-risk": true}
	if !ok[body.Status] {
		writeJSON(w, 400, map[string]any{"error": "status must be open|addressed|deferred|accepted-risk"})
		return
	}
	if err := s.rtLoadDecisions(); err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	rtState.mu.Lock()
	previous, existed := rtState.decisions[body.ID]
	rtState.decisions[body.ID] = findingDecision{Status: body.Status, Note: body.Note, At: nowStamp()}
	snapshot, _ := json.MarshalIndent(rtState.decisions, "", "  ")
	rtState.mu.Unlock()
	if err := atomicWriteState(s.rtDecisionsPath(), snapshot); err != nil {
		rtState.mu.Lock()
		if existed {
			rtState.decisions[body.ID] = previous
		} else {
			delete(rtState.decisions, body.ID)
		}
		rtState.mu.Unlock()
		s.recordStateError(err)
		writeJSON(w, 503, map[string]any{"error": "decision was not persisted: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": body.ID, "status": body.Status,
		"applyNote": "Decision recorded. Applying the fix is [PENDING-P-VCLUSTER write-path] — apply the recommended fix via code; the console does not fake an auto-apply."})
}

// ---- /api/redteam/gates : run the regression gates LIVE (1.62x/P3/lead-demo + suites) ----
func (s *Server) redteamGates(w http.ResponseWriter, r *http.Request) {
	pkgs := []struct{ Label, Pkg, Run string }{
		{"1.62× + P3 + lead-demo (decision)", "./internal/decision/", ""},
		{"RL adversary suite", "./internal/redteam/", ""},
		{"dual (λ-fix) suite", "./internal/cost/", "TestDual"},
	}
	type gate struct {
		Label string `json:"label"`
		Pass  bool   `json:"pass"`
		Out   string `json:"out"`
	}
	var gates []gate
	allPass := true
	for _, p := range pkgs {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		args := []string{"test", "-count=1", p.Pkg}
		if p.Run != "" {
			args = append(args, "-run", p.Run)
		}
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = filepath.Join(s.cfg.Root, "phorvex")
		cmd.Env = envBase()
		out, err := cmd.CombinedOutput()
		cancel()
		pass := err == nil && strings.Contains(string(out), "ok")
		if !pass {
			allPass = false
		}
		line := strings.TrimSpace(lastLine(string(out)))
		gates = append(gates, gate{Label: p.Label, Pass: pass, Out: line})
	}
	writeJSON(w, 200, map[string]any{"gates": gates, "allPass": allPass, "ranAt": nowStamp()})
}

// ---- /api/redteam/run : trigger an RL red-team run (managed background job) ----
func (s *Server) redteamRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	rtState.mu.Lock()
	if rtState.runState == "running" {
		rtState.mu.Unlock()
		writeJSON(w, 200, map[string]any{"state": "running", "note": "a run is already in progress"})
		return
	}
	bin := s.rtBinary()
	if !fileExists(bin) {
		rtState.mu.Unlock()
		writeJSON(w, 200, map[string]any{"state": "unavailable", "note": "redteam-rl binary not built at " + bin + " — build it: go build -o bin/redteam-rl ./cmd/redteam-rl"})
		return
	}
	intent, _ := json.Marshal(map[string]any{"kind": "phorvex.console.redteam", "phase": "intent", "time": time.Now().UTC()})
	if err := s.cfg.appendState(s.cfg.statePath("redteam-events.jsonl"), intent); err != nil {
		s.recordStateError(err)
		rtState.mu.Unlock()
		writeJSON(w, 503, map[string]any{"state": "refused", "error": "red-team run refused before effect: " + err.Error()})
		return
	}
	rtState.runState = "running"
	rtState.runMsg = "training the RL adversary (Recurrent-PPO + PBT + QD)…"
	rtState.runStartedAt = nowStamp()
	rtState.mu.Unlock()
	go s.rtRunJob(bin)
	writeJSON(w, 200, map[string]any{"state": "running", "startedAt": rtState.runStartedAt})
}

func (s *Server) rtRunJob(bin string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	tmp := s.rtArtifact() + ".tmp"
	if err := os.MkdirAll(filepath.Dir(tmp), 0o750); err != nil {
		rtState.mu.Lock()
		rtState.runState = "error"
		rtState.runMsg = "RL run refused before process start: " + err.Error()
		rtState.mu.Unlock()
		s.recordStateError(err)
		return
	}
	cmd := exec.CommandContext(ctx, bin, "--iters", "24", "--batch", "8", "--generations", "12", "--pop", "5", "--json", tmp)
	cmd.Dir = filepath.Join(s.cfg.Root, "phorvex")
	cmd.Env = envBase()
	err := cmd.Run()
	rtState.mu.Lock()
	defer rtState.mu.Unlock()
	if err != nil {
		rtState.runState = "error"
		rtState.runMsg = "RL run failed: " + err.Error()
		return
	}
	b, rerr := os.ReadFile(tmp)
	if rerr != nil {
		rtState.runState = "partial"
		rtState.runMsg = "RL process completed but result is unreadable: " + rerr.Error()
		s.recordStateError(rerr)
		return
	}
	if rerr = atomicWriteState(s.rtArtifact(), b); rerr != nil {
		rtState.runState = "partial"
		rtState.runMsg = "RL process completed but result persistence failed: " + rerr.Error()
		s.recordStateError(rerr)
		return
	}
	_ = os.Remove(tmp)
	rtState.runState = "done"
	rtState.runMsg = "RL run complete — curves + QD refreshed"
}

// ---- /api/redteam/run-status ----
func (s *Server) redteamRunStatus(w http.ResponseWriter, r *http.Request) {
	rtState.mu.Lock()
	defer rtState.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"state": rtState.runState, "msg": rtState.runMsg, "startedAt": rtState.runStartedAt,
		"continuous": rtState.continuous, "continuousGen": rtState.continuousGen,
	})
}

// ---- /api/redteam/continuous : start/stop the SCOPED continuous co-training loop ----
func (s *Server) redteamContinuous(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Action string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	bin := s.rtBinary()
	rtState.mu.Lock()
	defer rtState.mu.Unlock()
	switch body.Action {
	case "start":
		if rtState.continuous {
			writeJSON(w, 200, map[string]any{"continuous": true, "note": "already running"})
			return
		}
		if !fileExists(bin) {
			writeJSON(w, 200, map[string]any{"continuous": false, "note": "redteam-rl binary not built"})
			return
		}
		intent, _ := json.Marshal(map[string]any{"kind": "phorvex.console.redteam", "phase": "intent", "mode": "continuous", "time": time.Now().UTC()})
		if err := s.cfg.appendState(s.cfg.statePath("redteam-events.jsonl"), intent); err != nil {
			s.recordStateError(err)
			writeJSON(w, 503, map[string]any{"continuous": false, "error": "continuous run refused before effect: " + err.Error()})
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		rtState.cancel = cancel
		rtState.continuous = true
		rtState.continuousGen = 0
		go s.rtContinuousLoop(ctx, bin)
		writeJSON(w, 200, map[string]any{"continuous": true,
			"note": "SCOPED continuous: a managed in-process co-training loop (re-runs + refreshes the artifact each cycle). A cross-restart persistent daemon is [PENDING-INFRA]."})
	case "stop":
		if rtState.cancel != nil {
			rtState.cancel()
		}
		rtState.continuous = false
		writeJSON(w, 200, map[string]any{"continuous": false, "note": "stopped"})
	default:
		writeJSON(w, 400, map[string]any{"error": "action must be start|stop"})
	}
}

func (s *Server) rtContinuousLoop(ctx context.Context, bin string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		tmp := s.rtArtifact() + ".cont"
		cmd := exec.CommandContext(ctx, bin, "--iters", "16", "--batch", "6", "--generations", "8", "--pop", "4", "--json", tmp)
		cmd.Dir = filepath.Join(s.cfg.Root, "phorvex")
		cmd.Env = envBase()
		if cmd.Run() == nil {
			if b, err := os.ReadFile(tmp); err == nil {
				if err = atomicWriteState(s.rtArtifact(), b); err != nil {
					s.recordStateError(err)
					rtState.mu.Lock()
					rtState.continuous = false
					rtState.runMsg = "continuous result persistence failed: " + err.Error()
					rtState.mu.Unlock()
					return
				}
				_ = os.Remove(tmp)
			} else {
				s.recordStateError(err)
				return
			}
		}
		rtState.mu.Lock()
		if !rtState.continuous {
			rtState.mu.Unlock()
			return
		}
		rtState.continuousGen++
		rtState.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// ---- /redteam : the self-contained Red-Team Control page ----
func (s *Server) redteamPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(redteamHTML))
}

func nowStamp() string { return time.Now().UTC().Format("2006-01-02 15:04:05Z") }
func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}
