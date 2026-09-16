/*
 * Phorvex Console — THREE-ARM AVAILABILITY COMPARISON.
 *
 * GET /api/availability-arms answers the question a customer actually asks: "what happens to MY
 * app's availability when it is attacked — with no defense, with a blind rotator, and with
 * Phorvex?"
 *
 * All three arms are MEASURED on the same real workload, with the same real attack, and read from
 * the SAME background availability sampler, so they are directly comparable. The arm windows are
 * recorded by the experiment runner (three-arm.sh) into three-arm-<ns>.json; this endpoint windows
 * the sampler over them and computes the numbers. Nothing here is modelled:
 *
 *   A) no defense  — the Phorvex policy is put in dryRun, the attack is fired. Nothing is
 *                    disrupted, so availability stays flat — and the attacker keeps the pod. This
 *                    arm exists to make the crucial point that HIGH AVAILABILITY IS NOT SAFETY.
 *   B) R6 blind    — still dryRun; we run the blind-timer MECHANISM (delete the rotation target on
 *                    a fixed interval regardless of any signal), which is what a time-based
 *                    rotator does. Labelled as the mechanism, not as the R6 product.
 *   C) Phorvex     — policy active; it acts on the signal, once.
 */

package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type armExperiment struct {
	Operation string        `json:"operation,omitempty"`
	RunAt     string        `json:"runAt"`
	Namespace string        `json:"namespace"`
	Deploy    string        `json:"deploy"`
	Attack    string        `json:"attack"`
	ArmAStart string        `json:"armA_start"`
	ArmAEnd   string        `json:"armA_end"`
	ArmBStart string        `json:"armB_start"`
	ArmBEnd   string        `json:"armB_end"`
	ArmCStart string        `json:"armC_start"`
	ArmCEnd   string        `json:"armC_end"`
	Arms      []armEvidence `json:"arms,omitempty"`
	Restored  bool          `json:"restored"`
	Error     string        `json:"error,omitempty"`
}

type armEvidence struct {
	ID                   string `json:"id"`
	Label                string `json:"label"`
	Start                string `json:"start"`
	End                  string `json:"end"`
	StimulusAccepted     bool   `json:"stimulusAccepted"`
	AttackID             string `json:"attackId,omitempty"`
	TargetPod            string `json:"targetPod,omitempty"`
	TargetUID            string `json:"targetUid,omitempty"`
	Outcome              string `json:"outcome,omitempty"`
	Action               string `json:"action,omitempty"`
	Containment          string `json:"containment,omitempty"`
	DwellOngoing         bool   `json:"dwellOngoing,omitempty"`
	ObservationPersisted bool   `json:"observationPersisted"`
	RotationConfirmed    bool   `json:"rotationConfirmed,omitempty"`
	BaselineReady        bool   `json:"baselineReady"`
	Error                string `json:"error,omitempty"`
}

// armResult is one defender's measured availability over its window.
type armResult struct {
	Arm             string  `json:"arm"`
	Label           string  `json:"label"`
	Samples         int     `json:"samples"`
	MeanPct         float64 `json:"meanPct"`
	MinPct          float64 `json:"minPct"`
	DipCount        int     `json:"dipCount"`        // how many separate times it fell below full
	SecondsDegrade  float64 `json:"secondsDegraded"` // wall-clock seconds spent below full capacity
	ReplicaSeconds  float64 `json:"replicaSeconds"`  // capacity actually missing
	DowntimeUSD     float64 `json:"downtimeUsd"`
	AttackerStopped string  `json:"attackerStopped"` // yes | no | by-luck-only
	Verdict         string  `json:"verdict"`
	Complete        bool    `json:"complete"`
}

// armRun is ONE three-arm experiment: which app, when, and the three measured arms.
type armRun struct {
	RunAt     string      `json:"runAt"`
	Namespace string      `json:"namespace"`
	Deploy    string      `json:"deploy"`
	Attack    string      `json:"attack"`
	NodeRate  float64     `json:"nodeRatePerHr"`
	Arms      []armResult `json:"arms"`
}

type armsResponse struct {
	Running   []armsJob `json:"running"` // experiments in flight right now, with live progress
	Runs      []armRun  `json:"runs"`
	Available bool      `json:"available"`
	Note      string    `json:"note"`
	HowItRan  string    `json:"howItRan"`
	WhyNoDrop string    `json:"whyNoDrop"`
}

func armsPath(cfg Config) string {
	return cfg.statePath("three-arm-runs.jsonl")
}

func (s *Server) availabilityArms(w http.ResponseWriter, r *http.Request) {
	nsFilter := r.URL.Query().Get("ns") // optional; empty = every app
	p := principalOf(r)

	b, err := readStateLedger(armsPath(s.cfg))
	if err != nil || len(b) == 0 {
		writeJSON(w, 200, armsResponse{Available: false, Running: armsJobSnapshotFor(p),
			Note: "no three-arm experiment has been run yet. It is a real, disruptive procedure (it puts " +
				"the policy in dryRun and rotates pods), so it runs on request rather than on every attack."})
		return
	}
	// [M-136] The experiment log spans every app that has been run. An explicit ?ns= is already
	// checked against the grant by the boundary; an omitted one is filtered here rather than
	// returning every tenant's experiments.
	var exps []armExperiment
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var e armExperiment
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			writeJSON(w, 503, armsResponse{Available: false, Note: "retained experiment record is malformed: " + err.Error()})
			return
		}
		if !p.TenantWildcard() && !p.AllowsTenant(e.Namespace) {
			continue
		}
		if nsFilter == "" || e.Namespace == nsFilter {
			exps = append(exps, e)
		}
	}
	if len(exps) == 0 {
		writeJSON(w, 200, armsResponse{Available: false, Running: armsJobSnapshotFor(p), Note: "no experiment recorded for that app yet."})
		return
	}

	samples, sampleErr := readUptimeSamples(uptimePath(s.cfg))
	if sampleErr != nil {
		writeJSON(w, 503, armsResponse{Available: false, Note: sampleErr.Error()})
		return
	}
	resolve := s.buildRateResolver("")

	out := armsResponse{Available: true, Running: armsJobSnapshotFor(p),
		HowItRan:  "Each completed arm is bound to its own accepted stimulus and persisted ground-truth observation; availability is measured separately by the 5s sampler.",
		WhyNoDrop: "Availability alone does not establish attack execution or containment. Security status is shown only when the correlated observation proves it.",
		Note:      "Unknown or incomplete evidence remains unknown and is not scored as a successful defense.",
	}

	for i := len(exps) - 1; i >= 0; i-- { // newest first
		exp := exps[i]
		deploy := exp.Deploy
		if deploy == "" {
			deploy = s.firstDeploy(exp.Namespace)
		}
		rate := resolve(exp.Namespace, s.firstPodOf(exp.Namespace))
		run := armRun{RunAt: exp.RunAt, Namespace: exp.Namespace, Deploy: deploy,
			Attack: exp.Attack, NodeRate: round4(rate)}

		if len(exp.Arms) == 0 { // legacy timestamp-only records are retained but explicitly unknown.
			exp.Arms = []armEvidence{{ID: "nodefense", Label: "No defense", Start: exp.ArmAStart, End: exp.ArmAEnd, Error: "legacy record has no correlated stimulus evidence"}, {ID: "r6blind", Label: "Blind fixed-interval rotator", Start: exp.ArmBStart, End: exp.ArmBEnd, Error: "legacy record has no correlated stimulus evidence"}, {ID: "phorvex", Label: "Phorvex", Start: exp.ArmCStart, End: exp.ArmCEnd, Error: "legacy record has no correlated stimulus evidence"}}
		}
		for _, a := range exp.Arms {
			stopped, verdict := evidenceVerdict(a)
			measured := measureArm(samples, exp.Namespace, deploy, a.ID, a.Label, a.Start, a.End, stopped, verdict, rate)
			measured.Complete = measured.Complete && a.StimulusAccepted && a.ObservationPersisted && a.BaselineReady && exp.Restored && a.Error == ""
			run.Arms = append(run.Arms, measured)
		}
		out.Runs = append(out.Runs, run)
	}
	writeJSON(w, 200, out)
}

func evidenceVerdict(a armEvidence) (string, string) {
	if !a.ObservationPersisted || a.Error != "" {
		return "unknown", "Outcome unavailable: " + a.Error
	}
	stopped := a.Outcome == "DEFENDED" && !a.DwellOngoing && (a.Containment == "evicted" || a.Containment == "contained" || a.Containment == "flushed")
	if stopped {
		return "yes", fmt.Sprintf("Observed %s by %s for correlated attack %s.", a.Containment, a.Action, a.AttackID)
	}
	if a.Outcome == "LANDED" || a.DwellOngoing || a.Containment == "foothold-active" {
		return "no", fmt.Sprintf("Observed %s with containment %s for correlated attack %s.", a.Outcome, a.Containment, a.AttackID)
	}
	return "unknown", "Terminal observation did not prove containment."
}

// measureArm windows the availability sampler over one arm and reduces it to the comparable numbers.
func measureArm(samples []uptimeSample, ns, deploy, id, label, start, end, stopped, verdict string, rate float64) armResult {
	res := armResult{Arm: id, Label: label, AttackerStopped: stopped, Verdict: verdict, MinPct: -1, MeanPct: -1}
	t0, e0 := time.Parse(time.RFC3339, start)
	t1, e1 := time.Parse(time.RFC3339, end)
	if e0 != nil || e1 != nil {
		return res
	}
	var vals []float64
	var replicaSec, degradedSec float64
	dips, wasDown := 0, false
	for _, sm := range samples {
		if sm.NS != ns || sm.Workload != deploy || sm.Desired <= 0 {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, sm.T)
		if err != nil || at.Before(t0) || at.After(t1) {
			continue
		}
		vals = append(vals, float64(sm.Ready)/float64(sm.Desired)*100)
		if sm.Ready < sm.Desired {
			replicaSec += float64(sm.Desired-sm.Ready) * uptimeInterval.Seconds()
			degradedSec += uptimeInterval.Seconds()
			if !wasDown {
				dips++
				wasDown = true
			}
		} else {
			wasDown = false
		}
	}
	if len(vals) == 0 {
		return res
	}
	sum, min := 0.0, vals[0]
	for _, v := range vals {
		sum += v
		if v < min {
			min = v
		}
	}
	res.Samples = len(vals)
	res.MeanPct = round2(sum / float64(len(vals)))
	res.MinPct = round2(min)
	res.DipCount = dips
	res.SecondsDegrade = round2(degradedSec)
	res.ReplicaSeconds = round2(replicaSec)
	res.DowntimeUSD = round4(replicaSec / 3600.0 * rate)
	res.Complete = true
	return res
}

// firstPodOf returns any pod name in the namespace, used only to resolve which node (and therefore
// which on-demand rate) the workload sits on.
func (s *Server) firstPodOf(ns string) string {
	return strings.TrimSpace(s.kctlOut(ns, "get", "pods", "--no-headers", "-o",
		"jsonpath={.items[0].metadata.name}"))
}
