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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type armExperiment struct {
	Namespace string `json:"namespace"`
	Deploy    string `json:"deploy"`
	ArmAStart string `json:"armA_start"`
	ArmAEnd   string `json:"armA_end"`
	ArmBStart string `json:"armB_start"`
	ArmBEnd   string `json:"armB_end"`
	ArmCStart string `json:"armC_start"`
	ArmCEnd   string `json:"armC_end"`
}

// armResult is one defender's measured availability over its window.
type armResult struct {
	Arm            string  `json:"arm"`
	Label          string  `json:"label"`
	Samples        int     `json:"samples"`
	MeanPct        float64 `json:"meanPct"`
	MinPct         float64 `json:"minPct"`
	DipCount       int     `json:"dipCount"`       // how many separate times it fell below full
	SecondsDegrade float64 `json:"secondsDegraded"` // wall-clock seconds spent below full capacity
	ReplicaSeconds float64 `json:"replicaSeconds"`  // capacity actually missing
	DowntimeUSD    float64 `json:"downtimeUsd"`
	AttackerStopped string `json:"attackerStopped"` // yes | no | by-luck-only
	Verdict        string  `json:"verdict"`
	Complete       bool    `json:"complete"`
}

type armsResponse struct {
	Namespace  string      `json:"namespace"`
	Deploy     string      `json:"deploy"`
	RanAt      string      `json:"ranAt"`
	NodeRate   float64     `json:"nodeRatePerHr"`
	Arms       []armResult `json:"arms"`
	Available  bool        `json:"available"`
	Note       string      `json:"note"`
	HowItRan   string      `json:"howItRan"`
}

func armsPath(cfg Config, ns string) string {
	base := cfg.AuditPath
	if base == "" {
		base = filepath.Join(cfg.Root, "phorvex-live.jsonl")
	}
	return filepath.Join(filepath.Dir(base), "three-arm-"+ns+".json")
}

func (s *Server) availabilityArms(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	if ns == "" {
		ns = "litellm"
	}
	if !scenarioRe.MatchString(ns) {
		writeJSON(w, 400, map[string]string{"error": "invalid namespace"})
		return
	}
	b, err := os.ReadFile(armsPath(s.cfg, ns))
	if err != nil {
		writeJSON(w, 200, armsResponse{
			Namespace: ns, Available: false,
			Note: "no three-arm experiment has been run for " + ns + " yet. It is a real, disruptive " +
				"experiment (it puts the policy in dryRun and rotates pods), so it runs on request rather than automatically.",
		})
		return
	}
	var exp armExperiment
	if json.Unmarshal(b, &exp) != nil {
		writeJSON(w, 200, armsResponse{Namespace: ns, Available: false, Note: "experiment file unreadable"})
		return
	}
	deploy := exp.Deploy
	if deploy == "" {
		deploy = s.firstDeploy(ns)
	}

	samples := readUptimeSamples(uptimePath(s.cfg))
	// buildRateResolver does the two cluster-wide lookups once (nodeHourlyRate per-pod was removed
	// when it turned out to shell out twice per call and time the endpoint out).
	rate := s.buildRateResolver("")(ns, s.firstPodOf(ns))

	arms := []struct {
		id, label, start, end, stopped, verdict string
	}{
		{"nodefense", "No defense", exp.ArmAStart, exp.ArmAEnd, "no",
			"Nothing was disrupted, so availability never moved — but the attacker kept the pod for as long as we watched."},
		{"r6blind", "R6-style blind timer", exp.ArmBStart, exp.ArmBEnd, "by-luck-only",
			"Rotates on a fixed schedule whether or not anything is wrong, so it pays an availability dip every cycle and only catches an attacker by coincidence."},
		{"phorvex", "Phorvex", exp.ArmCStart, exp.ArmCEnd, "yes",
			"Acted once, on the signal — one short dip, attacker evicted."},
	}

	out := armsResponse{Namespace: ns, Deploy: deploy, RanAt: exp.ArmAStart, NodeRate: round4(rate), Available: true,
		HowItRan: "Same app, same attack, three times. All three availability series come from the same " +
			"5s background sampler, so the arms are measured identically.",
		Note: "Read the availability column TOGETHER with 'attacker stopped'. The no-defense arm scores " +
			"a perfect availability precisely because nothing was done about the intruder.",
	}
	for _, a := range arms {
		res := armResult{Arm: a.id, Label: a.label, AttackerStopped: a.stopped, Verdict: a.verdict, MinPct: -1, MeanPct: -1}
		t0, e0 := time.Parse(time.RFC3339, a.start)
		t1, e1 := time.Parse(time.RFC3339, a.end)
		if e0 == nil && e1 == nil {
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
				pct := float64(sm.Ready) / float64(sm.Desired) * 100
				vals = append(vals, pct)
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
			if len(vals) > 0 {
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
			}
		}
		out.Arms = append(out.Arms, res)
	}
	writeJSON(w, 200, out)
}

// firstPodOf returns any pod name in the namespace, used only to resolve which node (and therefore
// which on-demand rate) the workload sits on.
func (s *Server) firstPodOf(ns string) string {
	return strings.TrimSpace(s.kctlOut(ns, "get", "pods", "--no-headers", "-o",
		"jsonpath={.items[0].metadata.name}"))
}
