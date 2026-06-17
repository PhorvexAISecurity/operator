/*
 * Phorvex Console — per-run EVIDENCE: the full metric ledger for one triggered attack.
 *
 * Reads the run's own metrics.jsonl and returns, per defender arm, the complete measured
 * evidence (disruption + 95% CI, attacker dwell + CI, oracle-hit rate, defensive actions,
 * MTD-effect, security-per-$, evidence-retention, the Schwartau P/D/R triad, attack-replay
 * reusability) PLUS every per-trial row with the literal attacker command steps. This is the
 * same "evidence ledger" shape as the global report, scoped to a single live attack.
 */

package console

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// richRow is the permissive full subset of a harness metric row used for per-run evidence.
type richRow struct {
	Scenario             string   `json:"scenario"`
	Defender             string   `json:"defender"`
	Trial                int      `json:"trial"`
	OracleAchieved       bool     `json:"oracleAchieved"`
	DisruptionVsOracle   float64  `json:"disruptionVsOracle"`
	AttackerDwellSeconds float64  `json:"attackerDwellSeconds"`
	DefensiveActions     int      `json:"defensiveActions"`
	FalseDefensiveActions int     `json:"falseDefensiveActions"`
	SecurityPerCost      float64  `json:"securityPerCost"`
	EvidenceRetention    float64  `json:"evidenceRetention"`
	Skipped              bool     `json:"skipped"`
	NegativeControl      bool     `json:"negativeControl"`
	MTDEffect            string   `json:"mtdEffect"`
	ObservedState        string   `json:"observedState"`
	Commands             []string `json:"commands"`
	Schwartau            *struct {
		ProtectionTimeSeconds float64 `json:"protectionTimeSeconds"`
		DetectionTimeSeconds  float64 `json:"detectionTimeSeconds"`
		ReactionTimeSeconds   float64 `json:"reactionTimeSeconds"`
	} `json:"schwartau"`
	Reuse *struct {
		ReplaySuccessCount int `json:"replaySuccessCount"`
		ReplayAttempts     int `json:"replayAttempts"`
	} `json:"reuse"`
}

// RunEvidenceArm is the aggregated evidence for one defender arm of a run.
type RunEvidenceArm struct {
	Defender         string  `json:"defender"`
	Label            string  `json:"label"`
	Trials           int     `json:"trials"`
	Disruption       ci      `json:"disruption"`
	Dwell            ci      `json:"dwell"`
	OracleHitPct     float64 `json:"oracleHitPct"`
	DefensiveActions float64 `json:"defensiveActions"`
	SecurityPerCost  float64 `json:"securityPerCost"`
	EvidenceRetention float64 `json:"evidenceRetention"`
	MTDEffect        string  `json:"mtdEffect"`
	SchwartauP       float64 `json:"schwartauP"`
	SchwartauD       float64 `json:"schwartauD"`
	SchwartauR       float64 `json:"schwartauR"`
	ReplaySuccess    int     `json:"replaySuccess"`
	ReplayAttempts   int     `json:"replayAttempts"`
}

// RunEvidenceTrial is one per-trial row (the granular evidence).
type RunEvidenceTrial struct {
	Defender       string   `json:"defender"`
	Trial          int      `json:"trial"`
	Skipped        bool     `json:"skipped"`
	OracleAchieved bool     `json:"oracleAchieved"`
	Disruption     float64  `json:"disruption"`
	Dwell          float64  `json:"dwell"`
	DefensiveActions int    `json:"defensiveActions"`
	MTDEffect      string   `json:"mtdEffect"`
	Observed       string   `json:"observed"`
	Commands       []string `json:"commands"`
}

func armLabelOf(def string) string {
	switch def {
	case "d-phorvex":
		return "Phorvex"
	case "d-nomtd":
		return "Without Phorvex (no-MTD)"
	case "d-r6blindtimer":
		return "Without Phorvex (blind 15s)"
	case "d-randomequal":
		return "Without Phorvex (random)"
	case "d-fullphoenix":
		return "Full Phoenix"
	case "d-reactive-only":
		return "Reactive only"
	}
	return def
}

// RunEvidence parses one run's metrics.jsonl into the full per-arm + per-trial evidence ledger.
func (rm *RunManager) RunEvidence(id string) (arms []RunEvidenceArm, trials []RunEvidenceTrial, st RunStatus, ok bool) {
	rm.mu.Lock()
	out, has := rm.runOut[id]
	if s, sok := rm.runs[id]; sok {
		st = *s
	}
	rm.mu.Unlock()
	if !has {
		return nil, nil, st, false
	}
	f, err := os.Open(filepath.Join(rm.cfg.HarnessDir, out, "metrics.jsonl"))
	if err != nil {
		return []RunEvidenceArm{}, []RunEvidenceTrial{}, st, true // run exists, no metrics yet
	}
	defer f.Close()

	type acc struct {
		dis, dwl       []float64
		oracleHits, n  int
		defActs        int
		secPerCost     float64
		evidRetain     float64
		mtd            string
		schP, schD, schR float64
		replaySucc, replayAtt int
	}
	byDef := map[string]*acc{}
	order := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		var r richRow
		if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &r) != nil || r.NegativeControl {
			continue
		}
		trials = append(trials, RunEvidenceTrial{
			Defender: r.Defender, Trial: r.Trial, Skipped: r.Skipped, OracleAchieved: r.OracleAchieved,
			Disruption: r.DisruptionVsOracle, Dwell: r.AttackerDwellSeconds, DefensiveActions: r.DefensiveActions,
			MTDEffect: r.MTDEffect, Observed: r.ObservedState, Commands: r.Commands,
		})
		if r.Skipped {
			continue
		}
		a := byDef[r.Defender]
		if a == nil {
			a = &acc{}
			byDef[r.Defender] = a
			order = append(order, r.Defender)
		}
		a.dis = append(a.dis, r.DisruptionVsOracle)
		a.dwl = append(a.dwl, r.AttackerDwellSeconds)
		a.n++
		if r.OracleAchieved {
			a.oracleHits++
		}
		a.defActs += r.DefensiveActions
		a.secPerCost += r.SecurityPerCost
		a.evidRetain += r.EvidenceRetention
		if r.MTDEffect != "" {
			a.mtd = r.MTDEffect
		}
		if r.Schwartau != nil {
			a.schP, a.schD, a.schR = r.Schwartau.ProtectionTimeSeconds, r.Schwartau.DetectionTimeSeconds, r.Schwartau.ReactionTimeSeconds
		}
		if r.Reuse != nil {
			a.replaySucc += r.Reuse.ReplaySuccessCount
			a.replayAtt += r.Reuse.ReplayAttempts
		}
	}
	for _, def := range order {
		a := byDef[def]
		nn := float64(maxInt(a.n, 1))
		arms = append(arms, RunEvidenceArm{
			Defender: def, Label: armLabelOf(def), Trials: a.n,
			Disruption: tci(a.dis), Dwell: tci(a.dwl),
			OracleHitPct: float64(a.oracleHits) / nn * 100,
			DefensiveActions: float64(a.defActs) / nn,
			SecurityPerCost:  a.secPerCost / nn,
			EvidenceRetention: a.evidRetain / nn,
			MTDEffect: a.mtd, SchwartauP: a.schP, SchwartauD: a.schD, SchwartauR: a.schR,
			ReplaySuccess: a.replaySucc, ReplayAttempts: a.replayAtt,
		})
	}
	sort.Slice(arms, func(i, j int) bool { return arms[i].Defender == "d-phorvex" || (arms[j].Defender != "d-phorvex" && arms[i].Defender < arms[j].Defender) })
	sort.Slice(trials, func(i, j int) bool {
		if trials[i].Defender != trials[j].Defender {
			return trials[i].Defender < trials[j].Defender
		}
		return trials[i].Trial < trials[j].Trial
	})
	if arms == nil {
		arms = []RunEvidenceArm{}
	}
	if trials == nil {
		trials = []RunEvidenceTrial{}
	}
	return arms, trials, st, true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
