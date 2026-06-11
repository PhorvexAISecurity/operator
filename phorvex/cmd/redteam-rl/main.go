/*
 * P-REDTEAM — the PRODUCTION RL ADVERSARY (the IP centerpiece). Replaces the proof-of-concept
 * tabular learner with the full design: Recurrent-PPO (GRU policy, GAE, clipped surrogate, BPTT) +
 * Population-Based Training + Quality-Diversity (MAP-Elites), an effects-only POMDP, a factored TTP
 * action space + meta-actions, a shaped oracle-grounded reward, continuous CO-TRAINING against the
 * live DETERMINISTIC Phorvex economics (cost.DualSolver — Decide stays byte-deterministic), and a
 * HUMAN-APPROVAL promotion gate. All learning lives here (the attacker); NO ML in Phorvex.Decide.
 *
 * INDEPENDENT of the 52 scripted campaigns: it uses their TTPs as its action vocabulary but its
 * value is LEARNING + DISCOVERING novel multi-step paths — here it independently finds the
 * DISPERSION-STEER, a path the shipped λ-fix does NOT close (a new vulnerability), surfaced by QD.
 *
 * Run: go run ./cmd/redteam-rl   (the single-agent learning curves + the population QD archive)
 */
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/phorvex/phorvex/internal/redteam"
)

// jsonCurve / jsonProposal / jsonResult are the console-consumable shape written by --json.
type jsonCurve struct {
	Label string    `json:"label"`
	Curve []float64 `json:"curve"`
	Start float64   `json:"start"`
	End   float64   `json:"end"`
	Delta float64   `json:"delta"`
}
type jsonProposal struct {
	Strategy string  `json:"strategy"`
	Return   float64 `json:"return"`
	Approved bool    `json:"approved"`
}
type jsonResult struct {
	Seed                int64          `json:"seed"`
	Iters               int            `json:"iters"`
	Curves              []jsonCurve    `json:"curves"`
	QD                  []jsonProposal `json:"qd"`
	QDCoverage          int            `json:"qdCoverage"`
	AutoEscalate        bool           `json:"autoEscalate"`
	Proposals           []jsonProposal `json:"proposals"`
	SteerFixNeutralizes bool           `json:"steerFixNeutralizes"`
	VulnWasReal         bool           `json:"vulnWasReal"`
	FlatVsRandom        bool           `json:"flatVsRandom"`
}

func evalAgent(a *redteam.Agent, env *redteam.Env, n int) float64 {
	s := 0.0
	for i := 0; i < n; i++ {
		s += a.EpisodeReturn(env)
	}
	return s / float64(n)
}

// learningCurve trains ONE Recurrent-PPO agent over `iters` PPO iterations vs `kind`, recording its
// greedy return each iteration (the production learning curve — a single learner, so the climb is
// the learner's own, not a population lucky-draw).
func learningCurve(kind redteam.DefenderKind, obsDim int, seed int64, iters, batch int) []float64 {
	rng := rand.New(rand.NewSource(seed))
	env := redteam.NewEnv(kind, rng)
	agent := redteam.NewAgent(obsDim, redteam.DefaultHyper(), rng)
	curve := []float64{evalAgent(agent, env, 12)}
	for i := 0; i < iters; i++ {
		agent.Train(env, batch)
		curve = append(curve, evalAgent(agent, env, 12))
	}
	return curve
}

func main() {
	seed := flag.Int64("seed", 1337, "masterSeed (reproducible)")
	iters := flag.Int("iters", 40, "PPO iterations for the learning curve")
	batch := flag.Int("batch", 10, "PPO episodes per iteration")
	gens := flag.Int("generations", 25, "PBT/QD co-training generations")
	pop := flag.Int("pop", 6, "PBT population size")
	jsonOut := flag.String("json", "", "optional path to write the run result as JSON (for the console)")
	flag.Parse()

	obsDim := len(redteam.NewEnv(redteam.DefPhorvexFixed, rand.New(rand.NewSource(1))).Obs())
	fmt.Printf("P-REDTEAM PRODUCTION RL ADVERSARY — Recurrent-PPO + PBT + Quality-Diversity\n")
	fmt.Printf("seed=%d  iters=%d  batch=%d  | PBT pop=%d gens=%d  (effects-only POMDP; NO ML in Phorvex.Decide)\n\n", *seed, *iters, *batch, *pop, *gens)

	type cv struct {
		label string
		c     []float64
	}
	curves := []cv{
		{"SHIPPED (λ-fix + steer-fix)", learningCurve(redteam.DefPhorvexFixed, obsDim, *seed, *iters, *batch)},
		{"λ-fix only (pre steer-fix)", learningCurve(redteam.DefPhorvexLambdaOnly, obsDim, *seed, *iters, *batch)},
		{"OLD (pre any fix)", learningCurve(redteam.DefPhorvexOld, obsDim, *seed, *iters, *batch)},
		{"d-randomequal (control)", learningCurve(redteam.DefRandom, obsDim, *seed, *iters, *batch)},
	}
	fmt.Println("PRODUCTION LEARNING CURVES (single-agent greedy return per PPO iteration; rising = learning):")
	for _, x := range curves {
		fmt.Printf("  %-30s ", x.label)
		step := maxi(1, len(x.c)/12)
		for i := 0; i < len(x.c); i += step {
			fmt.Printf("%5.1f ", x.c[i])
		}
		fmt.Printf("  | start=%.1f end=%.1f Δ=%+.1f\n", x.c[0], x.c[len(x.c)-1], x.c[len(x.c)-1]-x.c[0])
	}

	// PBT/QD co-training vs the λ-fix-only Phorvex — the novel-path discovery engine; this is the
	// state in which the RL FOUND the dispersion-steer (now closed by the shipped steer-fix).
	rng := rand.New(rand.NewSource(*seed))
	ct := redteam.NewCoTrainer(*pop, obsDim, redteam.DefPhorvexLambdaOnly, 12.0, rng)
	for g := 0; g < *gens; g++ {
		ct.Generation(*batch)
	}
	fmt.Println("\nQD ARCHIVE vs λ-fix-only Phorvex — the strategy the RL discovered (now CLOSED by the steer-fix):")
	best := map[string]float64{}
	for _, e := range ct.Archive.Elites() {
		if e.Return > best[e.Strategy] {
			best[e.Strategy] = e.Return
		}
	}
	for s, r := range best {
		fmt.Printf("  [return %5.1f] %s\n", r, s)
	}
	fmt.Printf("  QD coverage (distinct behavior cells): %d\n", ct.Archive.Coverage())

	fmt.Println("\nHUMAN-APPROVAL GATE (discovered paths PROPOSED for review — NONE auto-promoted):")
	fmt.Printf("  gate.AutoEscalate() = %v\n", ct.Gate.AutoEscalate())
	for _, p := range ct.Gate.Proposals() {
		fmt.Printf("  proposed (return %.1f, approved=%v): %s\n", p.Return, p.Approved, p.Strategy)
	}

	fmt.Println("\nVERDICT (computed):")
	fx, lo, old, rd := curves[0].c, curves[1].c, curves[2].c, curves[3].c
	last := func(c []float64) float64 { return c[len(c)-1] }
	steerFixWorks := last(fx)-fx[0] < 4 && last(fx) < last(lo)/2
	fmt.Printf("  STEER-FIX neutralizes the dispersion-steer vs SHIPPED: %v  (SHIPPED held to %.1f vs λ-fix-only %.1f)\n", steerFixWorks, last(fx), last(lo))
	fmt.Printf("  the vuln WAS real (RL climbs vs λ-fix-only):           %v  (%.1f -> %.1f, Δ=%+.1f)\n", last(lo)-lo[0] > 4, lo[0], last(lo), last(lo)-lo[0])
	fmt.Printf("  RL climbs vs OLD (pre any fix):                        %v  (%.1f -> %.1f)\n", last(old)-old[0] > 4, old[0], last(old))
	fmt.Printf("  FLAT vs random (exploits structure, not noise):       %v  (final %.1f)\n", last(rd) < last(lo)/2, last(rd))
	steer := false
	for s := range best {
		if len(s) >= 5 && s[:5] == "DISPE" {
			steer = true
		}
	}
	fmt.Printf("  QD re-discovers the steer vs λ-fix-only (what the fix closes): %v\n", steer)

	if *jsonOut != "" {
		res := jsonResult{
			Seed: *seed, Iters: *iters, QDCoverage: ct.Archive.Coverage(),
			AutoEscalate:        ct.Gate.AutoEscalate(),
			SteerFixNeutralizes: steerFixWorks,
			VulnWasReal:         last(lo)-lo[0] > 4,
			FlatVsRandom:        last(rd) < last(lo)/2,
		}
		for _, x := range curves {
			res.Curves = append(res.Curves, jsonCurve{x.label, x.c, x.c[0], last(x.c), last(x.c) - x.c[0]})
		}
		for s, r := range best {
			res.QD = append(res.QD, jsonProposal{Strategy: s, Return: r})
		}
		for _, p := range ct.Gate.Proposals() {
			res.Proposals = append(res.Proposals, jsonProposal{Strategy: p.Strategy, Return: p.Return, Approved: p.Approved})
		}
		if b, err := json.MarshalIndent(res, "", "  "); err == nil {
			if err := os.WriteFile(*jsonOut, b, 0o644); err == nil {
				fmt.Printf("\nwrote JSON result to %s\n", *jsonOut)
			}
		}
	}
}

func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}
