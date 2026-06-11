/*
 * Phorvex Console (P-DASHBOARD-3) — subsystem read endpoints (Physics scan, Ablation,
 * Cluster status/configs). Each execs an EXISTING entrypoint (phorvex --scan / --ablation /
 * kubectl get) read-only and parses its real output. Nothing fabricated; raw text returned
 * alongside the parsed rows so the UI degrades to honest text if a format drifts.
 */

package console

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func (c *Config) execText(timeout time.Duration, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = c.HarnessDir
	cmd.Env = envBase()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// --- Physics scan (POST/GET /api/scan?ns=) ----------------------------------------------

type PhysWitness struct {
	Pod       string  `json:"pod"`
	ImageRare float64 `json:"imageRarity"`
	CoRes     float64 `json:"coResidency"`
	Slack     float64 `json:"slack"`
	PDBMin    int     `json:"pdbMinAvail"`
	MIGValid  bool    `json:"migValid"`
	EPSS      float64 `json:"epss"`
	GPU       bool    `json:"gpuPresent"`
}
type KillchainRow struct {
	Pod          string  `json:"pod"`
	Stage        string  `json:"stage"`
	AI           bool    `json:"ai"`
	PHold        float64 `json:"pHold"`
	PreemptMargin float64 `json:"preemptMargin"`
	ProjNextSec  float64 `json:"projNextStageSec"`
	Frontier     float64 `json:"infectionFrontier"`
}
type ScanResult struct {
	Platform  string         `json:"platform"`
	Nodes     int            `json:"nodes"`
	Pods      int            `json:"pods"`
	Witness   []PhysWitness  `json:"witness"`
	Killchain []KillchainRow `json:"killchain"`
	EMR       struct {
		Baseline float64 `json:"baseline"`
		Scarcity float64 `json:"scarcity"`
		Lift     float64 `json:"lift"`
		Note     string  `json:"note"`
	} `json:"emr"`
	Raw string `json:"raw"`
}

var (
	reWitness   = regexp.MustCompile(`^\s*(\S+/\S+)\s+K8s:\s+imgRarity=([\d.]+)\s+coRes=([\d.]+)\s+slack=([\d.]+)\s+pdbMinAvail=(-?\d+)\s+migValid=(\w+)\s+epss=([\d.]+)`)
	reKill      = regexp.MustCompile(`^\s*(\S+/\S+)\s+stage=(\S+)\s+\[([^\]]+)\]\s+PHold=([\d.]+)\s+PreemptMargin=([\d.]+)\s+ProjNextStage=([\d.]+)s\s+infectionFrontier=([\d.]+)`)
	rePlatform  = regexp.MustCompile(`platform-adapter:\s*(\S+)`)
	reNodesPods = regexp.MustCompile(`nodes:\s*(\d+)\s+pods:\s*(\d+)`)
	reEMRline   = regexp.MustCompile(`(baseline|scarcity).*ratio\s*=\s*([\d.]+)`)
	reEMRlift   = regexp.MustCompile(`lift\s*=\s*([\d.]+)x\s*(?:\(([^)]*)\))?`)
)

// contextRe validates a kubeconfig context name (EKS ARNs carry :/@.-) for the exec arg.
var contextRe = regexp.MustCompile(`^[a-zA-Z0-9._:@/-]{1,200}$`)

func (c *Config) Scan(ns, kubeContext, promURL string) ScanResult {
	if !scenarioRe.MatchString(ns) { // reuse the safe-name guard for the namespace arg
		ns = ""
	}
	args := []string{"--scan"}
	if ns != "" {
		args = append(args, "--scan-namespace", ns)
	}
	if kubeContext != "" && contextRe.MatchString(kubeContext) {
		args = append(args, "--context", kubeContext) // DERIVED by the console, never hardcoded
	}
	if promURL != "" {
		// SSRF-validate the caller-supplied Prometheus URL before phorvex fetches it
		// (loopback/allowlist only; IMDS/link-local blocked). Unsafe => drop -> honest-absent telemetry.
		if _, err := validateFetchTarget(promURL, c.MetricsAllow); err == nil {
			args = append(args, "--prometheus-url", promURL)
		}
	}
	raw, _ := c.execText(90*time.Second, c.PhorvexBin, args...)
	res := ScanResult{Raw: raw}
	for _, ln := range strings.Split(raw, "\n") {
		if m := reWitness.FindStringSubmatch(ln); m != nil {
			res.Witness = append(res.Witness, PhysWitness{Pod: m[1], ImageRare: atof(m[2]), CoRes: atof(m[3]), Slack: atof(m[4]), PDBMin: int(atof(m[5])), MIGValid: m[6] == "true", EPSS: atof(m[7])})
		} else if m := reKill.FindStringSubmatch(ln); m != nil {
			res.Killchain = append(res.Killchain, KillchainRow{Pod: m[1], Stage: m[2], AI: strings.Contains(m[3], "AI"), PHold: atof(m[4]), PreemptMargin: atof(m[5]), ProjNextSec: atof(m[6]), Frontier: atof(m[7])})
		} else if m := rePlatform.FindStringSubmatch(ln); m != nil {
			res.Platform = m[1]
		} else if m := reNodesPods.FindStringSubmatch(ln); m != nil {
			res.Nodes = int(atof(m[1]))
			res.Pods = int(atof(m[2]))
		} else if m := reEMRline.FindStringSubmatch(ln); m != nil {
			if m[1] == "baseline" {
				res.EMR.Baseline = atof(m[2])
			} else {
				res.EMR.Scarcity = atof(m[2])
			}
		} else if m := reEMRlift.FindStringSubmatch(ln); m != nil {
			res.EMR.Lift = atof(m[1])
			res.EMR.Note = m[2]
		}
	}
	// [P4-dash null-crash FIX] NEVER return a nil slice — Go marshals nil as JSON `null`, and the
	// frontend reads `.length`/`.map` on it. Emit `[]` so an empty scan renders a clean empty-state.
	if res.Witness == nil {
		res.Witness = []PhysWitness{}
	}
	if res.Killchain == nil {
		res.Killchain = []KillchainRow{}
	}
	return res
}

// --- Live ablation (GET /api/ablation?ns=) ----------------------------------------------

type AblationResult struct {
	Ratio          float64 `json:"ratio"`
	P1PerDollar     float64 `json:"p1PerDollar"`
	RandomPerDollar float64 `json:"randomPerDollar"`
	Ran            bool    `json:"ran"`
	Note           string  `json:"note"`
	Raw            string  `json:"raw"`
}

// the --ablation entrypoint prints a JSON object with ratio/p1PerDollar/randomPerDollar.
var reAblJSON = regexp.MustCompile(`(?s)\{[^{}]*"ratio"\s*:\s*[\d.eE+-]+[^{}]*\}`)

func (c *Config) Ablation(ns string) AblationResult {
	if !scenarioRe.MatchString(ns) {
		ns = ""
	}
	args := []string{"--ablation"}
	if ns != "" {
		args = append(args, "--ablation-namespace", ns)
	}
	raw, _ := c.execText(90*time.Second, c.PhorvexBin, args...)
	res := AblationResult{Raw: raw, Note: "live seed-pinned P1-vs-uniform-random recon-per-dollar (heavy-tailed fleet needed for lift > 1)"}
	// the brain prints the ablation as a JSON object — parse it, don't regex the text.
	if m := reAblJSON.FindString(raw); m != "" {
		var j struct {
			Ratio, P1PerDollar, RandomPerDollar float64
		}
		if err := json.Unmarshal([]byte(m), &j); err == nil {
			res.Ratio, res.P1PerDollar, res.RandomPerDollar, res.Ran = j.Ratio, j.P1PerDollar, j.RandomPerDollar, true
		}
	}
	return res
}

// --- Cluster status + configs (GET /api/cluster) ----------------------------------------
// Reads the PhorvexPolicy CRDs (spec + Status) via kubectl — the real operator control-plane
// state (HEALTH) and the editable policy surface (CONFIGS, read-only here).

type PolicyView struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Tenant    string          `json:"tenant"`
	Mode      string          `json:"mode"`
	Spec      json.RawMessage `json:"spec"`
	Status    json.RawMessage `json:"status"`
}

func (c *Config) ClusterPolicies() ([]PolicyView, bool) {
	raw, err := c.execText(15*time.Second, "kubectl", "get", "phorvexpolicy.phorvex.ai", "-A", "-o", "json")
	if err != nil || !strings.Contains(raw, "items") {
		return nil, false
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name, Namespace string
			} `json:"metadata"`
			Spec   json.RawMessage `json:"spec"`
			Status json.RawMessage `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &list) != nil {
		return nil, false
	}
	var out []PolicyView
	for _, it := range list.Items {
		var sp struct {
			Tenant, Mode string
		}
		_ = json.Unmarshal(it.Spec, &sp)
		out = append(out, PolicyView{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Tenant: sp.Tenant, Mode: sp.Mode, Spec: it.Spec, Status: it.Status})
	}
	return out, true
}
