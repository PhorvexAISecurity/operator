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
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

func (c *Config) execText(timeout time.Duration, bin string, args ...string) (string, error) {
	if c.Exec != nil {
		return c.Exec(timeout, bin, args...)
	}
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
	Pod          string  `json:"pod"`
	ImageRare    float64 `json:"imageRarity"`
	CoRes        float64 `json:"coResidency"`
	Slack        float64 `json:"slack"`
	PDBMin       int     `json:"pdbMinAvail"`
	MIGValid     bool    `json:"migValid"`
	EPSS         float64 `json:"epss"`
	Stateful     bool    `json:"stateful"` // StatefulSet/Job-owned or PVC-backed — rotate is auto-vetoed, quarantine preserves state
	GPU          bool    `json:"gpuPresent"`
	VRAMFraction float64 `json:"vramFraction"` // live DCGM GPU half (0 when GPUPresent=false)
	SMOccupancy  float64 `json:"smOccupancy"`
	LinkBW       float64 `json:"linkBandwidth"`
}
type KillchainRow struct {
	Pod           string  `json:"pod"`
	Stage         string  `json:"stage"`
	AI            bool    `json:"ai"`
	PHold         float64 `json:"pHold"`
	PreemptMargin float64 `json:"preemptMargin"`
	ProjNextSec   float64 `json:"projNextStageSec"`
	Frontier      float64 `json:"infectionFrontier"`
}
type ScanResult struct {
	Platform  string         `json:"platform"`
	Nodes     int            `json:"nodes"`
	Pods      int            `json:"pods"`
	NodeList  []NodeInfo     `json:"nodeList"` // per-node capacity from the scan (surfaces GPU nodes)
	Witness   []PhysWitness  `json:"witness"`
	Killchain []KillchainRow `json:"killchain"`
	// GraphNodes + GraphEdges are the live reachability graph (P-GRAPH) the Discovered
	// blast-radius map renders: directed lateral-movement edges (network + RBAC + co-location).
	GraphNodes []GraphNode `json:"graphNodes"`
	GraphEdges []GraphEdge `json:"graphEdges"`
	EMR        struct {
		Baseline float64 `json:"baseline"`
		Scarcity float64 `json:"scarcity"`
		Lift     float64 `json:"lift"`
		Note     string  `json:"note"`
	} `json:"emr"`
	Raw string `json:"raw"`
}

// NodeInfo is one cluster node's allocatable capacity as the scan reported it. AllocGPU > 0
// marks a GPU node — the reason the platform adapter resolves to eks-gpu rather than generic-k8s.
type NodeInfo struct {
	Name       string `json:"name"`
	AllocCPUm  int    `json:"allocCPUm"` // millicores
	AllocMemMi int    `json:"allocMemMi"`
	AllocGPU   int    `json:"allocGPU"`
	MIGKinds   int    `json:"migKinds"`
}

// GraphNode is one workload in the reachability graph (key = "ns/pod").
type GraphNode struct {
	Key   string  `json:"key"`
	Blast float64 `json:"blast"`
	AI    bool    `json:"ai"`
	UID   string  `json:"uid,omitempty"` // Pod epoch; absent from older scanner output
}

// GraphEdge is a directed lateral-movement path src -> dst (keys "ns/pod").
type GraphEdge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

var (
	reWitness   = regexp.MustCompile(`^\s*(\S+/\S+)\s+K8s:\s+imgRarity=([\d.]+)\s+coRes=([\d.]+)\s+slack=([\d.]+)\s+pdbMinAvail=(-?\d+)\s+migValid=(\w+)\s+epss=([\d.]+)(?:\s+stateful=(\w+))?`)
	reKill      = regexp.MustCompile(`^\s*(\S+/\S+)\s+stage=(\S+)\s+\[([^\]]+)\]\s+PHold=([\d.]+)\s+PreemptMargin=([\d.]+)\s+ProjNextStage=([\d.]+)s\s+infectionFrontier=([\d.]+)`)
	reNode      = regexp.MustCompile(`^\s*NODE\s+(\S+/\S+)\s+blast=([\d.]+)\s+ai=([01])(?:\s+uid=([a-zA-Z0-9-]+))?`)
	reEdge      = regexp.MustCompile(`^\s*EDGE\s+(\S+/\S+)\s+->\s+(\S+/\S+)`)
	reAI        = regexp.MustCompile(`AI:\s*VRAMfrac=([\d.]+)\s+SM=([\d.]+)\s+link=([\d.]+)\s+modelRarity=([\d.]+)`)
	rePlatform  = regexp.MustCompile(`platform-adapter:\s*(\S+)`)
	reNodesPods = regexp.MustCompile(`nodes:\s*(\d+)\s+pods:\s*(\d+)`)
	reK8sNode   = regexp.MustCompile(`^\s*node\s+(\S+)\s+allocCPU=(\d+)m\s+allocMem=(\d+)Mi\s+allocGPU=(\d+)\s+migKinds=(\d+)`)
	reEMRline   = regexp.MustCompile(`(baseline|scarcity).*ratio\s*=\s*([\d.]+)`)
	reEMRlift   = regexp.MustCompile(`lift\s*=\s*([\d.]+)x\s*(?:\(([^)]*)\))?`)
)

// contextRe validates a kubeconfig context name (EKS ARNs carry :/@.-) for the exec arg.
var contextRe = regexp.MustCompile(`^[a-zA-Z0-9._:@/-]{1,200}$`)

func (c *Config) Scan(ns, kubeContext, promURL string) (ScanResult, error) {
	if !scenarioRe.MatchString(ns) { // reuse the safe-name guard for the namespace arg
		ns = ""
	}
	args := []string{"--scan"}
	if ns != "" {
		args = append(args, "--scan-namespace", ns)
	}
	if !isLocalTargetAlias(kubeContext) && contextRe.MatchString(kubeContext) {
		args = append(args, "--context", kubeContext) // DERIVED by the console, never hardcoded
	}
	if promURL != "" {
		// SSRF-validate the caller-supplied Prometheus URL before phorvex fetches it
		// (loopback/allowlist only; IMDS/link-local blocked). Unsafe => drop -> honest-absent telemetry.
		if _, err := validateFetchTarget(promURL, c.MetricsAllow); err == nil {
			args = append(args, "--prometheus-url", promURL)
		}
	}
	// Feed the EPSS exploitability cache to the scan child (execText uses a curated env, so pass it
	// explicitly) — makes the physics EPSS leg data-driven in the dashboard scan, not honest-absent.
	if p := os.Getenv("PHORVEX_EPSS_CACHE"); p != "" {
		args = append(args, "--epss-cache", p)
	}
	raw, err := c.execText(90*time.Second, c.PhorvexBin, args...)
	if err != nil {
		return ScanResult{}, fmt.Errorf("live scan unavailable: %w: %s", err, strings.TrimSpace(raw))
	}
	// A successful process with an unrecognised report is not evidence of an empty cluster.
	if !rePlatform.MatchString(raw) || !reNodesPods.MatchString(raw) {
		return ScanResult{}, fmt.Errorf("live scan unavailable: scanner returned no valid cluster snapshot")
	}
	res := ScanResult{Raw: raw}
	for _, ln := range strings.Split(raw, "\n") {
		if m := reWitness.FindStringSubmatch(ln); m != nil {
			pw := PhysWitness{Pod: m[1], ImageRare: atof(m[2]), CoRes: atof(m[3]), Slack: atof(m[4]), PDBMin: int(atof(m[5])), MIGValid: m[6] == "true", EPSS: atof(m[7])}
			if len(m) > 8 && m[8] != "" {
				pw.Stateful = m[8] == "true" // StatefulSet/Job/PVC-backed — the stateful-safe physics signal
			}
			// the same scan line carries the GPU half when a DCGM feed answered for this pod.
			if a := reAI.FindStringSubmatch(ln); a != nil {
				pw.GPU, pw.VRAMFraction, pw.SMOccupancy, pw.LinkBW = true, atof(a[1]), atof(a[2]), atof(a[3])
			}
			res.Witness = append(res.Witness, pw)
		} else if m := reKill.FindStringSubmatch(ln); m != nil {
			res.Killchain = append(res.Killchain, KillchainRow{Pod: m[1], Stage: m[2], AI: strings.Contains(m[3], "AI"), PHold: atof(m[4]), PreemptMargin: atof(m[5]), ProjNextSec: atof(m[6]), Frontier: atof(m[7])})
		} else if m := reNode.FindStringSubmatch(ln); m != nil {
			res.GraphNodes = append(res.GraphNodes, GraphNode{Key: m[1], Blast: atof(m[2]), AI: m[3] == "1", UID: m[4]})
		} else if m := reEdge.FindStringSubmatch(ln); m != nil {
			res.GraphEdges = append(res.GraphEdges, GraphEdge{Src: m[1], Dst: m[2]})
		} else if m := rePlatform.FindStringSubmatch(ln); m != nil {
			res.Platform = m[1]
		} else if m := reNodesPods.FindStringSubmatch(ln); m != nil {
			res.Nodes = int(atof(m[1]))
			res.Pods = int(atof(m[2]))
		} else if m := reK8sNode.FindStringSubmatch(ln); m != nil {
			res.NodeList = append(res.NodeList, NodeInfo{
				Name:      m[1],
				AllocCPUm: int(atof(m[2])), AllocMemMi: int(atof(m[3])),
				AllocGPU: int(atof(m[4])), MIGKinds: int(atof(m[5])),
			})
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
	if res.GraphNodes == nil {
		res.GraphNodes = []GraphNode{}
	}
	if res.GraphEdges == nil {
		res.GraphEdges = []GraphEdge{}
	}
	if res.NodeList == nil {
		res.NodeList = []NodeInfo{}
	}
	return res, nil
}

// --- Live ablation (GET /api/ablation?ns=) ----------------------------------------------

type AblationResult struct {
	Ratio           float64 `json:"ratio"`
	P1PerDollar     float64 `json:"p1PerDollar"`
	RandomPerDollar float64 `json:"randomPerDollar"`
	Ran             bool    `json:"ran"`
	Note            string  `json:"note"`
	Raw             string  `json:"raw"`
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
// Reads the PhorvexPolicy CRDs (spec + Status) via the Kubernetes API (dynamic client) — the
// real operator control-plane state. Works identically on a dev box (kubeconfig) and as an
// in-cluster Deployment (the pod ServiceAccount), so the live policy view needs no kubectl.

type PolicyView struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Tenant    string          `json:"tenant"`
	Mode      string          `json:"mode"`
	Spec      json.RawMessage `json:"spec"`
	Status    json.RawMessage `json:"status"`
}

// phorvexPolicyGVR is the PhorvexPolicy custom resource (phorvex.ai/v1alpha1).
var phorvexPolicyGVR = schema.GroupVersionResource{Group: "phorvex.ai", Version: "v1alpha1", Resource: "phorvexpolicies"}

func (c *Config) ClusterPolicies() ([]PolicyView, bool) {
	rc, err := restConfigFor("")
	if err != nil {
		return nil, false
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	list, err := dyn.Resource(phorvexPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false // CRD absent or no API access => honestly unavailable
	}
	out := []PolicyView{}
	for i := range list.Items {
		obj := list.Items[i].Object
		spec, _ := obj["spec"].(map[string]any)
		status, _ := obj["status"].(map[string]any)
		specRaw, _ := json.Marshal(spec)
		statusRaw, _ := json.Marshal(status)
		tenant, _ := spec["tenant"].(string)
		mode, _ := spec["mode"].(string)
		out = append(out, PolicyView{
			Name: list.Items[i].GetName(), Namespace: list.Items[i].GetNamespace(),
			Tenant: tenant, Mode: mode, Spec: specRaw, Status: statusRaw,
		})
	}
	return out, true
}
