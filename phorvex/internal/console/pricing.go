/*
 * Phorvex Console — DYNAMIC cloud pricing for the cost model.
 *
 * The defense-overhead $ is computed from the REAL infrastructure cost of the cluster detected
 * in Connect: the live node instance types × the cloud provider's on-demand list price, NOT a
 * flat placeholder. Provider/region/instance-type are read live from the nodes; the price comes
 * from a built-in on-demand list-price table (clearly labeled as list prices). Unknown types fall
 * back to a same-family estimate so the number is never silently zero.
 */

package console

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// awsOnDemand is AWS EC2 on-demand list prices ($/hour), us-east-2 (≈ us-east-1). List prices,
// not contract/reserved — the cost panel labels them as such; swap for your contract rate.
var awsOnDemand = map[string]float64{
	// general purpose
	"t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
	"m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m5.4xlarge": 0.768,
	"m6i.large": 0.096, "m6i.xlarge": 0.192, "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
	// GPU (NVIDIA)
	"g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752, "g4dn.4xlarge": 1.204, "g4dn.12xlarge": 3.912,
	"g5.xlarge": 1.006, "g5.2xlarge": 1.212, "g5.12xlarge": 5.672, "g5.48xlarge": 16.288,
	"p3.2xlarge": 3.06, "p3.8xlarge": 12.24, "p4d.24xlarge": 32.7726, "p5.48xlarge": 98.32,
}

// priceForType returns the on-demand $/hr for an AWS instance type, with a same-family fallback so
// an unrecognized type still yields a sensible non-zero estimate (ok=false marks it an estimate).
func priceForType(t string) (price float64, ok bool) {
	if p, found := awsOnDemand[t]; found {
		return p, true
	}
	// family-prefix fallback: pick the cheapest known member of the same family as a floor.
	fam := t
	if i := strings.IndexByte(t, '.'); i >= 0 {
		fam = t[:i]
	}
	best := 0.0
	for k, p := range awsOnDemand {
		if strings.HasPrefix(k, fam+".") && (best == 0 || p < best) {
			best = p
		}
	}
	if best > 0 {
		return best, false
	}
	// last-resort generic estimate by GPU vs CPU naming.
	if strings.HasPrefix(fam, "g") || strings.HasPrefix(fam, "p") {
		return 1.0, false
	}
	return 0.1, false
}

// NodePrice is one instance-type group in the cluster with its live count and on-demand price.
type NodePrice struct {
	InstanceType string  `json:"instanceType"`
	Count        int     `json:"count"`
	GPU          bool    `json:"gpu"`
	PricePerHr   float64 `json:"pricePerHr"`
	Estimated    bool    `json:"estimated"` // true = same-family estimate (type not in the table)
}

// ClusterPricing is the live, provider-aware infrastructure cost of the detected cluster.
type ClusterPricing struct {
	Provider      string      `json:"provider"` // AWS | GCP | Azure | unknown
	Region        string      `json:"region"`
	Nodes         []NodePrice `json:"nodes"`
	TotalPerHr    float64     `json:"totalPerHr"`
	TotalPerYear  float64     `json:"totalPerYear"`
	GPUPricePerHr float64     `json:"gpuPricePerHr"`
	GPUCount      int         `json:"gpuCount"`
	Source        string      `json:"source"`
	Available     bool        `json:"available"`
}

// clusterPricing reads the live nodes of the selected cluster and prices them from the on-demand
// table — the basis for the dynamic, real defense-overhead cost.
func (s *Server) clusterPricing(ctxName string) ClusterPricing {
	out := ClusterPricing{Provider: "unknown", Source: "AWS EC2 on-demand list prices (us-east-2)", Nodes: []NodePrice{}}
	cs, err := clientForContext(ctxName)
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return out
	}
	type grp struct {
		count int
		gpu   bool
	}
	byType := map[string]*grp{}
	for i := range nodes.Items {
		n := &nodes.Items[i]
		if out.Provider == "unknown" {
			pid := n.Spec.ProviderID
			switch {
			case strings.HasPrefix(pid, "aws:"):
				out.Provider = "AWS"
			case strings.HasPrefix(pid, "gce:"):
				out.Provider = "GCP"
			case strings.HasPrefix(pid, "azure:"):
				out.Provider = "Azure"
			}
		}
		if out.Region == "" {
			out.Region = n.Labels["topology.kubernetes.io/region"]
		}
		it := n.Labels["node.kubernetes.io/instance-type"]
		if it == "" {
			it = n.Labels["beta.kubernetes.io/instance-type"]
		}
		if it == "" {
			it = "unknown"
		}
		g := byType[it]
		if g == nil {
			g = &grp{}
			byType[it] = g
		}
		g.count++
		if q, ok := n.Status.Allocatable["nvidia.com/gpu"]; ok && q.Value() > 0 {
			g.gpu = true
			out.GPUCount += int(q.Value())
		}
	}
	for it, g := range byType {
		price, known := priceForType(it)
		np := NodePrice{InstanceType: it, Count: g.count, GPU: g.gpu, PricePerHr: price, Estimated: !known}
		out.Nodes = append(out.Nodes, np)
		out.TotalPerHr += price * float64(g.count)
		if g.gpu && price > out.GPUPricePerHr {
			out.GPUPricePerHr = price
		}
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].PricePerHr > out.Nodes[j].PricePerHr })
	out.TotalPerYear = out.TotalPerHr * 8760
	out.Available = len(out.Nodes) > 0
	return out
}

// phorvexOperatorCost computes the REAL annual cost of running Phorvex on the cluster — NOT a
// magic percentage. It finds the live operator pod(s), takes each pod's resource footprint (the
// larger of its CPU or memory request as a fraction of the node it actually runs on) and prices
// that fraction at the node's on-demand $/yr. This is literally what the operator reserves on real
// AWS hardware. Returns (0, "") when no operator pod is found (then the caller shows $0 — honest:
// nothing extra is running here).
func (s *Server) phorvexOperatorCost(ctxName string) (costPerYear float64, detail string) {
	cs, err := clientForContext(ctxName)
	if err != nil {
		return 0, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// the in-cluster operator carries this label; fall back to the controller label.
	var pods *corev1.PodList
	for _, sel := range []string{"app.kubernetes.io/name=phorvex", "control-plane=phorvex", "app=phorvex"} {
		if pl, e := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: sel}); e == nil && len(pl.Items) > 0 {
			pods = pl
			break
		}
	}
	if pods == nil {
		return 0, ""
	}
	nodeCache := map[string]*corev1.Node{}
	var cpuM, memMi int64
	instType := ""
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning || p.Spec.NodeName == "" {
			continue
		}
		var cpuReq, memReq int64 // milli-cpu, bytes
		for _, c := range p.Spec.Containers {
			if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
				cpuReq += q.MilliValue()
			}
			if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
				memReq += q.Value()
			}
		}
		node := nodeCache[p.Spec.NodeName]
		if node == nil {
			n, e := cs.CoreV1().Nodes().Get(ctx, p.Spec.NodeName, metav1.GetOptions{})
			if e != nil {
				continue
			}
			node = n
			nodeCache[p.Spec.NodeName] = n
		}
		it := node.Labels["node.kubernetes.io/instance-type"]
		price, _ := priceForType(it)
		nodeCPU := node.Status.Capacity.Cpu().MilliValue()
		nodeMem := node.Status.Capacity.Memory().Value()
		cpuFrac, memFrac := 0.0, 0.0
		if nodeCPU > 0 {
			cpuFrac = float64(cpuReq) / float64(nodeCPU)
		}
		if nodeMem > 0 {
			memFrac = float64(memReq) / float64(nodeMem)
		}
		frac := cpuFrac
		if memFrac > frac {
			frac = memFrac // the binding dimension — what the operator actually ties up on the node
		}
		costPerYear += frac * price * 8760
		cpuM += cpuReq
		memMi += memReq >> 20
		instType = it
	}
	if costPerYear > 0 {
		detail = fmt.Sprintf("Phorvex operator footprint %dm CPU / %dMi on %s", cpuM, memMi, instType)
	}
	return costPerYear, detail
}

// pricing is GET /api/pricing?target=<ctx> — the live cloud-priced infrastructure cost.
func (s *Server) pricing(w http.ResponseWriter, r *http.Request) {
	ctxName := r.URL.Query().Get("target")
	if ctxName != "" && !contextRe.MatchString(ctxName) {
		writeJSON(w, 400, map[string]string{"error": "invalid target context"})
		return
	}
	writeJSON(w, 200, s.clusterPricing(ctxName))
}
