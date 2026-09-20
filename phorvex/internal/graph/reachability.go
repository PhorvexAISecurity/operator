/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package graph builds the blast-radius / reachability graph (PRD §4.1 physics-
// model #2 / §5.2). Edges are the three ways compromise spreads: NETWORK
// reachability (NetworkPolicy), RBAC lateral movement (a pod whose SA can write/exec
// pods or read secrets reaches other workloads), and CO-LOCATION (same node). The
// blast-radius score of a pod = the asset-weighted, hop-decayed set of workloads its
// compromise can reach — "move the one whose compromise would spread furthest".
//
// NetworkPolicy semantics implemented: applies-to podSelector, ingress/egress
// policyTypes isolation, and pod/namespaceSelector peers. DELIBERATE
// OVER-APPROXIMATION (documented, and the SAFE direction for blast radius): ipBlock
// peers and port restrictions are ignored, so Phorvex never UNDER-estimates who can
// reach a crown jewel.
package graph

import (
	"k8s.io/apimachinery/pkg/labels"
)

// PodNode is a projected pod in the reachability graph.
type PodNode struct {
	Namespace      string
	Name           string
	Labels         map[string]string
	ServiceAccount string
	Node           string
	AssetValue     float64 // base value (labels+secrets); the graph adds reach on top
}

func (p PodNode) key() string { return p.Namespace + "/" + p.Name }

// NetPeer is a projected NetworkPolicy peer (one entry in from[]/to[]).
type NetPeer struct {
	IPBlock           bool
	HasPodSelector    bool
	PodSelector       labels.Selector
	HasNamespaceSel   bool
	NamespaceSelector labels.Selector
}

// NetRule is one ingress/egress rule. AllowAll marks an empty from/to (allow any).
type NetRule struct {
	AllowAll bool
	Peers    []NetPeer
}

// NetPol is a projected NetworkPolicy.
type NetPol struct {
	Namespace      string
	Selector       labels.Selector // applies-to (empty = all pods in namespace)
	HasIngressType bool
	HasEgressType  bool
	Ingress        []NetRule
	Egress         []NetRule
}

// Input is everything the graph needs, projected from live k8s objects by ingest.
type Input struct {
	Pods            []PodNode
	NetPols         []NetPol
	NamespaceLabels map[string]map[string]string
	// SubjectPerms is the resolved per-ServiceAccount lateral capability map
	// (ResolveRBAC output), keyed "ns/saName".
	SubjectPerms map[string]SubjectPerms
}

// Graph is the built reachability graph with per-pod blast-radius scores.
type Graph struct {
	pods       []PodNode
	index      map[string]int
	adjacency  map[string]map[string]struct{} // directed: A -> reachable B
	rawScore   map[string]float64
	normScore  map[string]float64
	neighbors1 map[string][]string
}

const (
	maxHops  = 3
	hopDecay = 0.5
)

// Build constructs the graph and computes blast-radius scores.
func Build(in Input) *Graph {
	g := &Graph{
		pods:       in.Pods,
		index:      make(map[string]int, len(in.Pods)),
		adjacency:  make(map[string]map[string]struct{}, len(in.Pods)),
		rawScore:   make(map[string]float64, len(in.Pods)),
		normScore:  make(map[string]float64, len(in.Pods)),
		neighbors1: make(map[string][]string, len(in.Pods)),
	}
	for i, p := range in.Pods {
		g.index[p.key()] = i
		g.adjacency[p.key()] = map[string]struct{}{}
	}

	// Pre-bucket policies by namespace for the applies-to test.
	polByNS := map[string][]NetPol{}
	for _, np := range in.NetPols {
		polByNS[np.Namespace] = append(polByNS[np.Namespace], np)
	}

	// Build directed edges A -> B (A's compromise can reach B).
	for _, a := range in.Pods {
		for _, b := range in.Pods {
			if a.key() == b.key() {
				continue
			}
			if edgeExists(a, b, polByNS, in.NamespaceLabels, in.SubjectPerms) {
				g.adjacency[a.key()][b.key()] = struct{}{}
			}
		}
	}
	for k, set := range g.adjacency {
		for nb := range set {
			g.neighbors1[k] = append(g.neighbors1[k], nb)
		}
	}

	// Blast radius via hop-decayed BFS over the union edge set.
	assetOf := map[string]float64{}
	for _, p := range in.Pods {
		assetOf[p.key()] = p.AssetValue
	}
	maxRaw := 0.0
	for _, a := range in.Pods {
		s := g.reachScore(a.key(), assetOf)
		g.rawScore[a.key()] = s
		if s > maxRaw {
			maxRaw = s
		}
	}
	for k, s := range g.rawScore {
		if maxRaw > 0 {
			g.normScore[k] = s / maxRaw
		}
	}
	return g
}

// edgeExists is true if A's compromise can reach B via network OR RBAC OR co-location.
func edgeExists(a, b PodNode, polByNS map[string][]NetPol, nsLabels map[string]map[string]string, perms map[string]SubjectPerms) bool {
	// RBAC lateral: A's SA can write/exec pods, read secrets, or impersonate within a
	// scope that includes B's namespace.
	if sp, ok := perms[a.Namespace+"/"+a.ServiceAccount]; ok && sp.HasLateral() {
		if sp.ClusterWide {
			return true
		}
		if _, inScope := sp.Namespaces[b.Namespace]; inScope {
			return true
		}
	}
	// Co-location: same node => shared-kernel reach.
	if a.Node != "" && a.Node == b.Node {
		return true
	}
	// Network: A egress allows B AND B ingress allows A.
	if egressAllowed(a, b, polByNS[a.Namespace], nsLabels) && ingressAllowed(b, a, polByNS[b.Namespace], nsLabels) {
		return true
	}
	return false
}

// ingressAllowed: can src reach dst on the network (from dst's ingress view)?
func ingressAllowed(dst, src PodNode, polsInDstNS []NetPol, nsLabels map[string]map[string]string) bool {
	isolating := false
	for _, np := range polsInDstNS {
		if !np.HasIngressType || !appliesTo(np, dst) {
			continue
		}
		isolating = true
		for _, rule := range np.Ingress {
			if ruleMatches(rule, src, np.Namespace, nsLabels) {
				return true
			}
		}
	}
	return !isolating // default-allow when no ingress policy selects dst
}

// egressAllowed: can src reach dst (from src's egress view)?
func egressAllowed(src, dst PodNode, polsInSrcNS []NetPol, nsLabels map[string]map[string]string) bool {
	isolating := false
	for _, np := range polsInSrcNS {
		if !np.HasEgressType || !appliesTo(np, src) {
			continue
		}
		isolating = true
		for _, rule := range np.Egress {
			if ruleMatches(rule, dst, np.Namespace, nsLabels) {
				return true
			}
		}
	}
	return !isolating
}

func appliesTo(np NetPol, p PodNode) bool {
	if np.Namespace != p.Namespace {
		return false
	}
	if np.Selector == nil {
		return true
	}
	return np.Selector.Matches(labels.Set(p.Labels))
}

// ruleMatches: does the candidate pod satisfy any peer of this rule?
func ruleMatches(rule NetRule, cand PodNode, polNS string, nsLabels map[string]map[string]string) bool {
	if rule.AllowAll {
		return true
	}
	for _, peer := range rule.Peers {
		if peer.IPBlock {
			continue // external CIDR — not a pod-to-pod edge
		}
		switch {
		case peer.HasPodSelector && !peer.HasNamespaceSel:
			// Same namespace as the policy, matching podSelector.
			if cand.Namespace == polNS && peer.PodSelector.Matches(labels.Set(cand.Labels)) {
				return true
			}
		case peer.HasNamespaceSel && !peer.HasPodSelector:
			if nsSelMatches(peer.NamespaceSelector, cand.Namespace, nsLabels) {
				return true
			}
		case peer.HasPodSelector && peer.HasNamespaceSel:
			if nsSelMatches(peer.NamespaceSelector, cand.Namespace, nsLabels) &&
				peer.PodSelector.Matches(labels.Set(cand.Labels)) {
				return true
			}
		default:
			// A peer with neither selector nor ipBlock is treated as allow-all.
			return true
		}
	}
	return false
}

func nsSelMatches(sel labels.Selector, ns string, nsLabels map[string]map[string]string) bool {
	if sel == nil {
		return true
	}
	return sel.Matches(labels.Set(nsLabels[ns]))
}

// reachScore: hop-decayed, asset-weighted out-reach from start (BFS to maxHops).
func (g *Graph) reachScore(start string, assetOf map[string]float64) float64 {
	remaining := len(assetOf)
	if _, ok := assetOf[start]; ok {
		remaining--
	}
	if remaining == 0 {
		return 0
	}

	visited := map[string]int{start: 0}
	queue := []string{start}
	score := 0.0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		hop := visited[cur]
		if hop >= maxHops {
			continue
		}
		for nb := range g.adjacency[cur] {
			if _, seen := visited[nb]; seen {
				continue
			}
			visited[nb] = hop + 1
			if asset, ok := assetOf[nb]; ok {
				score += asset * pow(hopDecay, hop) // hop 0 edge -> weight 1, next -> 0.5, ...
				remaining--
				if remaining == 0 {
					return score
				}
			}
			queue = append(queue, nb)
		}
	}
	return score
}

func pow(base float64, exp int) float64 {
	r := 1.0
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}

// BlastRadius returns the normalized [0,1] blast-radius score for a pod (0 if absent).
func (g *Graph) BlastRadius(ns, name string) float64 { return g.normScore[ns+"/"+name] }

// RawBlastRadius returns the un-normalized asset-weighted reach score.
func (g *Graph) RawBlastRadius(ns, name string) float64 { return g.rawScore[ns+"/"+name] }

// NeighborCount returns the number of directly-reachable (1-hop) workloads.
func (g *Graph) NeighborCount(ns, name string) int { return len(g.neighbors1[ns+"/"+name]) }

// Neighbors returns the directly-reachable workload keys ("ns/name").
func (g *Graph) Neighbors(ns, name string) []string { return g.neighbors1[ns+"/"+name] }

// Size returns the number of nodes.
func (g *Graph) Size() int { return len(g.pods) }
