package graph

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// referenceReachScore derives shortest path lengths a layer at a time. It is
// intentionally separate from reachScore's FIFO traversal and early completion.
func referenceReachScore(adjacency map[string]map[string]struct{}, start string, assetOf map[string]float64) float64 {
	distance := map[string]int{start: 0}
	frontier := []string{start}
	for hop := 1; hop <= maxHops && len(frontier) > 0; hop++ {
		next := make([]string, 0)
		for _, cur := range frontier {
			for neighbor := range adjacency[cur] {
				if _, seen := distance[neighbor]; seen {
					continue
				}
				distance[neighbor] = hop
				next = append(next, neighbor)
			}
		}
		frontier = next
	}

	var score float64
	for key, value := range assetOf {
		if hop, reached := distance[key]; reached && hop > 0 && hop <= maxHops {
			score += value * pow(hopDecay, hop-1)
		}
	}
	return score
}

func TestReachScoreMatchesReferenceExhaustiveSmallDirectedGraphs(t *testing.T) {
	vertices := []string{"a", "b", "c"}
	edges := make([][2]string, 0, len(vertices)*len(vertices))
	for _, from := range vertices {
		for _, to := range vertices {
			edges = append(edges, [2]string{from, to})
		}
	}

	for edgeMask := 0; edgeMask < 1<<len(edges); edgeMask++ {
		adjacency := make(map[string]map[string]struct{}, len(vertices))
		for _, key := range vertices {
			adjacency[key] = map[string]struct{}{}
		}
		for i, edge := range edges {
			if edgeMask&(1<<i) != 0 {
				adjacency[edge[0]][edge[1]] = struct{}{}
			}
		}
		g := &Graph{adjacency: adjacency}
		for assetMask := 0; assetMask < 1<<len(vertices); assetMask++ {
			assetOf := map[string]float64{}
			for i, key := range vertices {
				if assetMask&(1<<i) != 0 {
					assetOf[key] = float64(i + 1)
				}
			}
			// The absent start covers malformed/internal graphs independently of
			// the ordinary starts and asset subsets.
			for _, start := range []string{"a", "b", "c", "absent"} {
				want := referenceReachScore(adjacency, start, assetOf)
				if got := g.reachScore(start, assetOf); got != want {
					t.Fatalf("edgeMask=%09b assetMask=%03b start=%q: got %v, want %v", edgeMask, assetMask, start, got, want)
				}
			}
		}
	}
}

func TestReachScorePreservesUnknownTraversalAndHopBoundary(t *testing.T) {
	adjacency := map[string]map[string]struct{}{
		"start":   {"unknown": {}},
		"unknown": {"hop2": {}, "cycle": {}},
		"cycle":   {"unknown": {}, "hop3": {}},
		"hop2":    {"hop3": {}},
		"hop3":    {"hop4": {}},
		"hop4":    {"beyond": {}},
	}
	assets := map[string]float64{
		"start":   64,
		"hop2":    8,
		"hop3":    4,
		"hop4":    16,
		"beyond":  1024,
		"missing": 2048,
	}
	g := &Graph{adjacency: adjacency}
	// hop2 contributes 4, hop3 contributes 1, and hop4/beyond/missing are
	// excluded. The unknown hop-1 vertex must still be traversed.
	if got, want := g.reachScore("start", assets), 5.0; got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestReachScoreDoesNotMutateTopology(t *testing.T) {
	g := &Graph{
		adjacency: map[string]map[string]struct{}{
			"a": {"b": {}, "c": {}},
			"b": {"c": {}},
			"c": {},
		},
		neighbors1: map[string][]string{
			"a": {"b", "c"},
			"b": {"c"},
		},
	}
	adjacencyBefore := cloneAdjacency(g.adjacency)
	neighborsBefore := cloneNeighbors(g.neighbors1)
	_ = g.reachScore("a", map[string]float64{"a": 1, "b": 2, "c": 3})
	if !reflect.DeepEqual(g.adjacency, adjacencyBefore) {
		t.Fatalf("adjacency mutated: got %v, want %v", g.adjacency, adjacencyBefore)
	}
	if !reflect.DeepEqual(g.neighbors1, neighborsBefore) {
		t.Fatalf("neighbors mutated: got %v, want %v", g.neighbors1, neighborsBefore)
	}
}

func TestBuildScoresMatchReferenceAcrossTopologies(t *testing.T) {
	tests := []struct {
		name string
		pods []PodNode
		pols []NetPol
	}{
		{
			name: "complete",
			pods: []PodNode{
				{Namespace: "ns", Name: "a", AssetValue: 1},
				{Namespace: "ns", Name: "b", AssetValue: 2},
				{Namespace: "ns", Name: "c", AssetValue: 4},
			},
		},
		{
			name: "disconnected",
			pods: []PodNode{
				{Namespace: "ns", Name: "a", AssetValue: 1},
				{Namespace: "ns", Name: "b", AssetValue: 2},
				{Namespace: "other", Name: "c", AssetValue: 4},
			},
			pols: []NetPol{
				{Namespace: "ns", HasIngressType: true, HasEgressType: true},
				{Namespace: "other", HasIngressType: true, HasEgressType: true},
			},
		},
		{
			name: "duplicate-keys-last-asset-wins",
			pods: []PodNode{
				{Namespace: "ns", Name: "a", AssetValue: 1},
				{Namespace: "ns", Name: "a", AssetValue: 8},
				{Namespace: "ns", Name: "b", AssetValue: 2},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := Build(Input{Pods: tc.pods, NetPols: tc.pols})
			assetOf := map[string]float64{}
			for _, pod := range tc.pods {
				assetOf[pod.key()] = pod.AssetValue
			}
			wantRaw := map[string]float64{}
			maxRaw := 0.0
			for _, pod := range tc.pods {
				wantRaw[pod.key()] = referenceReachScore(g.adjacency, pod.key(), assetOf)
				if wantRaw[pod.key()] > maxRaw {
					maxRaw = wantRaw[pod.key()]
				}
			}
			for key, want := range wantRaw {
				if got := g.rawScore[key]; got != want {
					t.Errorf("raw %s: got %v, want %v", key, got, want)
				}
				wantNormalized := 0.0
				if maxRaw > 0 {
					wantNormalized = want / maxRaw
				}
				if got := g.normScore[key]; got != wantNormalized {
					t.Errorf("normalized %s: got %v, want %v", key, got, wantNormalized)
				}
			}

			// Neighbor content and count are still the exact one-hop adjacency.
			for key, neighbors := range g.neighbors1 {
				got := append([]string(nil), neighbors...)
				sort.Strings(got)
				want := make([]string, 0, len(g.adjacency[key]))
				for neighbor := range g.adjacency[key] {
					want = append(want, neighbor)
				}
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("neighbors %s: got %v, want %v", key, got, want)
				}
				parts := splitKey(key)
				if gotCount := g.NeighborCount(parts[0], parts[1]); gotCount != len(want) {
					t.Errorf("neighbor count %s: got %d, want %d", key, gotCount, len(want))
				}
			}
		})
	}
}

func cloneAdjacency(in map[string]map[string]struct{}) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(in))
	for key, neighbors := range in {
		out[key] = make(map[string]struct{}, len(neighbors))
		for neighbor := range neighbors {
			out[key][neighbor] = struct{}{}
		}
	}
	return out
}

func cloneNeighbors(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for key, neighbors := range in {
		out[key] = append([]string(nil), neighbors...)
	}
	return out
}

func splitKey(key string) [2]string {
	namespace, name, ok := strings.Cut(key, "/")
	if !ok {
		// All Build keys contain one slash. Keep a deterministic fallback so a
		// malformed test failure is reported through NeighborCount as well.
		return [2]string{"", key}
	}
	return [2]string{namespace, name}
}
