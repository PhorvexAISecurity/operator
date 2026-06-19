/*
 * Phorvex Console (P4a) — DERIVE cluster targets from the operator's kubeconfig.
 *
 * The Connect step's targets are DERIVED from the live kubeconfig contexts — never a baked
 * context string (the P4a do-not-hardcode tripwire). When the operator adds their EKS
 * kubeconfig (`aws eks update-kubeconfig …`), that context appears as a runnable, read-only
 * scan target automatically. GPU magnitudes remain [SP-0-PENDING-P4].
 */

package console

import (
	"sort"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
)

// kubeContexts returns the context names from the operator's kubeconfig (KUBECONFIG / the
// default loading rules). Read-only; never mutates the kubeconfig.
func kubeContexts() []string {
	cfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil || cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// classifyContext maps a kubeconfig context name to a target label/note WITHOUT inventing a
// context string — the ID/Context IS the real kubeconfig context.
func classifyContext(ctx string) ClusterTarget {
	lc := strings.ToLower(ctx)
	t := ClusterTarget{ID: ctx, Context: ctx, Runnable: true}
	switch {
	case strings.Contains(lc, "vcluster") || strings.Contains(lc, "vc-"):
		t.Provider = "vCluster"
		t.Label = "vCluster · " + shortContext(ctx)
		t.Note = "virtual cluster (vCluster) on the host platform — full scan/operate/attack, same pipeline as the physical providers"
	case strings.Contains(lc, "kind"):
		t.Provider = "kind"
		t.Label = "kind (local) · " + ctx
		t.Note = "local kind cluster (read-only scan; reproducible at seed 1337)"
	case strings.Contains(lc, "eks") || strings.Contains(lc, "arn:aws"):
		t.Provider = "AWS EKS"
		t.Label = "AWS EKS · " + shortContext(ctx)
		t.Note = "DERIVED from your kubeconfig — read-only least-privilege scan; GPU magnitudes [SP-0-PENDING-P4]"
	case strings.Contains(lc, "coreweave"):
		t.Provider = "CoreWeave"
		t.Label = "CoreWeave · " + shortContext(ctx)
		t.Note = "DERIVED from your kubeconfig; GPU magnitudes [SP-0-PENDING-P4]"
	default:
		t.Provider = "Kubernetes"
		t.Label = ctx
		t.Note = "DERIVED from your kubeconfig — read-only scan"
	}
	return t
}

// shortContext trims a long EKS ARN-style context to its cluster tail for display.
func shortContext(ctx string) string {
	if i := strings.LastIndex(ctx, "/"); i >= 0 && i < len(ctx)-1 {
		return ctx[i+1:]
	}
	return ctx
}
