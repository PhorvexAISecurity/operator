/*
 * Phorvex Console (P4a) — DERIVE cluster targets from the operator's kubeconfig.
 *
 * The Connect step's targets are DERIVED from the live kubeconfig contexts — never a baked
 * context string (the P4a do-not-hardcode tripwire). When the operator adds their EKS
 * kubeconfig (`aws eks update-kubeconfig …`), that context appears as a runnable, read-only
 * scan target automatically. GPU magnitude validation is owned by PHORVEXSEC-87.
 */

package console

import (
	"sort"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeTargetResolution loads the kubeconfig once and determines which advertised context, if
// any, is the target used by unscoped mutation endpoints. ClientConfig is local resolution only:
// it does not contact the API server. If kubeconfig resolution fails, it mirrors restConfigFor("")
// by recognizing a usable in-cluster fallback without exposing either REST config.
func kubeTargetResolution() (contexts []string, defaultContext string, inClusterDefault bool) {
	cfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err == nil && cfg != nil {
		contexts = make([]string, 0, len(cfg.Contexts))
		for name := range cfg.Contexts {
			contexts = append(contexts, name)
		}
		sort.Strings(contexts)

		cc := clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{})
		if _, err := cc.ClientConfig(); err == nil {
			if _, ok := cfg.Contexts[cfg.CurrentContext]; ok && cfg.CurrentContext != "" {
				defaultContext = cfg.CurrentContext
			}
			return contexts, defaultContext, false
		}
	}
	if _, err := rest.InClusterConfig(); err == nil {
		return contexts, "", true
	}
	return contexts, "", false
}

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

// kubeContextExists reports whether the operator's kubeconfig really defines this context. It
// distinguishes a DELIBERATELY configured context that happens to be called "default" or
// "in-cluster" from the sentinel spellings that mean "this console's own cluster".
func kubeContextExists(name string) bool {
	if name == "" {
		return false
	}
	cfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil || cfg == nil {
		return false
	}
	_, ok := cfg.Contexts[name]
	return ok
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
		t.Note = "DERIVED from your kubeconfig — read-only least-privilege scan; GPU validation tracked by PHORVEXSEC-87"
	case strings.Contains(lc, "coreweave"):
		t.Provider = "CoreWeave"
		t.Label = "CoreWeave · " + shortContext(ctx)
		t.Note = "DERIVED from your kubeconfig; GPU validation tracked by PHORVEXSEC-87"
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
