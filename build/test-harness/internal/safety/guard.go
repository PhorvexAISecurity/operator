// Package safety is the mandatory containment layer. It REFUSES any mutating call
// unless (a) the live current-context equals the configured context, (b) the live
// apiserver host equals the host of that named context in the kubeconfig, (c) the
// owned/authorized acknowledgement is set, and (d) the target namespace equals the
// configured sandbox namespace. Anything else is a hard refusal — the harness
// NEVER mutates an unintended cluster or namespace.
package safety

import (
	"fmt"
	"net/url"
	"strings"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// RefuseError is returned by every guard assertion that fails. It is a distinct
// type so callers can detect a refusal vs an ordinary error.
type RefuseError struct {
	Reason string
}

func (e *RefuseError) Error() string { return "REFUSED: " + e.Reason }

// IsRefusal reports whether err is a containment refusal.
func IsRefusal(err error) bool {
	_, ok := err.(*RefuseError)
	return ok
}

// Guard implements core.SafetyGuard. It is constructed AFTER the client is built
// from the named context, capturing the resolved live host so every later
// mutation re-checks it cheaply.
type Guard struct {
	cfg          config.TargetConfig
	liveContext  string // the context actually used to build the client
	liveHost     string // the apiserver host the live client is talking to
	expectedHost string // the host of cfg.Context as declared in the kubeconfig
}

// NewGuard builds a guard and performs the one-time static assertions:
//   - ownedAck is set,
//   - the live context (the one the client was built from) == cfg.Context,
//   - the live apiserver host == the host declared for cfg.Context in the
//     kubeconfig (so a tampered/redirected connection is caught).
//
// It returns a *RefuseError on any mismatch. liveContext and liveHost are what
// the caller actually resolved when building the rest.Config.
func NewGuard(cfg config.TargetConfig, liveContext, liveHost string) (*Guard, error) {
	if !cfg.OwnedAck {
		return nil, &RefuseError{Reason: "ownedAck is not set — refusing to perform any mutating call on an unacknowledged cluster"}
	}
	if strings.TrimSpace(cfg.Context) == "" {
		return nil, &RefuseError{Reason: "config.Context is empty — refusing (no authorized target to assert against)"}
	}
	if liveContext != cfg.Context {
		return nil, &RefuseError{Reason: fmt.Sprintf("live kube-context %q != configured context %q — refusing to target an unauthorized context", liveContext, cfg.Context)}
	}

	expectedHost, err := hostForContext(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return nil, &RefuseError{Reason: fmt.Sprintf("cannot resolve apiserver host for context %q: %v", cfg.Context, err)}
	}
	if !hostsEqual(expectedHost, liveHost) {
		return nil, &RefuseError{Reason: fmt.Sprintf("live apiserver host %q != host %q declared for context %q in kubeconfig — refusing (connection does not match the named target)", liveHost, expectedHost, cfg.Context)}
	}

	return &Guard{
		cfg:          cfg,
		liveContext:  liveContext,
		liveHost:     liveHost,
		expectedHost: expectedHost,
	}, nil
}

// AssertMutationAllowed is called before EVERY create/delete. It re-checks the
// namespace target AND re-verifies the static invariants did not drift.
func (g *Guard) AssertMutationAllowed(targetNS string) error {
	if g == nil {
		return &RefuseError{Reason: "nil safety guard — refusing all mutation"}
	}
	if !g.cfg.OwnedAck {
		return &RefuseError{Reason: "ownedAck cleared — refusing"}
	}
	if g.liveContext != g.cfg.Context {
		return &RefuseError{Reason: fmt.Sprintf("live context %q drifted from configured %q — refusing", g.liveContext, g.cfg.Context)}
	}
	if !hostsEqual(g.expectedHost, g.liveHost) {
		return &RefuseError{Reason: "apiserver host drifted from the named context host — refusing"}
	}
	if targetNS != g.cfg.Namespace {
		return &RefuseError{Reason: fmt.Sprintf("object target namespace %q != sandbox namespace %q — refusing to act outside the sandbox", targetNS, g.cfg.Namespace)}
	}
	return nil
}

// LiveHost exposes the resolved live apiserver host (provenance).
func (g *Guard) LiveHost() string { return g.liveHost }

// hostForContext loads the kubeconfig and returns the apiserver host (server URL)
// declared for the named context's cluster. An empty kubeconfig path uses the
// standard loading rules (KUBECONFIG / ~/.kube/config).
func hostForContext(kubeconfigPath, contextName string) (string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	cfg, err := rules.Load()
	if err != nil {
		return "", err
	}
	ctx, ok := cfg.Contexts[contextName]
	if !ok {
		return "", fmt.Errorf("context %q not found in kubeconfig", contextName)
	}
	cluster, ok := cfg.Clusters[ctx.Cluster]
	if !ok {
		return "", fmt.Errorf("cluster %q for context %q not found in kubeconfig", ctx.Cluster, contextName)
	}
	if cluster.Server == "" {
		return "", fmt.Errorf("cluster %q has no server set", ctx.Cluster)
	}
	return cluster.Server, nil
}

// hostsEqual compares two apiserver URLs by scheme+host+port, tolerating a
// trailing slash and case differences in the host. This is strict enough to
// catch a redirected/proxied connection but does not false-refuse on cosmetic
// URL differences.
func hostsEqual(a, b string) bool {
	na, err1 := normalizeHost(a)
	nb, err2 := normalizeHost(b)
	if err1 != nil || err2 != nil {
		// Fall back to a trimmed string compare if either fails to parse.
		return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
	}
	return na == nb
}

func normalizeHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", err
	}
	host := strings.ToLower(u.Host)
	return strings.ToLower(u.Scheme) + "://" + host, nil
}
