/*
 * Phorvex Console (P-DASHBOARD) — the data-layer backend binary.
 *
 * A read-only HTTP API over the Phorvex reports/metrics/audit + safe triggers of the
 * existing entrypoints (harness -config). The Next.js frontend renders it. It changes
 * NOTHING in the brain/actuator/harness.
 */

package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/phorvex/phorvex/internal/console"
)

func main() {
	var (
		root         string
		addr         string
		audit        string
		web          string
		metricsAllow string
	)
	flag.StringVar(&root, "root", "", "Phorvex root dir (holds phorvex/ + build/test-harness/). Default: walk up from CWD.")
	flag.StringVar(&addr, "addr", ":8090", "HTTP listen address.")
	flag.StringVar(&audit, "audit-json", "", "Optional explicit decision-audit JSONL for the owner view.")
	flag.StringVar(&web, "web", "", "Static SPA dir (default <root>/dashboard-web/out).")
	flag.StringVar(&metricsAllow, "metrics-allow", "", "Comma-separated host[:port] allowlist for /api/metrics?url= SSRF guard (loopback always allowed; metadata/link-local always blocked).")
	flag.Parse()

	if root == "" {
		if wd, err := os.Getwd(); err == nil {
			root = guessRoot(wd)
		}
	}
	cfg := console.DefaultConfig(root)
	cfg.Addr = addr
	if audit != "" {
		cfg.AuditPath = audit
	}
	if web != "" {
		cfg.Web = web
	}
	for _, h := range strings.Split(metricsAllow, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.MetricsAllow = append(cfg.MetricsAllow, h)
		}
	}

	url := "http://localhost" + addr
	_, statErr := os.Stat(filepath.Join(cfg.Web, "index.html"))
	hasWeb := statErr == nil
	log.Printf("Phorvex Console")
	log.Printf("  root      : %s", root)
	log.Printf("  dashboard : %s  ->  open %s", map[bool]string{true: "built (serving the SPA)", false: "NOT BUILT (run: cd dashboard-web && npm run build)"}[hasWeb], url)
	log.Printf("  api       : %s/api/* (read-only data + safe triggers)", url)
	// [P-VCLUSTER Pass 2] enable the safe apply-fix write-path + per-tenant DoS quota. OIDC is wired
	// from config in production (verified identity); here it is nil => demo-trust dev mode (?user=&tenant=
	// for local click-through). The applier is nil => record-only until a deployment injects the
	// per-namespace-SA CRD patch (the UI labels this honestly).
	srv := console.NewServer(cfg)
	// OIDC: if the IdP is configured via env, build the verified-identity verifier (fail-closed on a
	// bad config); else nil => demo-trust dev mode. [PENDING-IDP-CONFIG] — see REAL-ENV-VALIDATION.md.
	var oidc *console.OIDCVerifier
	if iss := os.Getenv("PHORVEX_OIDC_ISSUER"); iss != "" {
		cfgOIDC := console.OIDCConfig{
			Issuer: iss, Audience: os.Getenv("PHORVEX_OIDC_AUDIENCE"), JWKSURL: os.Getenv("PHORVEX_OIDC_JWKS_URL"),
			TenantClaim: os.Getenv("PHORVEX_OIDC_TENANT_CLAIM"), LensClaim: os.Getenv("PHORVEX_OIDC_LENS_CLAIM"),
		}
		if v, err := console.LoadOIDCVerifier(context.Background(), cfgOIDC, nil); err != nil {
			log.Printf("  oidc      : config present but FAILED to load (%v) — staying demo-trust", err)
		} else {
			oidc = v
			log.Printf("  oidc      : verified identity ENABLED (issuer %s)", iss)
		}
	}
	srv.EnableVCluster(oidc, console.NewTenantQuota(console.DefaultQuota()), console.NewApplyFixManager(nil, nil, nil))
	log.Printf("  apply-fix : %s/api/apply-fix/* (allowlist + gate-check + two-key; %s identity; record-only applier [PENDING-CLUSTER-VALIDATION])", url, map[bool]string{true: "OIDC", false: "demo-trust"}[oidc != nil])
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

// guessRoot walks up from wd looking for the dir that contains both phorvex/ and
// build/test-harness/.
func guessRoot(wd string) string {
	d := wd
	for i := 0; i < 6; i++ {
		if dirExists(filepath.Join(d, "phorvex")) && dirExists(filepath.Join(d, "build", "test-harness")) {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return wd
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
