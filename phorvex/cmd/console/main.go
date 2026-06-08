/*
 * Phorvex Console (P-DASHBOARD) — the data-layer backend binary.
 *
 * A read-only HTTP API over the Phorvex reports/metrics/audit + safe triggers of the
 * existing entrypoints (harness -config). The Next.js frontend renders it. It changes
 * NOTHING in the brain/actuator/harness.
 */

package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/phorvex/phorvex/internal/console"
)

func main() {
	var (
		root  string
		addr  string
		audit string
		web   string
	)
	flag.StringVar(&root, "root", "", "Phorvex root dir (holds phorvex/ + build/test-harness/). Default: walk up from CWD.")
	flag.StringVar(&addr, "addr", ":8090", "HTTP listen address.")
	flag.StringVar(&audit, "audit-json", "", "Optional explicit decision-audit JSONL for the owner view.")
	flag.StringVar(&web, "web", "", "Static SPA dir (default <root>/dashboard-web/out).")
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

	url := "http://localhost" + addr
	_, statErr := os.Stat(filepath.Join(cfg.Web, "index.html"))
	hasWeb := statErr == nil
	log.Printf("Phorvex Console")
	log.Printf("  root      : %s", root)
	log.Printf("  dashboard : %s  ->  open %s", map[bool]string{true: "built (serving the SPA)", false: "NOT BUILT (run: cd dashboard-web && npm run build)"}[hasWeb], url)
	log.Printf("  api       : %s/api/* (read-only data + safe triggers)", url)
	if err := http.ListenAndServe(addr, console.NewServer(cfg).Handler()); err != nil {
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
