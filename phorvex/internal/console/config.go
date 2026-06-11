/*
 * Phorvex Console (P-DASHBOARD) — config + paths.
 */

package console

import "path/filepath"

// Config locates the Phorvex tree the console reads (read-only) and triggers.
type Config struct {
	Root       string // the Phorvex root (holds phorvex/ + build/test-harness/)
	PhorvexBin string // phorvex.exe (for --scan/--ablation/--native-demo/--audit-json)
	HarnessBin string // harness.exe (for -config <yaml>)
	HarnessDir string // build/test-harness (cwd for harness runs)
	AuditPath  string // optional explicit audit JSONL (owner-view source)
	Addr       string // http listen address
	Web        string // static SPA dir (dashboard-web/out) served at / alongside /api
	// MetricsAllow is the SSRF allowlist for /api/metrics?url= (host or host:port). Loopback
	// is always allowed; metadata/link-local is always blocked; any other host must be listed.
	MetricsAllow []string
}

// DefaultConfig derives the standard in-repo layout from a root.
func DefaultConfig(root string) Config {
	hd := filepath.Join(root, "build", "test-harness")
	return Config{
		Root:       root,
		PhorvexBin: filepath.Join(root, "phorvex", "bin", "phorvex.exe"),
		HarnessBin: filepath.Join(hd, "bin", "harness.exe"),
		HarnessDir: hd,
		Addr:       ":8090",
		Web:        filepath.Join(root, "dashboard-web", "out"),
	}
}
