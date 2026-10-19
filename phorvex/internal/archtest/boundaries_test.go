// Package archtest enforces the service boundaries of ADR-0001
// (docs/architecture/ADR-0001-service-monorepo.md) while every service still
// lives in this one module: each internal package belongs to exactly one domain,
// and a package may import another domain only where the rules below allow it.
// Crossings that exist today are listed as debt, each with the phase that removes
// it; the list may only shrink.
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePrefix = "github.com/phorvex/phorvex/"

const (
	shared     = "shared"
	sensor     = "sensor"
	brain      = "brain"
	dispatcher = "dispatcher"
	actuator   = "actuator"
	attacks    = "attacks"
	console    = "console"
)

// domains assigns every internal package (and the API types) to one domain.
var domains = map[string]string{
	"api/v1alpha1": shared,

	// Shared libraries: domain types, contracts written by one service and read by
	// another, and platform code. They import nothing outside shared.
	"model": shared, "brainapi": shared, "brainpb": shared, "sensorapi": shared, "sensorpb": shared, "wire": shared, "actuatorapi": shared, "registry": shared, "metrics": shared, "buildinfo": shared,
	"audit": shared, "audittransport": shared, "authz": shared, "representation": shared,
	"disclosure": shared, "losshistory": shared, "currentinventory": shared,
	"gpudevice": shared, "servingcontext": shared, "ownership": shared,
	"actuationbrake": shared, "epssmeta": shared, "pendinggate": shared, "scaleprobe": shared,
	"crmrefund": shared, "endpointlease": shared, "litellmclient": shared, "outputpolicy": shared,
	"voiceadmissionpolicy": shared, "voicemcppolicy": shared, "voicememorypolicy": shared,
	"voiceoutputpolicy": shared, "voicerefundpolicy": shared,

	"ingest": sensor, "graph": sensor, "platform": sensor, "physics": sensor,
	"ctxprov": sensor, "calib": sensor, "epssfeed": sensor, "sensorsvc": sensor,

	"decision": brain, "actionset": brain, "recon": brain, "cost": brain,
	"feasibility": brain, "killchain": brain, "mathlab": brain, "brainsvc": brain,

	"runner": dispatcher, "controller": dispatcher, "capability": dispatcher,
	"capacity": dispatcher, "slo": dispatcher, "codeexec": dispatcher,
	"exposure": dispatcher, "scopedoutcome": dispatcher, "brainclient": dispatcher, "sensorclient": dispatcher,

	"actuator": actuator, "podresources": actuator, "startupauthz": actuator,

	"cataloguev1": attacks, "lossobserver": attacks, "currentobserver": attacks,

	"console": console,
}

// allowed lists the domains each domain may import besides its own. The
// dispatcher drives sensor, brain and actuator in-process until phase 4 puts
// gRPC between them.
var allowed = map[string][]string{
	shared:     {},
	sensor:     {shared},
	brain:      {shared},
	dispatcher: {shared, sensor, brain, actuator},
	actuator:   {shared},
	attacks:    {shared},
	console:    {shared},
}

type edge struct{ from, to string }

// debt lists the boundary crossings that exist today and the phase that removes them.
var debt = map[edge]string{
	{"platform", "recon"}:      "the sensor precomputes the brain's EPSS value multiplier; phase 3b ships raw EPSS/CVSS and the brain computes it",
	{"decision", "ctxprov"}:    "the brain computes context in-process; phase 3b ships context features in the sensor snapshot",
	{"decision", "physics"}:    "the brain reads flow physics in-process; phase 3b ships physics features in the sensor snapshot",
	{"console", "actionset"}:   "the console embeds brain code (apply-fix gate); phase 4 calls the brain API",
	{"console", "decision"}:    "the console embeds brain code (apply-fix gate, benchmark simulation); phase 4 calls the brain API",
	{"console", "mathlab"}:     "the console replays Math Lab snapshots in-process; phase 4 calls the brain API",
	{"console", "actuator"}:    "the console introspects the actuator handler registry; phase 4 reads it from the actuator API",
	{"console", "cataloguev1"}: "the console runs catalogue jobs in-process; phase 6 moves them to the attacks service",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found from this package: %v", err)
	}
	return root
}

// imports returns, per package with production code, the module packages its
// non-test files import.
func imports(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	dirs := []string{"api/v1alpha1"}
	entries, err := os.ReadDir(filepath.Join(root, "internal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, "internal/"+e.Name())
		}
	}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(dir, "internal/")
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			if out[name] == nil {
				out[name] = map[string]bool{}
			}
			for _, spec := range parsed.Imports {
				path, _ := strconv.Unquote(spec.Path.Value)
				if !strings.HasPrefix(path, modulePrefix) {
					continue
				}
				dep := strings.TrimPrefix(strings.TrimPrefix(path, modulePrefix), "internal/")
				if dep != name {
					out[name][dep] = true
				}
			}
		}
	}
	return out
}

func permitted(from, to string) bool {
	if from == to {
		return true
	}
	for _, d := range allowed[from] {
		if d == to {
			return true
		}
	}
	return false
}

func TestEveryPackageHasADomain(t *testing.T) {
	graph := imports(t, moduleRoot(t))
	var missing []string
	for pkg := range graph {
		if _, ok := domains[pkg]; !ok {
			missing = append(missing, pkg)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("packages without a domain (assign each in domains): %v", missing)
	}
	for pkg, domain := range domains {
		if _, ok := allowed[domain]; !ok {
			t.Errorf("%s: unknown domain %q", pkg, domain)
		}
		if _, ok := graph[pkg]; !ok {
			t.Errorf("%s: classified but has no production code; remove it from domains", pkg)
		}
	}
}

func TestImportsRespectServiceBoundaries(t *testing.T) {
	graph := imports(t, moduleRoot(t))
	seen := map[edge]bool{}
	var violations []string
	for from, deps := range graph {
		for to := range deps {
			fromDomain, toDomain := domains[from], domains[to]
			if fromDomain == "" || toDomain == "" || permitted(fromDomain, toDomain) {
				continue
			}
			e := edge{from, to}
			if _, ok := debt[e]; ok {
				seen[e] = true
				continue
			}
			violations = append(violations, from+" ("+fromDomain+") -> "+to+" ("+toDomain+")")
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("imports cross a service boundary (ADR-0001); move the shared code to a shared package or go through the owning service:\n  %s",
			strings.Join(violations, "\n  "))
	}
	for e, reason := range debt {
		if !seen[e] {
			t.Errorf("debt %s -> %s no longer exists (%s); remove it from debt", e.from, e.to, reason)
		}
	}
}
