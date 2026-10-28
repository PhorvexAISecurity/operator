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
	// composition builds the services a process runs itself (cmd's in-process mode);
	// no domain imports it.
	composition = "composition"
)

// domains assigns every internal package (and the API types) to one domain.
var domains = map[string]string{
	"api/v1alpha1": shared,

	// Shared libraries: domain types, contracts written by one service and read by
	// another, and platform code. They import nothing outside shared.
	"model": shared, "brainapi": shared, "brainpb": shared, "sensorapi": shared, "sensorpb": shared, "wire": shared, "actuatorapi": shared, "actuatorpb": shared, "registry": shared, "metrics": shared, "buildinfo": shared,
	"audit": shared, "audittransport": shared, "servicetls": shared, "authz": shared, "representation": shared,
	"disclosure": shared, "losshistory": shared, "currentinventory": shared, "eventtrust": shared,
	"gpudevice": shared, "servingcontext": shared, "ownership": shared,
	"actuationbrake": shared, "epssmeta": shared, "pendinggate": shared, "scaleprobe": shared,
	"crmrefund": shared, "datastore": shared, "agentdeny": shared, "endpointlease": shared, "litellmclient": shared, "outputpolicy": shared,
	"attackcatalog": shared, "identityfixture": shared, "persistence": shared, "servingbudget": shared,
	"voiceadmissionpolicy": shared, "voicemcppolicy": shared, "voicememorypolicy": shared,
	"voiceoutputpolicy": shared, "voicerefundpolicy": shared,
	// feasibility is the pure SLO and disruption predicate the brain applies when it
	// selects and the dispatcher re-applies at the emit boundary.
	"feasibility": shared,

	"ingest": sensor, "graph": sensor, "platform": sensor,
	"epssfeed": sensor, "sensorsvc": sensor,

	"decision": brain, "actionset": brain, "recon": brain, "cost": brain,
	"killchain": brain, "mathlab": brain, "brainsvc": brain,
	// The flow physics and context providers are the brain's: it scores and
	// records with them, and no sensor package reads them.
	"physics": brain, "ctxprov": brain,

	"runner": dispatcher, "controller": dispatcher, "capability": dispatcher,
	"capacity": dispatcher, "slo": dispatcher, "codeexec": dispatcher,
	"exposure": dispatcher, "scopedoutcome": dispatcher, "brainclient": dispatcher, "sensorclient": dispatcher, "actuatorclient": dispatcher,

	// calib learns scales from the fleet the tick observes and the rotation outcomes
	// the dispatcher measures, and hands the brain its shadow views.
	"calib": dispatcher,

	"actuator": actuator, "podresources": actuator, "startupauthz": actuator, "actuatorsvc": actuator,

	"attacks": attacks, "cataloguev1": attacks, "lossobserver": attacks, "currentobserver": attacks,

	"console": console,

	"inprocess": composition,
}

// allowed lists the domains each domain may import besides its own. Since phase 4
// the dispatcher reaches sensor, brain and actuator only through their contracts;
// the crossings that remain are debt.
var allowed = map[string][]string{
	shared:     {},
	sensor:     {shared},
	brain:      {shared},
	dispatcher: {shared},
	actuator:   {shared},
	attacks:    {shared},
	console:    {shared},
	// It composes the brain, sensor and actuator for the dispatcher; it imports none
	// of the dispatcher's packages, so the runner's tests can run it in process.
	composition: {shared, sensor, brain, actuator},
}

type edge struct{ from, to string }

// debt lists the boundary crossings that exist today and the phase that removes them.
var debt = map[edge]string{
	{"console", "actionset"}:   "the console embeds brain code (apply-fix gate); phase 4 calls the brain API",
	{"console", "decision"}:    "the console embeds brain code (apply-fix gate, benchmark simulation); phase 4 calls the brain API",
	{"console", "mathlab"}:     "the console replays Math Lab snapshots in-process; phase 4 calls the brain API",
	{"console", "actuator"}:    "the console introspects the actuator handler registry; phase 4 reads it from the actuator API",
	{"console", "cataloguev1"}: "cmd/attacks serves the catalogue jobs, but their code is still package console's; it moves to an attacks package",
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
