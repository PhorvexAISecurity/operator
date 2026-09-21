/*
 * Phorvex — freshness and invariant tests for the producer-driven recon cover map (M-123).
 *
 * TestCoverMapDocumentIsCurrent is the CI hook: `go test ./...` in this module fails when
 * docs/recon-cover-map.generated.md no longer matches a fresh run of the registered
 * profiles. Regenerate with either of:
 *
 *	go run ./tools/covermap --write
 *	go test ./tools/covermap -run TestCoverMapDocumentIsCurrent -update
 */

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

var updateCoverMap = flag.Bool("update", false, "rewrite docs/recon-cover-map.generated.md from the producers")

func fresh(t *testing.T) (Report, []byte, string) {
	t.Helper()
	root, err := ModuleRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	return rep, out, filepath.Join(root, filepath.FromSlash(DefaultOutput))
}

func TestCoverMapDocumentIsCurrent(t *testing.T) {
	_, want, path := fresh(t)
	if *updateCoverMap {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s", path)
		return
	}
	ok, msg, err := Check(path, want)
	if err != nil {
		t.Fatalf("the generated cover map is missing (%v); regenerate with: go run ./tools/covermap --write", err)
	}
	if !ok {
		t.Fatalf("%s has drifted from the producers: %s\nRegenerate: go run ./tools/covermap --write", DefaultOutput, msg)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	_, a, _ := fresh(t)
	_, b, _ := fresh(t)
	if !bytes.Equal(a, b) {
		t.Fatal("two consecutive renders differ: the report is not deterministic")
	}
}

// A hand-edited row must be rejected by --check even though the source pin still matches.
func TestCheckRejectsEditedRowAndDetectsPinOnlyDrift(t *testing.T) {
	_, want, _ := fresh(t)
	dir := t.TempDir()

	edited := filepath.Join(dir, "edited.md")
	row := "| pod | `podIdentity` | 1 | `rotate` |\n"
	if !bytes.Contains(want, []byte(row)) {
		t.Fatalf("expected row %q in the fresh report", row)
	}
	tampered := bytes.Replace(want, []byte(row), []byte("| pod | `podIdentity` | 1 | `rotate`, `identity-rotate` |\n"), 1)
	if err := os.WriteFile(edited, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	ok, msg, err := Check(edited, want)
	if err != nil {
		t.Fatal(err)
	}
	if ok || !strings.Contains(msg, "SAME source pin") {
		t.Fatalf("an edited cover row was not rejected as a table edit: ok=%t msg=%q", ok, msg)
	}

	repinned := filepath.Join(dir, "repinned.md")
	pin := pinPrefix + pinLine(want)
	if err := os.WriteFile(repinned, bytes.Replace(want, []byte(pin), []byte(pinPrefix+"0000"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, msg, err = Check(repinned, want)
	if err != nil {
		t.Fatal(err)
	}
	if ok || !strings.Contains(msg, "only the source-input pin differs") {
		t.Fatalf("a pin-only change was not classified as such: ok=%t msg=%q", ok, msg)
	}

	same := filepath.Join(dir, "same.md")
	if err := os.WriteFile(same, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := Check(same, want); err != nil || !ok {
		t.Fatalf("identical file must pass: ok=%t err=%v", ok, err)
	}
}

func TestRunExitCodes(t *testing.T) {
	_, want, _ := fresh(t)
	dir := t.TempDir()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	good := filepath.Join(dir, "good.md")
	if err := os.WriteFile(good, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--check", "--out", good}, devnull, devnull); code != 0 {
		t.Fatalf("--check on a fresh copy exited %d, want 0", code)
	}
	bad := filepath.Join(dir, "bad.md")
	if err := os.WriteFile(bad, append(want, []byte("\nstale line\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--check", "--out", bad}, devnull, devnull); code != 1 {
		t.Fatalf("--check on a drifted copy exited %d, want 1", code)
	}
	if code := run([]string{"--check", "--write"}, devnull, devnull); code != 2 {
		t.Fatalf("--check together with --write exited %d, want 2 (usage)", code)
	}
	written := filepath.Join(dir, "written.md")
	if code := run([]string{"--write", "--out", written}, devnull, devnull); code != 0 {
		t.Fatalf("--write exited %d, want 0", code)
	}
	got, err := os.ReadFile(written)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("--write did not produce the fresh report (err=%v, equal=%t)", err, bytes.Equal(got, want))
	}
	// --check never rewrites the file it inspects.
	before, _ := os.ReadFile(bad)
	run([]string{"--check", "--out", bad}, devnull, devnull)
	after, _ := os.ReadFile(bad)
	if !bytes.Equal(before, after) {
		t.Fatal("--check modified the inspected file")
	}
}

// Every Action constant declared in internal/model/types.go must be either generatable
// (MutatingActions) or in declaredOnlyActions, so a new constant shows up in the report.
func TestDeclaredActionsAreAllListed(t *testing.T) {
	rep, _, _ := fresh(t)
	listed := map[string]bool{}
	for _, a := range rep.Declared.Mutating {
		listed[a] = true
	}
	for _, a := range rep.Declared.DeclaredOnly {
		if listed[a] {
			t.Errorf("%q is both generatable and declared-only", a)
		}
		listed[a] = true
	}
	if len(rep.Declared.Actions) == 0 {
		t.Fatal("no Action constants were read from internal/model/types.go")
	}
	for _, a := range rep.Declared.Actions {
		if !listed[a] {
			t.Errorf("Action constant %q is neither in model.MutatingActions nor in declaredOnlyActions: add it to one so the report lists it", a)
		}
	}
	for a := range listed {
		found := false
		for _, d := range rep.Declared.Actions {
			found = found || d == a
		}
		if !found {
			t.Errorf("%q is listed but is not an Action constant in internal/model/types.go", a)
		}
	}
	// Every result carries a cover entry for every declared action (empty means coverless).
	for _, r := range rep.Results {
		for a := range listed {
			if _, ok := r.Cover[a]; !ok {
				t.Errorf("%s/%s: no cover entry for %q", r.Profile, r.Fixture, a)
			}
		}
		for a := range r.Cover {
			if strings.HasPrefix(a, "UNDECLARED:") {
				t.Errorf("%s/%s: producer granted cover to an action outside the declared vocabulary: %s", r.Profile, r.Fixture, a)
			}
		}
	}
}

// Every Fact* kind declared in internal/recon/facts.go must be emitted by some fixture, so a
// new kind cannot be added without the fixtures (and therefore the report) reaching it.
func TestEveryDeclaredFactKindIsEmittedAndEveryFixtureMintsFacts(t *testing.T) {
	rep, _, _ := fresh(t)
	if len(rep.Declared.FactKinds) == 0 {
		t.Fatal("no Fact* constants were read from internal/recon/facts.go")
	}
	if len(rep.Declared.NeverEmitted) != 0 {
		t.Fatalf("declared fact kinds that no fixture emits: %v — extend Fixtures()", rep.Declared.NeverEmitted)
	}
	declared := map[string]bool{}
	for _, k := range rep.Declared.FactKinds {
		declared[k] = true
	}
	for _, r := range rep.Results {
		if r.AbsentReason != "" {
			t.Errorf("%s/%s: facts absent: %s", r.Profile, r.Fixture, r.AbsentReason)
		}
		if len(r.Facts) == 0 {
			t.Errorf("%s/%s: no facts emitted", r.Profile, r.Fixture)
		}
		for _, f := range r.Facts {
			if !declared[f.Kind] {
				t.Errorf("%s/%s emitted undeclared fact kind %q", r.Profile, r.Fixture, f.Kind)
			}
		}
		for a, cover := range r.Cover {
			for _, l := range cover {
				if strings.HasPrefix(l, "UNEMITTED:") {
					t.Errorf("%s/%s: %s covers a key that no emitted fact carries: %s", r.Profile, r.Fixture, a, l)
				}
			}
		}
	}
}

// The current-source facts the guide states (build/test-harness/ACTUATOR_COVERAGE.md §4)
// are asserted here against the report so the prose cannot drift without a test failing.
func TestCurrentCoverFactsHoldInEveryFixture(t *testing.T) {
	rep, _, _ := fresh(t)
	byKey := map[string]Result{}
	for _, r := range rep.Results {
		byKey[r.Profile+":"+r.Fixture] = r
	}
	coverOf := func(r Result, a model.Action) []string { return r.Cover[string(a)] }
	coveredBy := func(r Result, kind string) []string {
		for _, f := range r.Facts {
			if f.Kind == kind {
				return f.CoveredBy
			}
		}
		return nil
	}
	emits := func(r Result, kind string) bool {
		for _, f := range r.Facts {
			if f.Kind == kind {
				return true
			}
		}
		return false
	}
	for _, r := range rep.Results {
		id := r.Profile + "/" + r.Fixture
		if got := coverOf(r, model.ActionIdentityRotate); len(got) != 0 {
			t.Errorf("%s: identity-rotate must be coverless, got %v", id, got)
		}
		if got := coverOf(r, model.ActionRouteRotate); len(got) != 0 {
			t.Errorf("%s: route-rotate must be coverless because selector changes retain locators, got %v", id, got)
		}
		if got := coverOf(r, model.ActionQuarantine); !slices.Contains(got, recon.FactNetworkIdentity) {
			t.Errorf("%s: qualified quarantine must retain networkIdentity cover, got %v", id, got)
		}
		if got := coverOf(r, model.ActionWarmSwap); len(got) > 0 && strings.Join(got, ",") != "inMemory,podIdentity,session" {
			t.Errorf("%s: warm-swap may cover only the old-process facts, got %v", id, got)
		}
		if got := coverOf(r, model.ActionEndpointRotate); len(got) != 0 {
			t.Errorf("%s: endpoint-rotate must be coverless, got %v", id, got)
		}
		if got := coverOf(r, model.ActionModelShardReplace); len(got) != 0 {
			t.Errorf("%s: model-shard-replace must be coverless, got %v", id, got)
		}
		for _, a := range []model.Action{model.ActionDebugger, model.ActionCustomInject, model.ActionNoop, model.ActionDisable} {
			if got := coverOf(r, a); len(got) != 0 {
				t.Errorf("%s: %s must be coverless, got %v", id, a, got)
			}
		}
		for _, kind := range []string{recon.FactEndpointPath, recon.FactModelFingerprint, recon.FactGPUColocation,
			recon.FactNodeFoothold, recon.FactModelIdentity, recon.FactGuardrailVariant, recon.FactCredential,
			recon.FactRetrievalState, recon.FactArtifactProvenance, recon.FactControlPlanePersistence} {
			if got := coveredBy(r, kind); len(got) != 0 {
				t.Errorf("%s: %s must be audit-only, got covered by %v", id, kind, got)
			}
		}
		if got := coverOf(r, model.ActionKVMigrateInvalidate); len(got) > 0 && strings.Join(got, ",") != recon.FactSession {
			t.Errorf("%s: kv-migrate-invalidate may cover only session, got %v", id, got)
		}
		if got := coverOf(r, model.ActionMIGRebind); len(got) > 0 && strings.Join(got, ",") != recon.FactGPUContentionChannel {
			t.Errorf("%s: mig-rebind may cover only gpuContentionChannel, got %v", id, got)
		}
		if got := coverOf(r, model.ActionAdapterRotate); len(got) > 0 && strings.Join(got, ",") != recon.FactAdapterIntegrity {
			t.Errorf("%s: adapter-rotate may cover only adapterIntegrity, got %v", id, got)
		}
	}

	// Conditions: which fixtures reach which grant.
	want := map[string][]string{ // "profile:action" -> fixtures where the grant appears
		"ucw-recon:mig-rebind":     {"gpu-mig"},
		"ucw-recon:adapter-rotate": {"gpu-adapter"},
	}
	for key, fixtures := range want {
		profile, action, _ := strings.Cut(key, ":")
		var got []string
		for _, f := range rep.Fixtures {
			if len(byKey[profile+":"+f.Name].Cover[action]) > 0 {
				got = append(got, f.Name)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(fixtures, ",") {
			t.Errorf("%s granted in %v, want %v", key, got, fixtures)
		}
	}
	// mig-rebind exists only for ucw; standard-recon never grants it.
	for _, f := range rep.Fixtures {
		if got := byKey["standard-recon:"+f.Name].Cover[string(model.ActionMIGRebind)]; len(got) != 0 {
			t.Errorf("standard-recon/%s: mig-rebind cover %v", f.Name, got)
		}
	}

	// M-42 common prerequisite: both session erasers key on ServingEndpointReady.
	cpu := byKey["ucw-recon:cpu-served-model"]
	if !emits(cpu, recon.FactInflightRequests) || len(cpu.Cover[string(model.ActionKVMigrateInvalidate)]) == 0 {
		t.Errorf("cpu-served-model: expected AI facts and a kv-migrate-invalidate session grant (Pod.ModelID set)")
	}
	if got := cpu.Cover[string(model.ActionKVReset)]; strings.Join(got, ",") != recon.FactSession {
		t.Errorf("cpu-served-model: kv-reset must share session cover, got %v", got)
	}
	for _, f := range cpu.Facts {
		if f.Kind == recon.FactSession && f.Weight != 0.6 {
			t.Errorf("cpu-served-model: session weight %g, want 0.6 (non-GPU, non-stateful arm)", f.Weight)
		}
	}
	stateful := byKey["standard-recon:stateful"]
	if got := stateful.Cover[string(model.ActionKVReset)]; len(got) != 0 {
		t.Errorf("stateful: no endpoint witness must mean no kv-reset cover, got %v", got)
	}
	if got := stateful.Cover[string(model.ActionKVMigrateInvalidate)]; len(got) != 0 {
		t.Errorf("stateful: no endpoint witness must mean no migrate cover, got %v", got)
	}

	// PHold=0 zeroes every weight but changes no cover set.
	zero, one := byKey["ucw-recon:gpu-phold-zero"], byKey["ucw-recon:gpu"]
	for _, f := range zero.Facts {
		if f.Weight != 0 {
			t.Errorf("gpu-phold-zero: %s weight %g, want 0", f.Kind, f.Weight)
		}
	}
	for a, c := range one.Cover {
		if strings.Join(c, ",") != strings.Join(zero.Cover[a], ",") {
			t.Errorf("gpu-phold-zero: cover of %s differs from gpu: %v vs %v", a, zero.Cover[a], c)
		}
	}
}

// The attack-vector steer: exactly one fact kind per vector, exactly x3, only on a
// pod-targeting event, only inside the AI branch, no cover change, and no Age check.
func TestVectorSteeringIsMeasuredExactly(t *testing.T) {
	rep, _, _ := fresh(t)
	rows := map[string]steeringRow{}
	for _, row := range steeringRows(rep) {
		rows[row.Profile+":"+row.Fixture] = row
	}
	want := map[string]string{
		"ucw-recon:gpu-vector-kv":          recon.FactSession + " x3",
		"ucw-recon:gpu-vector-guardrail":   recon.FactGuardrailBypass + " x3",
		"ucw-recon:gpu-vector-inflight":    recon.FactInflightRequests + " x3",
		"ucw-recon:gpu-vector-kv-aged":     recon.FactSession + " x3",
		"ucw-recon:gpu-vector-adapter":     "",
		"ucw-recon:gpu-vector-kv-neighbor": "",
		"ucw-recon:plain-vector-kv":        "",
	}
	for key, changes := range want {
		row, ok := rows[key]
		if !ok {
			t.Fatalf("no steering row for %s", key)
		}
		if got := strings.Join(row.Changes, ","); got != changes {
			t.Errorf("%s: weight changes %q, want %q", key, got, changes)
		}
		if row.CoverChanged {
			t.Errorf("%s: a vector event changed a cover set", key)
		}
	}
	for _, f := range rep.Fixtures {
		if len(f.Events) == 0 {
			continue
		}
		row := rows["standard-recon:"+f.Name]
		if len(row.Changes) != 0 || row.CoverChanged {
			t.Errorf("standard-recon/%s: events must not change anything, got %v", f.Name, row.Changes)
		}
	}
	if *updateCoverMap {
		return
	}
	if vectorDominanceFromReport(rep) != 3 {
		t.Errorf("measured vector dominance %g, want 3", vectorDominanceFromReport(rep))
	}
}

func vectorDominanceFromReport(rep Report) float64 {
	var base, boosted float64
	for _, r := range rep.Results {
		if r.Profile != "ucw-recon" {
			continue
		}
		for _, f := range r.Facts {
			if f.Kind != recon.FactSession {
				continue
			}
			switch r.Fixture {
			case "gpu":
				base = f.Weight
			case "gpu-vector-kv":
				boosted = f.Weight
			}
		}
	}
	if base == 0 {
		return 0
	}
	return boosted / base
}
