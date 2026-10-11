package console

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// fakePolicies applies RFC 7386 merge patches the way the API server does, including the
// resourceVersion precondition, and bumps the generation on every spec change.
type fakePolicies struct {
	items   map[string]*v1alpha1.PhorvexPolicy
	patches [][]byte
	fail    error
}

func policyFixture(t *testing.T, ns, name, uid string, generation int64, spec string) *v1alpha1.PhorvexPolicy {
	t.Helper()
	var p v1alpha1.PhorvexPolicy
	doc := `{"metadata":{"namespace":"` + ns + `","name":"` + name + `","uid":"` + uid + `","generation":` + strconv.FormatInt(generation, 10) +
		`,"resourceVersion":"100"},"spec":` + spec + `}`
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

const legacySpec = `{"tenant":"vllm","mode":"active","objective":{"lambda":"0.5","costWeights":{"normSparsity":"0.4","flowDisruption":"0.6"}},
"slo":{"costCeiling":"1.2"},"budget":{"maxMovesPerTick":10,"proactiveFloor":"15m","antiOverRotationWindow":"90s"}}`

func newFakePolicies(ps ...*v1alpha1.PhorvexPolicy) *fakePolicies {
	f := &fakePolicies{items: map[string]*v1alpha1.PhorvexPolicy{}}
	for _, p := range ps {
		f.items[p.Namespace+"/"+p.Name] = p
	}
	return f
}

func (f *fakePolicies) List(context.Context) ([]v1alpha1.PhorvexPolicy, error) {
	out := []v1alpha1.PhorvexPolicy{}
	for _, p := range f.items {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fakePolicies) Get(_ context.Context, ns, name string) (*v1alpha1.PhorvexPolicy, error) {
	p, ok := f.items[ns+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "phorvex.ai", Resource: "phorvexpolicies"}, name)
	}
	cp := *p
	return &cp, nil
}

func mergePatch(dst, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		if pm, ok := v.(map[string]any); ok {
			dm, _ := dst[k].(map[string]any)
			if dm == nil {
				dm = map[string]any{}
			}
			mergePatch(dm, pm)
			dst[k] = dm
			continue
		}
		dst[k] = v
	}
}

func (f *fakePolicies) Patch(_ context.Context, ns, name string, patch []byte) (*v1alpha1.PhorvexPolicy, error) {
	f.patches = append(f.patches, patch)
	if f.fail != nil {
		return nil, f.fail
	}
	p := f.items[ns+"/"+name]
	var pm map[string]any
	if err := json.Unmarshal(patch, &pm); err != nil {
		return nil, err
	}
	if meta, ok := pm["metadata"].(map[string]any); ok && meta["resourceVersion"] != p.ResourceVersion {
		return nil, apierrors.NewConflict(schema.GroupResource{Group: "phorvex.ai", Resource: "phorvexpolicies"}, name, nil)
	}
	delete(pm, "metadata")
	raw, _ := json.Marshal(p)
	var cur map[string]any
	_ = json.Unmarshal(raw, &cur)
	mergePatch(cur, pm)
	raw, _ = json.Marshal(cur)
	var next v1alpha1.PhorvexPolicy
	if err := json.Unmarshal(raw, &next); err != nil {
		return nil, err
	}
	next.Generation = p.Generation + 1
	rv, _ := strconv.Atoi(p.ResourceVersion)
	next.ResourceVersion = strconv.Itoa(rv + 1)
	f.items[ns+"/"+name] = &next
	cp := next
	return &cp, nil
}

// traceRecord is a decision record of policy uid at generation, carrying the given knobs.
func traceRecord(at time.Time, uid string, generation int64, mutate func(*model.DecisionTraceV2)) audit.Record {
	t := &model.DecisionTraceV2{PolicyUID: uid, DecisionID: "d-" + strconv.FormatInt(generation, 10), NormWeight: 0.4, FlowWeight: 0.6,
		LambdaConfiguredSeed: 0.5, LambdaSeedConsumed: 0.5, CostCeiling: 1.2, Budget: 10, EconomicsVersion: model.EconomicsLegacyRuntimeLambdaV1}
	t.Inputs.ProactiveFloorSec, t.Inputs.AntiOverRotateSec = 900, 90
	if mutate != nil {
		mutate(t)
	}
	return audit.Record{Time: at, Tenant: "vllm", Namespace: "vllm", Action: "noop", DecisionTrace: t,
		ParameterSet: &model.ParameterSetReference{PolicyOverridesID: "vllm/vllm-defense@" + uid + ":" + strconv.FormatInt(generation, 10)}}
}

func optimizerServer(t *testing.T, client optimizerPolicyClient, records []audit.Record) *Server {
	t.Helper()
	s := NewServer(Config{StateDir: t.TempDir()})
	s.optimizerClient = client
	s.optimizerRecords = func(context.Context) ([]audit.Record, error) { return records, nil }
	return s
}

func operatorRequest(method, target string, body any, tenants ...string) *http.Request {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, target, bytes.NewReader(b))
	return withTestPrincipal(r, testPrincipal([]Role{RoleOperator}, tenants, []string{defaultTargetID}))
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
}

func TestSpecValuesResolveTheThreeEconomicsModesLikeTheOperator(t *testing.T) {
	legacy := policyFixture(t, "vllm", "vllm-defense", "u1", 1, legacySpec)
	v, err := specValues(&legacy.Spec)
	if err != nil || v.EconomicsMode != economicsLegacy || v.Values["lambdaSeed"].Value != 0.5 || v.Values["beta"].Present ||
		v.Values["proactiveFloorSeconds"].Value != 900 || v.Values["maxMovesPerTick"].Value != 10 {
		t.Fatalf("legacy: %+v %v", v, err)
	}
	fixed := policyFixture(t, "vllm", "vllm-defense", "u1", 1, `{"objective":{"disruptionAversion":"1.5"}}`)
	if v, _ := specValues(&fixed.Spec); v.EconomicsMode != economicsFixed || v.Values["beta"].Value != 1.5 || v.Values["normWeight"].Value != 0.4 {
		t.Fatalf("fixed (weights default to 0.4/0.6): %+v", v)
	}
	indep := policyFixture(t, "vllm", "vllm-defense", "u1", 1, `{"objective":{"costPreferences":{"norm":"2","flow":"0.25"}}}`)
	if v, _ := specValues(&indep.Spec); v.EconomicsMode != economicsIndependent || v.Values["normPreference"].Value != 2 || v.Values["flowPreference"].Value != 0.25 {
		t.Fatalf("independent: %+v", v)
	}
}

func TestTargetValuesRefuseOutOfDomainAndOutOfModeKnobs(t *testing.T) {
	cur, _ := specValues(&policyFixture(t, "vllm", "vllm-defense", "u1", 1, legacySpec).Spec)
	bad := []struct {
		mode string
		set  map[string]float64
	}{
		{"", map[string]float64{"normWeight": -0.1}},
		{"", map[string]float64{"costCeiling": 0}},
		{"", map[string]float64{"maxMovesPerTick": 1.5}},
		{"", map[string]float64{"proactiveFloorSeconds": 0}},
		{"", map[string]float64{"spec.tenant": 1}},
		{"", map[string]float64{"beta": 1}},                             // beta only in fixed mode
		{economicsFixed, map[string]float64{}},                          // fixed needs beta
		{economicsIndependent, map[string]float64{"normPreference": 1}}, // needs both
		{"turbo", map[string]float64{}},
	}
	for i, c := range bad {
		if _, err := targetValues(cur, c.mode, c.set); err == nil {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
	if _, err := targetValues(cur, economicsFixed, map[string]float64{"beta": 2, "normWeight": 0.3}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePatchWritesTheEconomicsModeAsAWhole(t *testing.T) {
	cur, _ := specValues(&policyFixture(t, "vllm", "vllm-defense", "u1", 1, legacySpec).Spec)
	next, err := targetValues(cur, economicsFixed, map[string]float64{"beta": 1.25, "normWeight": 0.3, "proactiveFloorSeconds": 600})
	if err != nil {
		t.Fatal(err)
	}
	patch, changes := buildRuntimePatch(cur, next, "100")
	var got map[string]any
	_ = json.Unmarshal(patch, &got)
	obj := got["spec"].(map[string]any)["objective"].(map[string]any)
	if obj["disruptionAversion"] != "1.25" || obj["costPreferences"] != nil || obj["costWeights"].(map[string]any)["normSparsity"] != "0.3" {
		t.Fatalf("objective patch: %s", patch)
	}
	if _, present := obj["costPreferences"]; !present {
		t.Fatal("the unused mode's field must be cleared with an explicit null")
	}
	if got["spec"].(map[string]any)["budget"].(map[string]any)["proactiveFloor"] != "600s" || got["metadata"].(map[string]any)["resourceVersion"] != "100" {
		t.Fatalf("budget/precondition: %s", patch)
	}
	keys := []string{}
	for _, c := range changes {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "normWeight,beta,proactiveFloorSeconds" {
		t.Fatalf("changes: %v", keys)
	}
	if p, _ := buildRuntimePatch(cur, cur, "100"); p != nil {
		t.Fatal("an unchanged assignment must not produce a patch")
	}
	back, _ := targetValues(next, economicsLegacy, nil)
	patch, _ = buildRuntimePatch(next, back, "")
	if !strings.Contains(string(patch), `"disruptionAversion":null`) {
		t.Fatalf("returning to legacy must remove beta: %s", patch)
	}
}

func TestProtectedLooseningIsDetectedInItsUnsafeDirectionOnly(t *testing.T) {
	ch := []parameterChange{
		{Key: "costCeiling", Before: optionalValue{true, 1.2}, After: optionalValue{true, 1.5}},
		{Key: "maxMovesPerTick", Before: optionalValue{true, 10}, After: optionalValue{true, 5}},
		{Key: "antiOverRotationSeconds", Before: optionalValue{true, 90}, After: optionalValue{true, 30}},
		{Key: "normWeight", Before: optionalValue{true, 0.4}, After: optionalValue{true, 0.9}},
	}
	if got := strings.Join(loosensProtected(ch), ","); got != "costCeiling,antiOverRotationSeconds" {
		t.Fatalf("loosened: %s", got)
	}
}

func TestVerdictsNeedADecisionAtTheCurrentGeneration(t *testing.T) {
	cur, _ := specValues(&policyFixture(t, "vllm", "vllm-defense", "u1", 8, legacySpec).Spec)
	status := func(ps []paramStatus, key string) string {
		for _, p := range ps {
			if p.Key == key {
				return p.Status
			}
		}
		return ""
	}
	if got := status(verdicts(cur, 8, nil), "normWeight"); got != paramNoRecentDecision {
		t.Fatal(got)
	}
	old := newestObservations([]audit.Record{traceRecord(time.Unix(100, 0), "u1", 7, nil)})["u1"]
	if got := status(verdicts(cur, 8, &old), "normWeight"); got != paramPending {
		t.Fatalf("an older generation can only be pending: %s", got)
	}
	recs := []audit.Record{
		traceRecord(time.Unix(100, 0), "u1", 7, nil),
		traceRecord(time.Unix(200, 0), "u1", 8, func(t *model.DecisionTraceV2) { t.FlowWeight = 0.7 }),
		traceRecord(time.Unix(150, 0), "u1", 8, nil),
	}
	obs := newestObservations(recs)["u1"]
	if obs.Generation != 8 || obs.DecisionID != "d-8" || obs.Values["flowWeight"].Value != 0.7 {
		t.Fatalf("newest record per policy: %+v", obs)
	}
	vs := verdicts(cur, 8, &obs)
	if status(vs, "normWeight") != paramVerified || status(vs, "flowWeight") != paramMismatch || status(vs, "beta") != paramNotApplicable ||
		status(vs, "proactiveFloorSeconds") != paramVerified {
		t.Fatalf("verdicts: %+v", vs)
	}
}

func TestApplyIsAuditedVerifiableAndRestorable(t *testing.T) {
	client := newFakePolicies(policyFixture(t, "vllm", "vllm-defense", "u1", 8, legacySpec))
	s := optimizerServer(t, client, nil)

	w := httptest.NewRecorder()
	s.optimizerApply(w, operatorRequest(http.MethodPost, optimizerApplyRoute, map[string]any{
		"namespace": "vllm", "name": "vllm-defense", "expectedGeneration": 8, "economicsMode": "fixed",
		"set": map[string]float64{"beta": 1.5, "flowWeight": 0.7}, "note": "beta sweep arm 1"}, "vllm"))
	if w.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	var applied struct {
		ChangeID   string            `json:"changeId"`
		Generation int64             `json:"generation"`
		Changes    []parameterChange `json:"changes"`
	}
	decodeBody(t, w, &applied)
	if applied.Generation != 9 || applied.ChangeID == "" || len(applied.Changes) != 2 {
		t.Fatalf("apply result: %+v", applied)
	}
	live := client.items["vllm/vllm-defense"]
	if live.Spec.Objective.DisruptionAversion != "1.5" || live.Spec.Objective.CostWeights.FlowDisruption != "0.7" {
		t.Fatalf("live spec: %+v", live.Spec.Objective)
	}

	// The brain's next decision at generation 9 carries the new values: every knob verifies.
	s.optimizerRecords = func(context.Context) ([]audit.Record, error) {
		return []audit.Record{traceRecord(time.Now(), "u1", 9, func(t *model.DecisionTraceV2) {
			t.FlowWeight, t.EconomicsVersion, t.EffectiveCostCoefficient = 0.7, model.EconomicsFixedDisruptionAversionV1, 1.5
			t.DisruptionAversion = &model.OptionalFloat{Present: true, Value: 1.5}
		})}, nil
	}
	w = httptest.NewRecorder()
	s.optimizerRuntime(w, operatorRequest(http.MethodGet, "/api/optimizer/runtime", nil, "vllm"))
	var rt struct {
		Policies []runtimePolicyView `json:"policies"`
	}
	decodeBody(t, w, &rt)
	if len(rt.Policies) != 1 || rt.Policies[0].Generation != 9 || rt.Policies[0].ModeMatches == nil || !*rt.Policies[0].ModeMatches {
		t.Fatalf("runtime view: %s", w.Body.String())
	}
	for _, p := range rt.Policies[0].Parameters {
		if p.Status != paramVerified && p.Status != paramNotApplicable {
			t.Fatalf("%s: %s (%s)", p.Key, p.Status, p.Note)
		}
	}

	// The log carries the change; a restore re-applies the replaced values and is itself logged.
	w = httptest.NewRecorder()
	s.optimizerApply(w, operatorRequest(http.MethodPost, optimizerApplyRoute, map[string]any{
		"namespace": "vllm", "name": "vllm-defense", "restoreChangeId": applied.ChangeID}, "vllm"))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	live = client.items["vllm/vllm-defense"]
	if live.Spec.Objective.DisruptionAversion != "" || live.Spec.Objective.CostWeights.FlowDisruption != "0.6" || live.Generation != 10 {
		t.Fatalf("restored spec: %+v gen %d", live.Spec.Objective, live.Generation)
	}
	w = httptest.NewRecorder()
	s.optimizerParameterLog(w, operatorRequest(http.MethodGet, "/api/optimizer/parameter-log", nil, "vllm"))
	var log struct {
		Entries []consoleMutation `json:"entries"`
	}
	decodeBody(t, w, &log)
	if len(log.Entries) != 2 || log.Entries[0].RestoreOf != applied.ChangeID || log.Entries[1].ChangeID != applied.ChangeID ||
		log.Entries[1].Verdict != "applied" || log.Entries[1].Generation != 9 || log.Entries[1].PreviousGeneration != 8 || log.Entries[1].Note != "beta sweep arm 1" {
		t.Fatalf("log: %+v", log.Entries)
	}
	w = httptest.NewRecorder()
	s.optimizerParameterLog(w, operatorRequest(http.MethodGet, "/api/optimizer/parameter-log", nil, "voice"))
	decodeBody(t, w, &log)
	if len(log.Entries) != 0 {
		t.Fatal("another tenant's grant must not see vllm's changes")
	}
}

func TestApplyRefusesStaleProtectedAndFixtureWrites(t *testing.T) {
	client := newFakePolicies(policyFixture(t, "vllm", "vllm-defense", "u1", 8, legacySpec),
		policyFixture(t, "phorvex-verify-x", "p", "u2", 1, legacySpec))
	s := optimizerServer(t, client, nil)
	post := func(body map[string]any, tenant string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.optimizerApply(w, operatorRequest(http.MethodPost, optimizerApplyRoute, body, tenant))
		return w
	}
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "expectedGeneration": 7, "set": map[string]float64{"normWeight": 0.3}}, "vllm"); w.Code != http.StatusConflict {
		t.Fatalf("stale generation: %d", w.Code)
	}
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "set": map[string]float64{"costCeiling": 2}}, "vllm"); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("protected loosening without confirmation: %d", w.Code)
	}
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "set": map[string]float64{"costCeiling": 2}, "confirmProtected": true}, "vllm"); w.Code != http.StatusOK {
		t.Fatalf("confirmed loosening: %d %s", w.Code, w.Body.String())
	}
	if w := post(map[string]any{"namespace": "phorvex-verify-x", "name": "p", "set": map[string]float64{"normWeight": 0.3}}, "phorvex-verify-x"); w.Code != http.StatusForbidden {
		t.Fatalf("fixture write: %d", w.Code)
	}
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "set": map[string]float64{"normWeight": 0.3}, "mode": "dryRun"}, "vllm"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown fields (mode, actuators) are not this route's business: %d", w.Code)
	}
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "set": map[string]float64{"normWeight": 0.3}}, "vllm"); w.Code != http.StatusOK {
		t.Fatalf("plain change: %d %s", w.Code, w.Body.String())
	}
	client.fail = apierrors.NewInvalid(schema.GroupKind{Group: "phorvex.ai", Kind: "PhorvexPolicy"}, "vllm-defense", nil)
	if w := post(map[string]any{"namespace": "vllm", "name": "vllm-defense", "set": map[string]float64{"normWeight": 0.2}}, "vllm"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("apiserver rejection: %d", w.Code)
	}
}
