package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const routingSyntheticMasterKey = "sk-local-routing-boundary-do-not-retain"

// Run the exact producer script against a real local listener. The master key
// exists only in the child environment and never in argv or serialized output.
func runRoutingFixtureProbe(ctx context.Context, fixture *routingHTTPFixture, alias, key string) (liteRoutingResponse, []byte, error) {
	return runRoutingFixtureProbeScript(ctx, fixture, alias, key, liteRoutingProbeScript)
}

func runRoutingFixtureProbeScript(ctx context.Context, fixture *routingHTTPFixture, alias, key, script string) (liteRoutingResponse, []byte, error) {
	var response liteRoutingResponse
	cmd := exec.CommandContext(ctx, "python3", "-c", script, alias, fixture.port)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "LITELLM_MASTER_KEY=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "LITELLM_MASTER_KEY="+key)
	raw, err := cmd.Output()
	if err != nil {
		return response, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, raw, err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return response, raw, errors.New("probe printed more than one JSON value")
	}
	return response, raw, nil
}

type routingFixtureTransport struct {
	liteKubeTransport
	configSHA string
	key       string
	byPod     map[string]*routingHTTPFixture
	afterPost func(litePod)
}

func (t *routingFixtureTransport) snapshot(ctx context.Context, c LiteLLMRuntime) (liteAuthority, error) {
	c.ExpectedConfigSHA256 = t.configSHA
	return t.liteKubeTransport.snapshot(ctx, c)
}
func (*routingFixtureTransport) sourcePin(context.Context, LiteLLMRuntime, litePod) error { return nil }
func (t *routingFixtureTransport) inferenceConfig(ctx context.Context, c LiteLLMRuntime, a liteAuthority) error {
	c.ExpectedConfigSHA256 = t.configSHA
	return t.liteKubeTransport.inferenceConfig(ctx, c, a)
}
func (t *routingFixtureTransport) post(ctx context.Context, _ LiteLLMRuntime, p litePod, alias string) (liteRoutingResponse, error) {
	fixture := t.byPod[p.UID]
	if fixture == nil {
		return liteRoutingResponse{}, errors.New("unrecognized exact Pod")
	}
	response, _, err := runRoutingFixtureProbe(ctx, fixture, alias, t.key)
	if t.afterPost != nil {
		t.afterPost(p)
	}
	return response, err
}

func routingRunFixture(t *testing.T, respondA, respondB func(string) routingFixtureReply) (Runtime, *routingFixtureTransport, *liteRecorder, *routingHTTPFixture, *routingHTTPFixture) {
	t.Helper()
	runtime, base, recorder, getServer := liteFixture(t)
	t.Cleanup(getServer.Close)
	configSHA := installRoutingFixtureAuthority(t, runtime, base, routingSyntheticMasterKey)
	runtime.LiteLLM.InferenceEnabled = true
	runtime.LiteLLM.ModelAlias = routingKnownAlias
	a := newRoutingHTTPFixture(t, routingSyntheticMasterKey, respondA)
	b := newRoutingHTTPFixture(t, routingSyntheticMasterKey, respondB)
	transport := &routingFixtureTransport{liteKubeTransport: liteKubeTransport{runtime: runtime}, configSHA: configSHA,
		key: routingSyntheticMasterKey, byPod: map[string]*routingHTTPFixture{"pod-a": a, "pod-b": b}}
	return runtime, transport, recorder, a, b
}

func routingValidPair(t *testing.T) func(string) routingFixtureReply {
	t.Helper()
	return func(alias string) routingFixtureReply {
		if alias == routingKnownAlias {
			return routingValidCompletion(t, alias)
		}
		return routingTypedError(t, http.StatusNotFound, "ModelNotFoundError", "model_not_found", "unknown model")
	}
}

func TestLiteLLMRoutingRealHTTPProbeClassifiesBoundaries(t *testing.T) {
	cases := []struct {
		name, alias, reason string
		reply               routingFixtureReply
		valid               bool
	}{
		{"known-completion", routingKnownAlias, "VALID_ASSISTANT_COMPLETION", routingValidCompletion(t, routingKnownAlias), true},
		{"typed-unknown", liteUnknownAlias, "MODEL_NOT_FOUND", routingTypedError(t, 404, "ModelNotFoundError", "model_not_found", "unknown model"), false},
		{"generic-400", liteUnknownAlias, "CONFIGURATION_ERROR", routingTypedError(t, 400, "BadRequestError", "bad_request", "generic error"), false},
		{"missing-db", routingKnownAlias, "NO_CONNECTED_DB", routingTypedError(t, 400, "BadRequestError", "bad_request", "No connected db."), false},
		{"typed-unknown-with-missing-db", liteUnknownAlias, "NO_CONNECTED_DB", routingTypedError(t, 400, "ModelNotFoundError", "model_not_found", "No connected db."), false},
		{"auth-401", routingKnownAlias, "AUTH_DENIED", routingTypedError(t, 401, "AuthenticationError", "invalid_api_key", "denied"), false},
		{"auth-403", routingKnownAlias, "AUTH_DENIED", routingTypedError(t, 403, "PermissionError", "forbidden", "denied"), false},
		{"rate-429", routingKnownAlias, "RATE_LIMITED", routingTypedError(t, 429, "RateLimitError", "rate_limit", "slow down"), false},
		{"provider-503", routingKnownAlias, "PROVIDER_OR_GATEWAY_ERROR", routingTypedError(t, 503, "ServiceUnavailableError", "provider_error", "provider unavailable"), false},
		{"partial-200", routingKnownAlias, "MALFORMED_RESPONSE", routingFixtureReply{status: 200, contentType: "application/json", body: `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`}, false},
		{"truncated-json", routingKnownAlias, "MALFORMED_RESPONSE", routingFixtureReply{status: 200, contentType: "application/json", body: `{"choices":`}, false},
		{"streaming", routingKnownAlias, "MALFORMED_RESPONSE", routingFixtureReply{status: 200, contentType: "text/event-stream", body: "data: hello\n\n"}, false},
		{"contradictory-200-error", routingKnownAlias, "MALFORMED_RESPONSE", routingFixtureReply{status: 200, contentType: "application/json", body: `{"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Ready."},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6},"error":{"type":"ProviderError","message":"failed"}}`}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply { return tc.reply })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			response, raw, err := runRoutingFixtureProbe(ctx, fixture, tc.alias, routingSyntheticMasterKey)
			if err != nil || response.Reason != tc.reason || response.CompletionValid != tc.valid || len(fixture.requestedModels()) != 1 {
				t.Fatalf("probe classification: response=%+v error=%v", response, err)
			}
			if bytes.Contains(raw, []byte(routingSyntheticMasterKey)) || bytes.Contains(raw, []byte(tc.reply.body)) {
				t.Fatal("probe retained credential or raw response body")
			}
		})
	}
}

func TestLiteLLMRoutingRealHTTPResponseCannotRetainCredential(t *testing.T) {
	// A misbehaving provider may echo an input credential in the model field.
	// A structurally valid completion remains a serving observation, but the
	// subprocess must replace the returned model string with a hash/relation.
	fixture := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingValidCompletion(t, routingSyntheticMasterKey)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, raw, err := runRoutingFixtureProbe(ctx, fixture, routingKnownAlias, routingSyntheticMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(routingSyntheticMasterKey))
	if bytes.Contains(raw, []byte(routingSyntheticMasterKey)) || !response.CompletionValid || response.Reason != "VALID_ASSISTANT_COMPLETION" ||
		response.ReturnedModel != "" || response.ModelRelation != "OTHER_REDACTED" || response.ReturnedModelSHA256 != fmt.Sprintf("%x", want) {
		t.Fatalf("credential echoed or valid completion lost: %+v", response)
	}
}

func TestLiteLLMRoutingRealHTTPVersionedReturnedModel(t *testing.T) {
	versioned := "openai/gpt-4o-mini-2026-09-25"
	fixture := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingValidCompletion(t, versioned)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, raw, err := runRoutingFixtureProbe(ctx, fixture, routingKnownAlias, routingSyntheticMasterKey)
	want := sha256.Sum256([]byte(versioned))
	if err != nil || !response.CompletionValid || response.Reason != "VALID_ASSISTANT_COMPLETION" || response.ModelRelation != "OTHER_REDACTED" ||
		response.ReturnedModel != "" || response.ReturnedModelSHA256 != fmt.Sprintf("%x", want) || bytes.Contains(raw, []byte(versioned)) {
		t.Fatalf("valid versioned completion was rejected or leaked: %+v, error=%v", response, err)
	}
}

func TestLiteLLMRoutingRealHTTPRefusesMissingKeyAndRedirect(t *testing.T) {
	fixture := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingFixtureReply{status: http.StatusFound, contentType: "text/plain", location: "/v1/chat/completions", body: "redirect"}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, raw, err := runRoutingFixtureProbe(ctx, fixture, routingKnownAlias, ""); err == nil || len(raw) != 0 || len(fixture.requestedModels()) != 0 {
		t.Fatal("absent declared key reached the application")
	}
	response, raw, err := runRoutingFixtureProbe(ctx, fixture, routingKnownAlias, routingSyntheticMasterKey)
	if err != nil || response.Status != http.StatusFound || response.CompletionValid || len(fixture.requestedModels()) != 1 || bytes.Contains(raw, []byte(routingSyntheticMasterKey)) {
		t.Fatalf("redirect followed or credited: %+v, error=%v", response, err)
	}
}

func TestLiteLLMRoutingRealHTTPProbeRefusesOversizeAndSlow(t *testing.T) {
	oversize := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingFixtureReply{status: 200, contentType: "application/json", body: strings.Repeat("x", liteRoutingMaxBody+1)}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, raw, err := runRoutingFixtureProbe(ctx, oversize, routingKnownAlias, routingSyntheticMasterKey)
	if err != nil || !response.BoundExceeded || validateLiteRoutingResponse(response) == nil || bytes.Contains(raw, []byte(routingSyntheticMasterKey)) {
		t.Fatalf("oversize response was accepted: %+v %v", response, err)
	}
	slow := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingFixtureReply{status: 200, contentType: "application/json", body: `{}`, delay: 250 * time.Millisecond}
	})
	short, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer stop()
	if _, _, err := runRoutingFixtureProbe(short, slow, routingKnownAlias, routingSyntheticMasterKey); err == nil {
		t.Fatal("slow response produced a completion receipt after deadline")
	}
}

func TestLiteLLMRoutingRealHTTPAbsoluteDeadlineStopsTrickle(t *testing.T) {
	fixture := newRoutingHTTPFixture(t, routingSyntheticMasterKey, func(string) routingFixtureReply {
		return routingFixtureReply{status: 200, contentType: "application/json", body: strings.Repeat(" ", 30), trickle: 50 * time.Millisecond}
	})
	// Change only the duration in the embedded production script. This still
	// executes its actual timer and request/read path without a 25-second test.
	script := strings.Replace(liteRoutingProbeScript, "absolute_seconds=25", "absolute_seconds=0.2", 1)
	if script == liteRoutingProbeScript {
		t.Fatal("embedded absolute deadline source unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	response, raw, err := runRoutingFixtureProbeScript(ctx, fixture, routingKnownAlias, routingSyntheticMasterKey, script)
	if err == nil || time.Since(started) >= time.Second || response.CompletionValid || len(raw) != 0 || len(fixture.requestedModels()) != 1 {
		t.Fatalf("trickling response evaded internal absolute deadline: %+v, error=%v, elapsed=%v", response, err, time.Since(started))
	}
}

func TestLiteLLMRoutingTwoExactPodsAndSanitizedConsumer(t *testing.T) {
	respond := routingValidPair(t)
	runtime, transport, recorder, podA, podB := routingRunFixture(t, respond, respond)
	h := liteRoutingHandler{transport: transport}
	if err := h.Validate(runtime); err != nil {
		t.Fatal(err)
	}
	result := h.Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeFunctionalPass || result.Evidence["requestCount"] != "4" ||
		result.Evidence["knownModelState"] != "COMPLETION_SERVED" || result.Evidence["unknownModelState"] != "MODEL_REJECTED" ||
		result.Evidence["pod1.version"] == result.Evidence["pod2.version"] || len(recorder.intents) != 4 || len(recorder.events) != 4 ||
		len(podA.requestedModels()) != 2 || len(podB.requestedModels()) != 2 {
		t.Fatalf("two-Pod routing result: %+v intents=%d events=%d", result, len(recorder.intents), len(recorder.events))
	}
	job := liteJobForTest(t, runtime, LiteLLMRouting)
	if err := ValidateResult(job, normalizeResult(job, h.Definition(), result, result.StartedAt)); err != nil {
		t.Fatalf("shared consumer rejected actual producer result: %v", err)
	}
	retained, err := json.Marshal(struct {
		Result  Result
		Intents []Intent
		Events  []Event
	}{result, recorder.intents, recorder.events})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{routingSyntheticMasterKey, "synthetic-provider-never-used", "Reply with OK."} {
		if bytes.Contains(retained, []byte(secret)) {
			t.Fatal("secret or raw prompt retained in evidence")
		}
	}
}

func TestLiteLLMRoutingMixedPodsRemainUnverified(t *testing.T) {
	respondA := routingValidPair(t)
	respondB := func(alias string) routingFixtureReply {
		if alias == routingKnownAlias {
			return routingTypedError(t, 400, "BadRequestError", "bad_request", "No connected db.")
		}
		return routingTypedError(t, 404, "ModelNotFoundError", "model_not_found", "unknown model")
	}
	runtime, transport, recorder, podA, podB := routingRunFixture(t, respondA, respondB)
	result := (liteRoutingHandler{transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "4" ||
		result.Evidence["pod1.known.state"] != "COMPLETION_SERVED" || result.Evidence["pod2.known.reason"] != "NO_CONNECTED_DB" ||
		result.Evidence["knownModelState"] != "UNVERIFIED" || len(podA.requestedModels()) != 2 || len(podB.requestedModels()) != 2 {
		t.Fatalf("mixed Pod outcome incorrectly passed or collapsed: %+v", result)
	}
}

func TestLiteLLMRoutingMissingEnvAndConfigDriftStopBeforePOST(t *testing.T) {
	respond := routingValidPair(t)
	runtime, transport, recorder, podA, podB := routingRunFixture(t, respond, respond)
	pod, err := runtime.Kube.CoreV1().Pods("litellm").Get(context.Background(), "litellm-rs-a", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Spec.Containers[0].Env = nil
	if _, err := runtime.Kube.CoreV1().Pods("litellm").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	result := (liteRoutingHandler{transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "0" || len(podA.requestedModels())+len(podB.requestedModels()) != 0 {
		t.Fatalf("missing declared master key reached application: %+v", result)
	}
	// A separately fresh fixture proves mounted ConfigMap drift is equally early.
	runtime, transport, recorder, podA, podB = routingRunFixture(t, respond, respond)
	cm, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Get(context.Background(), "litellm-config", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["config.yaml"] += "# drift\n"
	if _, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	result = (liteRoutingHandler{transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "0" || len(podA.requestedModels())+len(podB.requestedModels()) != 0 {
		t.Fatalf("config drift reached application: %+v", result)
	}
}

func TestLiteLLMRoutingPostResponseDriftPreservesFirstReceipt(t *testing.T) {
	respond := routingValidPair(t)
	runtime, transport, recorder, podA, podB := routingRunFixture(t, respond, respond)
	changed := false
	transport.afterPost = func(_ litePod) {
		if changed {
			return
		}
		changed = true
		cm, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Get(context.Background(), "litellm-config", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		cm.Data["config.yaml"] += "# changed after first POST\n"
		if _, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	result := (liteRoutingHandler{transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "1" ||
		result.Evidence["pod1.known.bodySHA256"] == "" || len(podA.requestedModels()) != 1 || len(podB.requestedModels()) != 0 {
		t.Fatalf("post-POST drift lost first receipt or continued: %+v", result)
	}
}
