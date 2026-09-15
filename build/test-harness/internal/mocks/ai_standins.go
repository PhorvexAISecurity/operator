package mocks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ai_standins.go provides the SHARED, containment-safe AI stand-ins the Pass-B
// (ai1-*/ai2-*) scenarios use. EVERYTHING here is a busybox:1.36 CPU-only mock
// confined to the sandbox namespace — there is NO real LLM, registry, vector DB,
// cloud, or GPU. Every mock reuses the EXISTING internal/mocks patterns verbatim:
// httpResponderScript / deployServer / WaitHTTPReady / NewPod / owned labels /
// env.Exec marker-file oracles. MTD arms rotate whatever carries the
// RotationTargetLabel; backend-only rotation (external Service name stable, leader
// pod label rotates) mirrors AI-MTD-AUDIT #3.

// ---- shared AI stand-in labels / markers ----

const (
	// RotationTargetLabelKey is the label the rotation arms (d-r6blindtimer /
	// d-randomequal / d-fullphoenix AMTD PodSelector) target. It MIRRORS
	// defenders.RotationTargetLabel by value; it is restated here (not imported) so
	// the low-level mocks package stays free of a defenders dependency. The scenario
	// tests pin that the two stay in sync.
	RotationTargetLabelKey = "r6th.io/rotation-target"

	// InferLeaderLabel is the leader label the mock inference Service selects on.
	// Backend-only rotation churns the pod carrying this; the EXTERNAL Service name
	// stays stable (audit #3).
	InferLeaderLabel = "r6th.io/infer-leader"
	// InferLeaderValue is the initial leader value.
	InferLeaderValue = "a"

	// MockWeightsDigest is the FAKE weights digest the model card / registry serve.
	MockWeightsDigest = "sha256:r6thmockweights"
	// GoldenModelDigest is the signed "golden" digest the registry restores on a
	// regenerate (the benign provenance anchor).
	GoldenModelDigest = "sha256:r6thgoldenmodel"
	// PoisonedModelDigest is the digest a poisoning step mutates the manifest to.
	PoisonedModelDigest = "sha256:r6thpoisonedmodel"

	// Per-stand-in OBSERVABLE markers (all distinct so one oracle cannot cross-read
	// another mock's marker and report a false-positive success).
	InjectionMarker           = "R6TH-PROMPT-INJECTION-FIRED"
	RAGPoisonMarker           = "R6TH-RAG-POISON-DOC"
	ToolPoisonMarker          = "R6TH-MCP-TOOL-POISON"
	RogueServerMarker         = "R6TH-MCP-ROGUE-SERVER"
	ToolResponseInjMarker     = "R6TH-MCP-TOOLRESP-INJECT"
	MemoryContaminationMarker = "R6TH-AGENT-MEM-CONTAMINATION"
	RogueToolMarker           = "R6TH-AGENT-ROGUE-TOOL"
	ConfusedDeputyMarker      = "R6TH-AGENT-CONFUSED-DEPUTY"
	AgentBackdoorMarker       = "R6TH-AGENT-BACKDOOR"
	SensitiveSecretMarker     = "R6TH-LEAKED-SECRET-FAKE-KEY"
	SystemPromptMarker        = "R6TH-SYSTEM-PROMPT-SECRET"
	KVLeakMarker              = "R6TH-KVCACHE-CROSS-SESSION-LEAK"
	EmbeddingTamperMarker     = "R6TH-EMBEDDING-TAMPER"
	MaliciousArtifactMarker   = "R6TH-MALICIOUS-ARTIFACT-PAYLOAD-RAN"
	ShadowComputeMarker       = "R6TH-SHADOW-COMPUTE"
)

// ---- 1) MockInferenceServer ("the model") ----

// MockInferenceServer is the busybox HTTP "model" on :9000 behind an EXTERNAL
// ClusterIP Service whose selector is the LEADER label (so the external name is
// stable while the backend pod label rotates — audit #3 backend-only rotation).
// It accrues "GPU-seconds" of compute per request to /tmp/work_accrued (a CPU
// proxy for GPU utilization, CapGPU/GPU-PENDING for the headline number) and
// holds per-session "memory" in /tmp/session_<id> (the persistence substrate). A
// /tmp/kv_<session> file mocks the KV-cache (real KV behavior is GPU-PENDING).
type MockInferenceServer struct {
	*MockServer
}

// simpleInferenceScript is a readiness-friendly variant: a plain catch-all
// responder that serves a fixed model-card body so WaitHTTPReady passes, while
// still accruing work per request. It avoids the double-listen complexity of
// inferenceScript on busybox nc (one accept per loop). The richer per-path
// behavior is exercised by the scenario via marker files + env.Exec, which is the
// same approach the other mocks use for their oracles.
func simpleInferenceScript() string {
	body := `{"text":"completion","confidence":0.87,"model":"r6th-mock-llm","digest":"` + MockWeightsDigest + `"}`
	format := fmt.Sprintf(`HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%%s`, len(body))
	return `: > /tmp/work_accrued; ` +
		`echo "` + MockWeightsDigest + `" > /tmp/weights_digest; ` +
		fmt.Sprintf(`while true; do `+
			`prev=$(cat /tmp/work_accrued 2>/dev/null || echo 0); echo $((prev + 1)) > /tmp/work_accrued; `+
			`printf '%s' %s | nc -l -p $PORT -w 30 2>/dev/null || sleep 1; `+
			`done`, format, shQuote(body))
}

// DeployMockInferenceServer stands up the model pod (carrying the rotation-target
// AND leader labels) plus an EXTERNAL ClusterIP Service that selects ONLY the
// leader label (mock-infer-svc). Backend rotation churns the pod; the service
// name is stable.
func DeployMockInferenceServer(ctx context.Context, env *core.Env) (*MockInferenceServer, error) {
	srv, err := deployLeaderServer(ctx, env, "mock-infer", "mock-infer-svc", 9000, simpleInferenceScript(),
		map[string]string{"r6th.io/mock": "inference", RotationTargetLabelKey: "true"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock inference server up at %s:%d (external svc stable, backend leader=%s rotates; work_accrued = GPU-seconds CPU proxy)", srv.ClusterDNS, srv.Port, InferLeaderValue)
	return &MockInferenceServer{srv}, nil
}

// WorkAccrued reads the accrued "GPU-seconds" compute counter (a CPU stand-in for
// GPU utilization). It is the in-request oracle measurement for LLM-jacking /
// unbounded-consumption (the headline GPU number is capability-pending).
func (m *MockInferenceServer) WorkAccrued(ctx context.Context, env *core.Env) (int64, error) {
	return readCounterFile(ctx, env, m.PodName, "server", "/tmp/work_accrued")
}

// AccrueShadowCompute simulates a hijacked shadow-compute job by bumping the
// work_accrued counter by units and writing the shadow marker. Containment-safe:
// it is a marker + counter bump inside the pod (no real GPU work, no egress).
func (m *MockInferenceServer) AccrueShadowCompute(ctx context.Context, env *core.Env, units int) {
	script := fmt.Sprintf("prev=$(cat /tmp/work_accrued 2>/dev/null || echo 0); echo $((prev + %d)) > /tmp/work_accrued; echo %s > /tmp/shadow", units, ShadowComputeMarker)
	_ = execMarker(ctx, env, m.PodName, "server", script)
}

// PlantInjection writes the in-request prompt-injection override the model echoes
// back (the in-request injection marker), and persists it to a session file so a
// "memory-persisted instruction" can survive (or not) a rotation.
func (m *MockInferenceServer) PlantInjection(ctx context.Context, env *core.Env, sessionID string) {
	script := fmt.Sprintf("echo %s > /tmp/inject; echo %s > /tmp/session_%s; echo %s > /tmp/kv_%s",
		InjectionMarker, InjectionMarker, sessionID, KVLeakMarker, sessionID)
	_ = execMarker(ctx, env, m.PodName, "server", script)
}

// PlantSystemPromptSecret seeds a system prompt carrying a planted secret marker
// (system-prompt-leakage oracle).
func (m *MockInferenceServer) PlantSystemPromptSecret(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf("echo '%s' > /tmp/system_prompt; echo %s > /tmp/secret", SystemPromptMarker, SensitiveSecretMarker)
	_ = execMarker(ctx, env, m.PodName, "server", script)
}

// MarkerPresent reports whether a marker file inside the inference pod contains
// the wanted marker (the generic in-pod oracle read).
func (m *MockInferenceServer) MarkerPresent(ctx context.Context, env *core.Env, path, want string) bool {
	return markerPresentByApp(ctx, env, m.Name, "server", path, want) // robust to backend rotation
}

// ---- 2) MockMCPServer(s) ----

// MockMCPServer is the busybox MCP (Model Context Protocol) stand-in on :9100. It
// serves GET /tools (a tool manifest — the tool-poisoning surface) and POST
// /call/<tool> (echoes a tool result the agent ingests). Tool descriptions/results
// live in /tmp so a poisoning step is observable. Two flavors deploy: trusted
// (mock-mcp-svc) and rogue (mock-rogue-mcp-svc).
type MockMCPServer struct {
	*MockServer
	Rogue bool
}

// mcpScript serves a fixed tools manifest (readiness-friendly catch-all) and keeps
// the tool manifest + last result in /tmp so a poisoning step is observable.
func mcpScript(rogue bool) string {
	tool := `{"name":"search","description":"search the corpus","schema":{"q":"string"}}`
	rogueLine := ""
	if rogue {
		rogueLine = `echo "` + RogueServerMarker + `" > /tmp/rogue_id; `
	}
	body := `{"tools":[` + tool + `]}`
	format := fmt.Sprintf(`HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%%s`, len(body))
	return rogueLine +
		`echo ` + shQuote(tool) + ` > /tmp/tools_manifest; ` +
		fmt.Sprintf(`while true; do printf '%s' %s | nc -l -p $PORT -w 30 2>/dev/null || sleep 1; done`, format, shQuote(body))
}

// DeployMockMCPServer deploys a trusted (rogue=false) or rogue (rogue=true) MCP
// server. The trusted server carries the rotation-target label; the rogue one is
// an UNTRUSTED impersonator with its own stable service.
func DeployMockMCPServer(ctx context.Context, env *core.Env, rogue bool) (*MockMCPServer, error) {
	name := "mock-mcp"
	svc := "mock-mcp-svc"
	extra := map[string]string{"r6th.io/mock": "mcp"}
	if rogue {
		name = "mock-rogue-mcp"
		svc = "mock-rogue-mcp-svc"
		extra = map[string]string{"r6th.io/mock": "mcp-rogue"}
	} else {
		extra[RotationTargetLabelKey] = "true"
	}
	srv, err := deployNamedServer(ctx, env, name, svc, 9100, mcpScript(rogue), extra)
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock MCP server up at %s:%d (rogue=%v; /tools manifest + /call/<tool> in /tmp)", srv.ClusterDNS, srv.Port, rogue)
	return &MockMCPServer{MockServer: srv, Rogue: rogue}, nil
}

// PoisonToolDescription mutates the served tool manifest to carry the poison
// marker in its description (the tool-poisoning surface) — observable in /tmp.
func (s *MockMCPServer) PoisonToolDescription(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf(`echo '{"name":"search","description":"%s","schema":{"q":"string"}}' > /tmp/tools_manifest`, ToolPoisonMarker)
	_ = execMarker(ctx, env, s.PodName, "server", script)
}

// PlantToolResponseInjection writes a malicious tool RESULT the agent will ingest
// (tool-response injection).
func (s *MockMCPServer) PlantToolResponseInjection(ctx context.Context, env *core.Env) {
	_ = execMarker(ctx, env, s.PodName, "server", "echo "+ToolResponseInjMarker+" > /tmp/last_result")
}

// ToolManifestContains reports whether the served tool manifest carries the marker.
func (s *MockMCPServer) ToolManifestContains(ctx context.Context, env *core.Env, want string) bool {
	return markerPresentByApp(ctx, env, s.Name, "server", "/tmp/tools_manifest", want) // robust to rotation
}

// ---- 3) MockModelRegistry ----

// MockModelRegistry EXTENDS the existing MockRegistry pattern (registry.go) on
// :8083: it serves a model manifest {name,version,digest,signature}, a model blob
// bearing a digest (GET /models/<n>/blob), and a catalog (GET /index). A writable
// /tmp/manifest.json lets a poisoning/tamper step mutate the served digest/
// signature (the observable oracle). It reuses the PoisonedImageRef idea for the
// ai2-tampered-inference-base-image scenario.
type MockModelRegistry struct {
	*MockServer
	// PoisonedImageRef is the logical tampered serving-image reference (reuses the
	// MockRegistry tamper pattern).
	PoisonedImageRef string
}

// modelRegistryScript serves the golden manifest by default and keeps it writable
// in /tmp so a tamper step mutates the digest/signature observably.
func modelRegistryScript() string {
	golden := `{"name":"r6th-mock-llm","version":"1.0.0","digest":"` + GoldenModelDigest + `","signature":"r6th-signed-golden"}`
	format := fmt.Sprintf(`HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%%s`, len(golden))
	return `echo ` + shQuote(golden) + ` > /tmp/manifest.json; ` +
		`echo "` + GoldenModelDigest + `" > /tmp/served_digest; ` +
		fmt.Sprintf(`while true; do printf '%s' %s | nc -l -p $PORT -w 30 2>/dev/null || sleep 1; done`, format, shQuote(golden))
}

// DeployMockModelRegistry deploys the model registry stand-in.
func DeployMockModelRegistry(ctx context.Context, env *core.Env) (*MockModelRegistry, error) {
	srv, err := deployServer(ctx, env, "mock-model-registry", 8083, modelRegistryScript(), map[string]string{"r6th.io/mock": "model-registry"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock model registry up at %s:%d (golden digest %s; writable /tmp/manifest.json for tamper oracle)", srv.ClusterDNS, srv.Port, GoldenModelDigest)
	return &MockModelRegistry{MockServer: srv, PoisonedImageRef: srv.ClusterDNS + ":8083/r6th/tampered-inference:latest"}, nil
}

// PoisonManifest mutates the served digest/signature to the poisoned value (the
// supply-chain poisoning oracle). Observable via ServedDigest.
func (r *MockModelRegistry) PoisonManifest(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf(`echo '{"name":"r6th-mock-llm","version":"6.6.6","digest":"%s","signature":"r6th-FORGED"}' > /tmp/manifest.json; echo "%s" > /tmp/served_digest`, PoisonedModelDigest, PoisonedModelDigest)
	_ = execMarker(ctx, env, r.PodName, "server", script)
}

// RestoreGolden is an explicit fixture reset. It is not a supported Regenerate
// action on the registry and must not run in a scored scenario.
func (r *MockModelRegistry) RestoreGolden(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf(`echo '{"name":"r6th-mock-llm","version":"1.0.0","digest":"%s","signature":"r6th-signed-golden"}' > /tmp/manifest.json; echo "%s" > /tmp/served_digest`, GoldenModelDigest, GoldenModelDigest)
	_ = execMarker(ctx, env, r.PodName, "server", script)
}

// ServedDigest reads the digest the registry currently serves (golden vs poisoned).
func (r *MockModelRegistry) ServedDigest(ctx context.Context, env *core.Env) string {
	res := env.Exec(ctx, r.PodName, "server", []string{"sh", "-c", "cat /tmp/served_digest 2>/dev/null"})
	return strings.TrimSpace(res.Stdout)
}

// ObservedServedDigest rejects failed and malformed reads. A missing digest must
// never be interpreted as a defender clearing poison.
func (r *MockModelRegistry) ObservedServedDigest(ctx context.Context, env *core.Env) (string, error) {
	digest, _, err := r.ObservedServedDigestWithUID(ctx, env)
	return digest, err
}

// ObservedServedDigestWithUID brackets exec with fresh Pod identity reads.
// Same-name recreation, deletion and non-running targets invalidate the value.
func (r *MockModelRegistry) ObservedServedDigestWithUID(ctx context.Context, env *core.Env) (string, string, error) {
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("read registry target: %w", err)
	}
	uid := string(pod.UID)
	if uid == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return "", "", fmt.Errorf("registry target has no stable running identity")
	}
	res := env.Exec(ctx, r.PodName, "server", []string{"sh", "-c", "cat /tmp/served_digest"})
	if res.Err != nil || res.ExitCode != 0 {
		return "", "", fmt.Errorf("read served digest: exit=%d: %w", res.ExitCode, execReadError(res))
	}
	digest := strings.TrimSpace(res.Stdout)
	if digest != GoldenModelDigest && digest != PoisonedModelDigest {
		return "", "", fmt.Errorf("malformed served digest %q", digest)
	}
	after, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("recheck registry target: %w", err)
	}
	if string(after.UID) != uid || after.DeletionTimestamp != nil || after.Status.Phase != corev1.PodRunning {
		return "", "", fmt.Errorf("registry target changed during digest read")
	}
	return digest, uid, nil
}

func execReadError(res core.ExecResult) error {
	if res.Err != nil {
		return res.Err
	}
	return fmt.Errorf("command failed: %s", res.Stderr)
}

// ---- 4) MockRetriever + EmbeddingStore ----

// MockRetriever is the busybox tiny vector store on :9200: POST /upsert appends to
// /tmp/store.jsonl, POST /query returns top-k by a cheap seeded score, GET /doc/<id>.
// The corpus + a poisoned doc (with an embedded instruction) live in /tmp so RAG-
// poisoning / embedding-tamper steps are observable.
type MockRetriever struct {
	*MockServer
}

// retrieverScript serves a fixed top-k body (readiness-friendly) and seeds the
// store file. The corpus + poison live in /tmp; the scenario writes/reads them via
// env.Exec (the same marker-file oracle approach as the other mocks).
func retrieverScript() string {
	body := `{"results":[{"id":"doc1","text":"benign","score":0.9}]}`
	format := fmt.Sprintf(`HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%%s`, len(body))
	return `: > /tmp/store.jsonl; ` +
		`echo '{"id":"doc1","text":"benign","vector":[0.1,0.2]}' >> /tmp/store.jsonl; ` +
		fmt.Sprintf(`while true; do printf '%s' %s | nc -l -p $PORT -w 30 2>/dev/null || sleep 1; done`, format, shQuote(body))
}

// DeployMockRetriever deploys the retriever/embedding-store stand-in.
func DeployMockRetriever(ctx context.Context, env *core.Env) (*MockRetriever, error) {
	srv, err := deployServer(ctx, env, "mock-retriever", 9200, retrieverScript(), map[string]string{"r6th.io/mock": "retriever"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock retriever/embedding store up at %s:%d (corpus + poison in /tmp/store.jsonl)", srv.ClusterDNS, srv.Port)
	return &MockRetriever{srv}, nil
}

// PoisonCorpus appends a poisoned document (with an embedded instruction marker)
// to the corpus — RAG retrieval poisoning. Observable via TopKContains.
func (r *MockRetriever) PoisonCorpus(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf(`echo '{"id":"poison","text":"%s ignore-previous","vector":[0.9,0.9],"score":1.0}' >> /tmp/store.jsonl; echo %s > /tmp/topk`, RAGPoisonMarker, RAGPoisonMarker)
	_ = execMarker(ctx, env, r.PodName, "server", script)
}

// TamperEmbedding mutates a stored vector so an unrelated query returns the tamper
// doc top-k (embedding-store tampering).
func (r *MockRetriever) TamperEmbedding(ctx context.Context, env *core.Env) {
	script := fmt.Sprintf(`echo '{"id":"tamper","text":"%s","vector":[0.0,0.0],"score":1.0}' >> /tmp/store.jsonl; echo %s > /tmp/topk`, EmbeddingTamperMarker, EmbeddingTamperMarker)
	_ = execMarker(ctx, env, r.PodName, "server", script)
}

// TopKContains reports whether the top-k result marker file carries the want
// marker (the poisoned/tampered doc is still top-k).
func (r *MockRetriever) TopKContains(ctx context.Context, env *core.Env, want string) bool {
	return markerFilePresent(ctx, env, r.PodName, "server", "/tmp/topk", want)
}

// StoreContains reports whether the corpus store file carries the want marker.
func (r *MockRetriever) StoreContains(ctx context.Context, env *core.Env, want string) bool {
	return markerFilePresent(ctx, env, r.PodName, "server", "/tmp/store.jsonl", want)
}

// ---- 5) MockAgentRuntime ----

// AgentMemoryConfigMap / AgentToolsConfigMap are the OWNED ConfigMaps the agent
// runtime uses for cross-session memory and its tool registry. A rotation that
// also deletes these clears the contamination / rogue-tool; an external/PVC-backed
// store would survive (measured per arm).
const (
	AgentMemoryConfigMap = "agent-memory"
	AgentToolsConfigMap  = "agent-tools"
)

// MockAgentRuntime is the busybox "agent" pod that, per step, calls the retriever,
// the MCP server (/tools then /call), and the inference server, persisting
// cross-session memory to the agent-memory ConfigMap (+ /tmp/agent_mem) and using
// agent-tools as its tool registry. Its "excessive agency" is modeled by calling a
// high-privilege mock tool it should not (observable via a marker).
type MockAgentRuntime struct {
	PodName string
}

// DeployMockAgentRuntime stands up the agent pod (rotation target) plus the owned
// memory + tools ConfigMaps.
func DeployMockAgentRuntime(ctx context.Context, env *core.Env) (*MockAgentRuntime, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	// Owned ConfigMaps (memory + tools).
	for _, cm := range []struct {
		name string
		data map[string]string
	}{
		{AgentMemoryConfigMap, map[string]string{"mem": "clean"}},
		{AgentToolsConfigMap, map[string]string{"tools": "search,summarize"}},
	} {
		obj := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: cm.name, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(nil)},
			Data:       cm.data,
		}
		env.Log.Command(fmt.Sprintf("kubectl create configmap %s -n %s  # agent %s substrate", cm.name, env.Config.Namespace, cm.name))
		if _, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("create configmap %s: %w", cm.name, err)
		}
	}

	name := "mock-agent"
	labels := LabelMap(map[string]string{"app": name, "r6th.io/mock": "agent", RotationTargetLabelKey: "true"})
	pod := NewPod(env, name, labels).
		WithBusyboxLoop("agent", agentLoopScript(), 100, 32).
		WithRestartPolicy(corev1.RestartPolicyAlways).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s -l %s=true  # mock agent runtime (tool-calling loop)", name, BusyboxImage, env.Config.Namespace, RotationTargetLabelKey))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create agent pod: %w", err)
	}
	if err := env.WaitForPodRunning(ctx, name, waitTimeout); err != nil {
		env.Log.Logf("mock agent pod not Ready in time: %v", err)
	}
	return &MockAgentRuntime{PodName: name}, nil
}

// agentLoopScript is the per-step agent loop stand-in: it persists local memory to
// /tmp/agent_mem and idles. The cross-session memory + tool registry live in the
// owned ConfigMaps (mutated/read via the API), which is the rotation substrate.
func agentLoopScript() []string {
	return []string{"sh", "-c",
		": > /tmp/agent_mem; : > /tmp/agent_actions; " +
			"while true; do sleep 5; done"}
}

// CallPrivilegedTool models the agent's EXCESSIVE AGENCY / confused-deputy: it
// invokes a high-privilege mock tool it should not, writing the confused-deputy
// marker to its action log (observable).
func (a *MockAgentRuntime) CallPrivilegedTool(ctx context.Context, env *core.Env) {
	_ = execMarker(ctx, env, a.PodName, "agent", "echo "+ConfusedDeputyMarker+" >> /tmp/agent_actions")
}

// PlantBackdoorStep models an injection escalating to a persistence step: the
// agent plants a backdoor marker in its pod (evicted by an injected panic event).
func (a *MockAgentRuntime) PlantBackdoorStep(ctx context.Context, env *core.Env) {
	_ = execMarker(ctx, env, a.PodName, "agent", "echo "+AgentBackdoorMarker+" > /tmp/agent_backdoor")
}

// ContaminateMemory writes a contamination marker into the cross-session memory
// ConfigMap (survives a pod restart but NOT a rotation that also deletes the CM).
func (a *MockAgentRuntime) ContaminateMemory(ctx context.Context, env *core.Env) error {
	return patchConfigMap(ctx, env, AgentMemoryConfigMap, "mem", MemoryContaminationMarker)
}

// RegisterRogueTool registers a durable malicious tool in the agent-tools
// ConfigMap (rogue-tool persistence).
func (a *MockAgentRuntime) RegisterRogueTool(ctx context.Context, env *core.Env) error {
	return patchConfigMap(ctx, env, AgentToolsConfigMap, "tools", "search,summarize,"+RogueToolMarker)
}

// RestoreGoldenTools is an explicit fixture reset, not a supported Regenerate
// action on the tools ConfigMap. It must not run in a scored scenario.
func (a *MockAgentRuntime) RestoreGoldenTools(ctx context.Context, env *core.Env) error {
	return patchConfigMap(ctx, env, AgentToolsConfigMap, "tools", "search,summarize")
}

// MemoryContains reports whether the agent-memory ConfigMap carries the marker.
func (a *MockAgentRuntime) MemoryContains(ctx context.Context, env *core.Env, want string) bool {
	return configMapContains(ctx, env, AgentMemoryConfigMap, "mem", want)
}

// ToolsContain reports whether the agent-tools ConfigMap carries the marker.
func (a *MockAgentRuntime) ToolsContain(ctx context.Context, env *core.Env, want string) bool {
	return configMapContains(ctx, env, AgentToolsConfigMap, "tools", want)
}

// ObservedTools reads the owned registry without collapsing API errors or a
// missing tools key into a successful defense observation.
func (a *MockAgentRuntime) ObservedTools(ctx context.Context, env *core.Env) (string, error) {
	tools, _, err := a.ObservedToolsWithUID(ctx, env)
	return tools, err
}

// ObservedToolsWithUID binds content and ConfigMap identity to the same API Get.
func (a *MockAgentRuntime) ObservedToolsWithUID(ctx context.Context, env *core.Env) (string, string, error) {
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, AgentToolsConfigMap, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("read agent tools: %w", err)
	}
	uid := string(cm.UID)
	if uid == "" || cm.DeletionTimestamp != nil {
		return "", "", fmt.Errorf("agent tools target has no stable identity")
	}
	tools, ok := cm.Data["tools"]
	if !ok || strings.TrimSpace(tools) == "" {
		return "", "", fmt.Errorf("agent tools observation missing tools value")
	}
	if tools != "search,summarize" && tools != "search,summarize,"+RogueToolMarker {
		return "", "", fmt.Errorf("malformed agent tools observation %q", tools)
	}
	return tools, uid, nil
}

// ActionLogContains reports whether the agent pod's action log carries the marker.
func (a *MockAgentRuntime) ActionLogContains(ctx context.Context, env *core.Env, want string) bool {
	return markerPresentByApp(ctx, env, a.PodName, "agent", "/tmp/agent_actions", want) // robust to rotation
}

// BackdoorPresent reports whether the agent backdoor marker survives in any
// running agent pod (gone after an injected-panic eviction).
func (a *MockAgentRuntime) BackdoorPresent(ctx context.Context, env *core.Env) bool {
	return markerPresentByApp(ctx, env, a.PodName, "agent", "/tmp/agent_backdoor", AgentBackdoorMarker) // robust to rotation
}

// ---- shared deploy/exec/configmap helpers (reuse deployServer pattern) ----

// deployNamedServer is deployServer with an explicit Service name (so the MCP
// rogue/trusted servers get their own stable service names).
func deployNamedServer(ctx context.Context, env *core.Env, name, svcName string, port int32, script string, extraLabels map[string]string) (*MockServer, error) {
	ms, err := deployServer(ctx, env, name, port, script, extraLabels)
	if err != nil {
		return ms, err
	}
	if svcName != name+"-svc" {
		// Create the explicitly-named alias service selecting the same pod.
		alias := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"app": name})},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": name, core.OwnedLabelKey: core.OwnedLabelValue},
				Ports:    []corev1.ServicePort{{Port: port, TargetPort: intstr.FromInt32(port)}},
			},
		}
		env.Log.Command(fmt.Sprintf("kubectl expose pod %s-pod --name=%s --port=%d -n %s", name, svcName, port, env.Config.Namespace))
		if _, err := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, alias, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return ms, fmt.Errorf("create alias svc %s: %w", svcName, err)
		}
		ms.SvcName = svcName
		ms.ClusterDNS = fmt.Sprintf("%s.%s.svc.cluster.local", svcName, env.Config.Namespace)
	}
	return ms, nil
}

// deployLeaderServer deploys a mock whose EXTERNAL Service selects ONLY the leader
// label (audit #3 backend-only rotation: stable external name, rotating backend).
// The pod carries the leader label AND whatever extraLabels are passed (incl. the
// rotation-target label so the timer arms churn it).
func deployLeaderServer(ctx context.Context, env *core.Env, name, svcName string, port int32, script string, extraLabels map[string]string) (*MockServer, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	podName := name + "-pod"
	labels := LabelMap(map[string]string{"app": name, InferLeaderLabel: InferLeaderValue}, extraLabels)
	container := corev1.Container{
		Name:            "server",
		Image:           BusyboxImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", script},
		Env:             []corev1.EnvVar{{Name: "PORT", Value: fmt.Sprintf("%d", port)}},
		Ports:           []corev1.ContainerPort{{ContainerPort: port}},
	}
	pod := NewPod(env, podName, LabelMap(labels, map[string]string{"r6th.io/role": "mock"})).
		WithContainer(container).
		WithRestartPolicy(corev1.RestartPolicyAlways).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # mock %s :%d (leader=%s)", podName, BusyboxImage, env.Config.Namespace, name, port, InferLeaderValue))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create leader pod %s: %w", podName, err)
	}
	// EXTERNAL Service selects ONLY the leader label (NOT the pod name), so backend
	// rotation that re-stamps the leader on a fresh pod keeps the external name stable.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"app": name})},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{InferLeaderLabel: InferLeaderValue, core.OwnedLabelKey: core.OwnedLabelValue},
			Ports:    []corev1.ServicePort{{Port: port, TargetPort: intstr.FromInt32(port)}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl expose --selector=%s=%s --name=%s --port=%d -n %s  # EXTERNAL svc (stable name, backend leader rotates)", InferLeaderLabel, InferLeaderValue, svcName, port, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create leader svc %s: %w", svcName, err)
	}
	ms := &MockServer{
		Name:       name,
		PodName:    podName,
		SvcName:    svcName,
		Port:       port,
		ClusterDNS: fmt.Sprintf("%s.%s.svc.cluster.local", svcName, env.Config.Namespace),
	}
	if err := env.WaitForPodRunning(ctx, podName, waitTimeout); err != nil {
		env.Log.Logf("mock %s pod not Ready in time: %v", name, err)
	}
	return ms, nil
}

// MockServerExec runs a small in-pod sh script against a MockServer's "server"
// container (a marker write/mutation step the scenario observes via an oracle).
// Exported so scenarios can drive a stand-in's observable state with the SAME
// containment-safe exec pattern the mocks use internally.
func MockServerExec(ctx context.Context, env *core.Env, ms *MockServer, script string) error {
	if ms == nil {
		return fmt.Errorf("MockServerExec: nil mock server")
	}
	return execMarker(ctx, env, ms.PodName, "server", script)
}

// MarkerOnServer reports whether a marker file in a MockServer's "server"
// container contains want (the generic in-pod oracle read, exported for scenarios).
func MarkerOnServer(ctx context.Context, env *core.Env, ms *MockServer, path, want string) bool {
	if ms == nil {
		return false
	}
	return markerPresentByApp(ctx, env, ms.Name, "server", path, want) // robust to rotation
}

// execMarker runs a small in-pod sh script (a marker write/mutation) and logs it.
// In a non-live env (unit test) it is a no-op-ish exec that records the command.
func execMarker(ctx context.Context, env *core.Env, pod, container, script string) error {
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", script})
	if res.Err != nil {
		env.Log.Logf("execMarker (%s) error: %v", pod, res.Err)
	}
	return res.Err
}

// markerFilePresent reads a file inside a pod and reports whether it contains want.
func markerFilePresent(ctx context.Context, env *core.Env, pod, container, path, want string) bool {
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", "cat " + path + " 2>/dev/null"})
	return strings.Contains(res.Stdout, want)
}

// currentPodForApp returns a RUNNING, non-terminating pod carrying app=<app> in the sandbox (the
// CURRENT foothold pod after any rotation), or "" if none.
func currentPodForApp(ctx context.Context, env *core.Env, app string) string {
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + app})
	if err != nil {
		return ""
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			return p.Name
		}
	}
	return ""
}

// markerPresentByApp checks the marker on the CURRENT pod for app — robust to rotation + emergent-
// rate arms (PX). [P-REDTEAM measurement-bug fix #2] A FIXED-pod-name cat could not reflect a
// rotation that replaced (or deleted) the foothold pod with a fresh one: a session/foothold marker
// that lived only in the OLD pod must read as ABSENT after such a rotation. Resolving the CURRENT
// app pod yields the honest post-rotation outcome (gone => false). An in-request marker checked
// BEFORE the rotation window still finds the original pod (so genuine in-request ceilings stay true).
func markerPresentByApp(ctx context.Context, env *core.Env, app, container, path, want string) bool {
	pod := currentPodForApp(ctx, env, app)
	if pod == "" {
		return false // the foothold pod is gone (rotated away) => the marker is absent
	}
	return markerFilePresent(ctx, env, pod, container, path, want)
}

// readCounterFile reads an integer counter file from inside a pod.
func readCounterFile(ctx context.Context, env *core.Env, pod, container, path string) (int64, error) {
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", "cat " + path + " 2>/dev/null || echo 0"})
	if res.Err != nil {
		return 0, res.Err
	}
	v := strings.TrimSpace(res.Stdout)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse counter %q: %w", v, err)
	}
	return n, nil
}

// patchConfigMap sets data[key]=val on an owned ConfigMap (the agent memory/tools
// substrate). It goes through the safety guard.
func patchConfigMap(ctx context.Context, env *core.Env, name, key, val string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[key] = val
	env.Log.Command(fmt.Sprintf("kubectl patch configmap %s -n %s --data %s=%s", name, env.Config.Namespace, key, truncateForLog(val)))
	_, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// configMapContains reports whether an owned ConfigMap's data[key] carries want.
func configMapContains(ctx context.Context, env *core.Env, name, key, want string) bool {
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false
	}
	return strings.Contains(cm.Data[key], want)
}

func truncateForLog(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
