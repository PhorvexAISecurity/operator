/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P4 — AI actuator stack)
 *
 * gpu_stack.go — the SERVING-STACK + GPU control-plane abstraction the AI handlers drive.
 *
 * DESIGN (persona panel: AI-Engineer / GPU-expert / MLSecOps / Cloud-engineer):
 *   - The serving control plane is HTTP (`vLLMClient`) — the production control plane vLLM/Triton/TGI
 *     already expose — NOT in-pod exec. Default impl talks vLLM's HTTP API; a Triton(gRPC)/TGI impl
 *     swaps in by implementing the SAME interface (the stack-specific calls are isolated here).
 *   - MIG reconfiguration is NVML/nvidia-smi behind a `nodeRunner` (the node-exec mechanism is
 *     infra-dependent — a privileged node agent / GPU-Operator mig-manager — so it is the part that is
 *     [PENDING-GPU-VALIDATION]; the COMMAND logic + ordering is real and unit-tested via a mock).
 *
 * HONEST tri-state every AI handler uses:
 *   (a) real call SUCCEEDS                      -> full effect.
 *   (b) endpoint UNREACHABLE (no serving stack, e.g. kind / no GPU node agent) -> the K8s mechanic is
 *       still enacted for real, the GPU/stack effect is recorded [PENDING-GPU-VALIDATION] (NEVER faked).
 *   (c) endpoint REACHABLE but the call FAILS   -> FAIL-CLOSED (return the error; never claim success).
 *
 * NONE of this is production-ready until calibrated on real GPU hardware — see [PENDING-GPU-VALIDATION].
 */

package actuator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ---- serving-stack control plane (vLLM default; Triton/TGI swappable) ----

// servingEndpoint identifies a model-serving pod's reachable HTTP control plane.
type servingEndpoint struct {
	podIP     string
	port      int
	resetPath  string // the prefix/KV-cache reset path (vLLM default; configurable per pod)
	healthPath string // liveness probe path (vLLM default /health; configurable per pod)
	modelsPath string // loaded-models list path (vLLM default /v1/models; configurable per pod)
	token      string // optional bearer for the admin op
	// P-ACTUATOR-SET-COMPLETE routes (vLLM-shaped defaults; per-pod annotation overrides).
	unloadPath string // LoRA unload (adapter-rotate)
	loadPath   string // LoRA load (adapter-rotate)
	drainPath  string // request drain/abort (request-drain, warm-swap drain)
	guardPath  string // guardrail reload (guardrail-rotate)
	kvInvPath  string // disaggregated KV invalidate (kv-migrate-invalidate)
}

func (e servingEndpoint) reachable() bool { return e.podIP != "" && e.port > 0 }
func (e servingEndpoint) base() string    { return fmt.Sprintf("http://%s:%d", e.podIP, e.port) }

const (
	// Pod annotations let an operator declare the serving stack per workload without code change.
	annoServingPort = "phorvex.ai/serving-port"   // default 8000 (vLLM OpenAI server)
	annoResetPath   = "phorvex.ai/kv-reset-path"   // default vLLM prefix-cache reset
	annoHealthPath  = "phorvex.ai/health-path"     // default /health (liveness probe)
	annoModelsPath  = "phorvex.ai/models-path"     // default /v1/models (loaded-model list)
	annoServingTok  = "phorvex.ai/serving-token"   // optional admin bearer (prefer a Secret ref in prod)
	defaultServePort = 8000
	// [PENDING-GPU-VALIDATION] confirm EVERY route against the deployed vLLM version: recent vLLM exposes
	// the prefix-cache reset on the engine; the exact routes differ by version/flag. All configurable via
	// the phorvex.ai/* annotations above (no hardcoded literal reaches the wire).
	defaultResetPath  = "/reset_prefix_cache"
	defaultHealthPath = "/health"
	defaultModelsPath = "/v1/models"
)

// endpointForPod derives the serving endpoint from a running pod (IP + declared port/path).
func endpointForPod(pod *corev1.Pod) servingEndpoint {
	ep := servingEndpoint{podIP: pod.Status.PodIP, port: defaultServePort, resetPath: defaultResetPath, healthPath: defaultHealthPath, modelsPath: defaultModelsPath}
	if v := pod.Annotations[annoServingPort]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ep.port = n
		}
	}
	if v := pod.Annotations[annoResetPath]; v != "" {
		ep.resetPath = v
	}
	if v := pod.Annotations[annoHealthPath]; v != "" {
		ep.healthPath = v
	}
	if v := pod.Annotations[annoModelsPath]; v != "" {
		ep.modelsPath = v
	}
	ep.token = pod.Annotations[annoServingTok]
	// P-ACTUATOR-SET-COMPLETE routes (annotation-overridable, vLLM-shaped defaults).
	ep = ep.withRoutes(pod.Annotations[annoUnloadPath], pod.Annotations[annoLoadPath],
		pod.Annotations[annoDrainPath], pod.Annotations[annoGuardrailPath], pod.Annotations[annoKVInvalidate])
	return ep
}

// errStackUnreachable signals case (b): no serving stack answered (connection refused/timeout/no IP)
// — distinct from a reachable-but-failing endpoint (case c, fail-closed).
var errStackUnreachable = errors.New("serving endpoint unreachable [PENDING-GPU-VALIDATION]")

// errAdapterAbsent means the serving stack answered and reported the named adapter is NOT
// loaded. For an EVICTION this is the goal state already met, not a failure — treating it as
// an error made adapter-rotate fail forever on a stale detector flag (the flag naming an
// adapter vLLM never had), which starved every other AI move on that pod. See adapterRotateHandler.
var errAdapterAbsent = errors.New("adapter not loaded on the serving stack")

// vLLMClient is the serving-stack control plane. Default impl = vLLM HTTP API. Swap for Triton/TGI.
type vLLMClient interface {
	// ModelReady reports whether the served model is LOADED + healthy at ep (warm-pool readiness).
	// Returns errStackUnreachable when no stack answers (so callers can fall back honestly on kind).
	ModelReady(ctx context.Context, ep servingEndpoint) (bool, error)
	// ResetPrefixCache flushes the prefix/KV cache in-process WITHOUT restarting (kv-reset).
	ResetPrefixCache(ctx context.Context, ep servingEndpoint) error
	// UnloadAdapter unloads a named LoRA/adapter (vLLM /v1/unload_lora_adapter; adapter-rotate).
	UnloadAdapter(ctx context.Context, ep servingEndpoint, adapter string) error
	// LoadAdapter loads a named LoRA/adapter from a (trusted, pinned) source path/uri.
	LoadAdapter(ctx context.Context, ep servingEndpoint, adapter, source string) error
	// DrainRequests stops admitting + aborts/finishes in-flight requests, returning the count
	// aborted (request-drain; also warm-swap's drain). Best-effort; pair with the K8s readiness flip.
	DrainRequests(ctx context.Context, ep servingEndpoint) (aborted int, err error)
}

// httpVLLM is the REAL vLLM HTTP control-plane client. [PENDING-GPU-VALIDATION] — calibrate the health/
// model/reset routes against the deployed vLLM version; on kind (no vLLM) calls surface errStackUnreachable.
type httpVLLM struct{ hc *http.Client }

func newHTTPVLLM() *httpVLLM { return &httpVLLM{hc: &http.Client{Timeout: 3 * time.Second}} }

func (c *httpVLLM) do(ctx context.Context, method, url, token string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// connection refused / no route / timeout => unreachable (no serving stack here).
		var ne net.Error
		if errors.As(err, &ne) || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "no such host") {
			return 0, "", errStackUnreachable
		}
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(b), nil
}

func (c *httpVLLM) ModelReady(ctx context.Context, ep servingEndpoint) (bool, error) {
	if !ep.reachable() {
		return false, errStackUnreachable
	}
	code, _, err := c.do(ctx, http.MethodGet, ep.base()+ep.healthPath, ep.token)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, nil
	}
	// health 200 => live; the models route lists the loaded model => model-loaded.
	mcode, body, err := c.do(ctx, http.MethodGet, ep.base()+ep.modelsPath, ep.token)
	if err != nil {
		return false, err
	}
	return mcode == http.StatusOK && strings.Contains(body, "\"data\""), nil
}

func (c *httpVLLM) ResetPrefixCache(ctx context.Context, ep servingEndpoint) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := c.do(ctx, http.MethodPost, ep.base()+ep.resetPath, ep.token)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("vLLM reset_prefix_cache: HTTP %d %s", code, strings.TrimSpace(body))
	}
	return nil
}

// ---- GPU MIG control plane (NVML/nvidia-smi behind a node runner) ----

// nodeRunner executes a command on a specific node (a privileged DaemonSet exec / GPU-Operator agent
// in production). [PENDING-GPU-VALIDATION] — the default runner is UNCONFIGURED so MIG ops fail-closed
// rather than fabricate a reconfiguration; a deployment injects the real node-exec.
type nodeRunner interface {
	Run(ctx context.Context, node string, argv ...string) (stdout string, err error)
	// Available is a non-mutating readiness probe (nil only if Run can actually execute on node).
	Available(ctx context.Context, node string) error
}

// migController abstracts the NVML/nvidia-smi MIG reconfiguration. Default impl = nvidiaSMIMIG.
type migController interface {
	// Available is a NON-mutating readiness probe: nil only if the node-exec transport can actually run
	// (agent pod present + exec wired). mig-rebind calls it BEFORE the destructive GPU-context eviction
	// so a non-GPU / unwired cluster fail-closes WITHOUT deleting the pod.
	Available(ctx context.Context, node string) error
	// CurrentProfile reads the MIG profile currently configured on the GPU (e.g. "1g.10gb").
	CurrentProfile(ctx context.Context, node, gpuID string) (string, error)
	// Repartition reconfigures the GPU to targetProfile (the caller MUST evict CUDA contexts first).
	Repartition(ctx context.Context, node, gpuID, targetProfile string) error
}

// nvidiaSMIMIG is the REAL nvidia-smi MIG controller. The command sequence + ordering is implemented
// and unit-tested via a mock nodeRunner; the live node-exec + GPU are [PENDING-GPU-VALIDATION].
type nvidiaSMIMIG struct{ run nodeRunner }

func (m *nvidiaSMIMIG) Available(ctx context.Context, node string) error {
	return m.run.Available(ctx, node)
}

func (m *nvidiaSMIMIG) CurrentProfile(ctx context.Context, node, gpuID string) (string, error) {
	out, err := m.run.Run(ctx, node, "nvidia-smi", "mig", "-i", gpuID, "-lgi")
	if err != nil {
		return "", err
	}
	// parse the first listed GPU-instance profile (e.g. "MIG 1g.10gb"); honest empty on no match.
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "MIG "); i >= 0 {
			f := strings.Fields(ln[i+4:])
			if len(f) > 0 {
				return f[0], nil
			}
		}
	}
	return "", nil
}

func (m *nvidiaSMIMIG) Repartition(ctx context.Context, node, gpuID, targetProfile string) error {
	if targetProfile == "" {
		return fmt.Errorf("mig repartition: empty target profile")
	}
	// REAL nvidia-smi sequence (drain is the caller's responsibility): destroy compute instances,
	// destroy GPU instances, then create the new geometry + default compute instances.
	for _, argv := range [][]string{
		{"nvidia-smi", "mig", "-i", gpuID, "-dci"},
		{"nvidia-smi", "mig", "-i", gpuID, "-dgi"},
		{"nvidia-smi", "mig", "-i", gpuID, "-cgi", targetProfile, "-C"},
	} {
		if _, err := m.run.Run(ctx, node, argv...); err != nil {
			return fmt.Errorf("mig repartition step %v: %w", argv[3:], err)
		}
	}
	return nil
}

// ---- EnactCtx resolution: handlers use the injected client or the real package default ----

var pkgVLLM vLLMClient = newHTTPVLLM()

func (ec EnactCtx) vllm() vLLMClient {
	if ec.VLLM != nil {
		return ec.VLLM
	}
	return pkgVLLM
}
// mig resolves the GPU MIG controller: an injected mock, else the REAL client-aware controller whose
// nvidia-smi commands run through the execNodeRunner transport (resolves a privileged MIG node-agent
// pod on the target node via ec.Client; the exec syscall is pkgNodeExec, [PENDING-GPU-VALIDATION] /
// fail-closed until a deployment wires it).
func (ec EnactCtx) mig() migController {
	if ec.MIG != nil {
		return ec.MIG
	}
	return &nvidiaSMIMIG{run: execNodeRunner{c: ec.Client, exec: pkgNodeExec, label: migAgentLabelKey}}
}
