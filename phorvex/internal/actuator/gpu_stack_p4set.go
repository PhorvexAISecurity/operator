/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR-SET-COMPLETE)
 *
 * gpu_stack_p4set.go — the stack control-plane surface for the NEW actuators (adapter-rotate,
 * request-drain, guardrail-rotate, kv-migrate-invalidate) + the REAL MIG node-exec transport that
 * completes mig-rebind. Every call is REAL code behind a swappable interface (vLLM default; Triton
 * EXPLICIT / TGI / LoRAX swap by re-implementing), marked [PENDING-GPU-VALIDATION] — the serving
 * routes + the node-exec syscall are confirmed on real hardware, not here. Same honest tri-state:
 * success / errStackUnreachable -> [PENDING] / reachable-fails -> fail-closed.
 */

package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Configurable serving-stack routes (per-pod annotations override; defaults are vLLM-shaped and
// [PENDING-GPU-VALIDATION] — confirm against the deployed vLLM/Triton/TGI version).
const (
	annoUnloadPath    = "phorvex.ai/lora-unload-path"
	annoLoadPath      = "phorvex.ai/lora-load-path"
	annoDrainPath     = "phorvex.ai/drain-path"
	annoGuardrailPath = "phorvex.ai/guardrail-path"
	annoKVInvalidate  = "phorvex.ai/kv-invalidate-path"
	defaultUnloadPath = "/v1/unload_lora_adapter"
	defaultLoadPath   = "/v1/load_lora_adapter"
	defaultDrainPath  = "/v1/drain"           // [PENDING-GPU-VALIDATION] no standard vLLM drain-all; deployment-specific
	defaultGuardPath  = "/v1/guardrail/reload" // [PENDING-GPU-VALIDATION] guardrail-service specific
	defaultKVInvPath  = "/v1/kv/invalidate"    // [PENDING-GPU-VALIDATION] disaggregation-connector specific
)

func pathOr(ep servingEndpoint, override, def string) string {
	if override != "" {
		return override
	}
	_ = ep
	return def
}

// postJSON performs a real POST with a JSON body through the shared http client, reusing httpVLLM.do's
// unreachable-vs-error discrimination.
func (c *httpVLLM) postJSON(ctx context.Context, url, token string, payload any) (int, string, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "timeout") {
			return 0, "", errStackUnreachable
		}
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<14)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n]), nil
}

func okCode(code int) bool {
	return code == http.StatusOK || code == http.StatusNoContent || code == http.StatusAccepted
}

// ---- vLLMClient NEW methods: adapter load/unload + request drain ----

func (c *httpVLLM) UnloadAdapter(ctx context.Context, ep servingEndpoint, adapter string) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := c.postJSON(ctx, ep.base()+ep.unloadPath, ep.token, map[string]string{"lora_name": adapter})
	if err != nil {
		return err
	}
	if !okCode(code) {
		return fmt.Errorf("vLLM unload_lora_adapter %q: HTTP %d %s", adapter, code, strings.TrimSpace(body))
	}
	return nil
}

func (c *httpVLLM) LoadAdapter(ctx context.Context, ep servingEndpoint, adapter, source string) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := c.postJSON(ctx, ep.base()+ep.loadPath, ep.token, map[string]string{"lora_name": adapter, "lora_path": source})
	if err != nil {
		return err
	}
	if !okCode(code) {
		return fmt.Errorf("vLLM load_lora_adapter %q from %q: HTTP %d %s", adapter, source, code, strings.TrimSpace(body))
	}
	return nil
}

func (c *httpVLLM) DrainRequests(ctx context.Context, ep servingEndpoint) (int, error) {
	if !ep.reachable() {
		return 0, errStackUnreachable
	}
	code, body, err := c.postJSON(ctx, ep.base()+ep.drainPath, ep.token, map[string]bool{"abort_inflight": true})
	if err != nil {
		return 0, err
	}
	if !okCode(code) {
		return 0, fmt.Errorf("serving drain: HTTP %d %s", code, strings.TrimSpace(body))
	}
	var r struct {
		Aborted int `json:"aborted"`
	}
	_ = json.Unmarshal([]byte(body), &r)
	return r.Aborted, nil
}

// servingEndpoint route accessors (annotation-overridable; resolved in endpointForPod's extension).
func (e servingEndpoint) withRoutes(unload, load, drain, guard, kvinv string) servingEndpoint {
	e.unloadPath = pathOr(e, unload, defaultUnloadPath)
	e.loadPath = pathOr(e, load, defaultLoadPath)
	e.drainPath = pathOr(e, drain, defaultDrainPath)
	e.guardPath = pathOr(e, guard, defaultGuardPath)
	e.kvInvPath = pathOr(e, kvinv, defaultKVInvPath)
	return e
}

// ---- guardrail control plane ----

// guardrailController rotates the safety/guardrail tier (variant/ruleset) to stale a found bypass.
// Default impl posts to a guardrail-service reload endpoint; a NeMo/Llama-Guard/Guardrails-AI impl
// swaps in. The K8s side (variant label / ruleset ConfigMap) is done by the handler.
type guardrailController interface {
	ApplyVariant(ctx context.Context, ep servingEndpoint, variant string) error
}

type httpGuardrail struct{ v *httpVLLM }

func (g httpGuardrail) ApplyVariant(ctx context.Context, ep servingEndpoint, variant string) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := g.v.postJSON(ctx, ep.base()+ep.guardPath, ep.token, map[string]string{"variant": variant})
	if err != nil {
		return err
	}
	if !okCode(code) {
		return fmt.Errorf("guardrail reload variant %q: HTTP %d %s", variant, code, strings.TrimSpace(body))
	}
	return nil
}

// ---- disaggregated KV-transfer control plane ----

// kvTransferController invalidates/migrates KV across disaggregated prefill/decode workers. The LOCAL
// invalidate is real + runnable; the cross-worker MigrateRemote is DEFERRED [PENDING-GPU-VALIDATION]
// (needs a disaggregated P/D deployment + the connector — vLLM --kv-transfer-config / Dynamo / Mooncake).
type kvTransferController interface {
	InvalidateLocal(ctx context.Context, ep servingEndpoint) error
	MigrateRemote(ctx context.Context, ep servingEndpoint, peers []string) error
}

type httpKVTransfer struct{ v *httpVLLM }

func (k httpKVTransfer) InvalidateLocal(ctx context.Context, ep servingEndpoint) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := k.v.postJSON(ctx, ep.base()+ep.kvInvPath, ep.token, map[string]bool{"local": true})
	if err != nil {
		return err
	}
	if !okCode(code) {
		return fmt.Errorf("kv invalidate(local): HTTP %d %s", code, strings.TrimSpace(body))
	}
	return nil
}

func (k httpKVTransfer) MigrateRemote(_ context.Context, _ servingEndpoint, _ []string) error {
	// DEFERRED by design — cross-worker KV migration/invalidation needs a live disaggregated P/D
	// fabric (RDMA/NVLink connector). Honest fail-closed rather than fabricate a cross-worker effect.
	return fmt.Errorf("kv MigrateRemote not built [PENDING-GPU-VALIDATION]: needs a disaggregated P/D deployment + connector")
}

// ---- REAL MIG node-exec transport (completes mig-rebind) ----

const (
	migAgentLabelKey = "phorvex.ai/mig-agent"
	migAgentContaine = "agent"
)

// execInPodFunc runs argv inside a container of a pod and returns stdout. The real implementation is
// a remotecommand SPDY exec (needs the clientset + REST config) injected by the deployment; the
// DEFAULT (pkgNodeExec == nil) makes execNodeRunner fail-closed [PENDING-GPU-VALIDATION] rather than
// fabricate a node exec.
type execInPodFunc func(ctx context.Context, ns, pod, container string, argv []string) (string, error)

var pkgNodeExec execInPodFunc // nil by default => mig node-exec fail-closed until a deployment wires it

// execNodeRunner is the GPU-Operator-mig-manager / privileged-node-agent transport: it resolves a
// privileged MIG node-agent DaemonSet pod ON the target node (REAL K8s) and execs argv into it. The
// agent-pod resolution is real + unit-tested; the exec syscall is injected ([PENDING-GPU-VALIDATION]).
type execNodeRunner struct {
	c     client.Client
	exec  execInPodFunc
	label string
}

// Available is the non-mutating readiness probe: the exec transport must be wired AND a node-agent pod
// must be Running on the target node. On kind / no GPU this returns an error so mig-rebind fail-closes
// BEFORE the destructive GPU-context eviction (never delete a pod we then cannot repartition).
func (r execNodeRunner) Available(ctx context.Context, node string) error {
	if r.exec == nil {
		return fmt.Errorf("MIG node-exec not wired [PENDING-GPU-VALIDATION]: no execInPod transport (needs clientset+remotecommand / GPU-Operator mig-manager)")
	}
	if pod, _ := r.agentPodOnNode(ctx, node); pod == "" {
		return fmt.Errorf("no MIG node-agent pod (label %s) Running on node %q [PENDING-GPU-VALIDATION]", r.label, node)
	}
	return nil
}

func (r execNodeRunner) Run(ctx context.Context, node string, argv ...string) (string, error) {
	if err := r.Available(ctx, node); err != nil {
		return "", err
	}
	pod, ns := r.agentPodOnNode(ctx, node)
	return r.exec(ctx, ns, pod, migAgentContaine, argv)
}

// agentPodOnNode finds a Running privileged MIG node-agent pod scheduled on `node`.
func (r execNodeRunner) agentPodOnNode(ctx context.Context, node string) (pod, ns string) {
	var pods corev1.PodList
	if err := r.c.List(ctx, &pods, client.MatchingLabels{r.label: "true"}); err != nil {
		return "", ""
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == node && p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			return p.Name, p.Namespace
		}
	}
	return "", ""
}

// ---- EnactCtx resolvers (injected client or real default) ----

var (
	pkgGuardrail guardrailController = httpGuardrail{v: newHTTPVLLM()}
	pkgKVXfer    kvTransferController = httpKVTransfer{v: newHTTPVLLM()}
)

func (ec EnactCtx) guardrail() guardrailController {
	if ec.Guardrail != nil {
		return ec.Guardrail
	}
	return pkgGuardrail
}
func (ec EnactCtx) kvxfer() kvTransferController {
	if ec.KVXfer != nil {
		return ec.KVXfer
	}
	return pkgKVXfer
}
