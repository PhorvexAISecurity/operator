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
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/phorvex/phorvex/internal/podresources"
)

const servingResponseMaxBytes = 1 << 16

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
	defaultDrainPath  = "/v1/drain"            // [PENDING-GPU-VALIDATION] no standard vLLM drain-all; deployment-specific
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, servingResponseMaxBytes+1))
	if err != nil {
		return 0, "", fmt.Errorf("read serving response: %w", err)
	}
	if len(body) > servingResponseMaxBytes {
		return 0, "", fmt.Errorf("serving response exceeds %d bytes", servingResponseMaxBytes)
	}
	return resp.StatusCode, string(body), nil
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
	// 404 = "The lora adapter 'x' cannot be found": the stack ANSWERED and the adapter is not
	// loaded. For an eviction that is the desired end state, so surface it as a distinct sentinel
	// rather than a generic failure (the caller decides it means "already converged").
	if code == http.StatusNotFound {
		return fmt.Errorf("%w: %q (HTTP 404 %s)", errAdapterAbsent, adapter, strings.TrimSpace(body))
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
	// A request drain is synchronous evidence. Accepted/NoContent cannot establish a
	// terminal abort count, so only an exact 200 response enters the strict parser.
	if code != http.StatusOK {
		return 0, fmt.Errorf("serving drain: HTTP %d %s", code, strings.TrimSpace(body))
	}
	aborted, err := parseDrainResponse(body)
	if err != nil {
		return 0, fmt.Errorf("serving drain response: %w", err)
	}
	return aborted, nil
}

// parseDrainResponse accepts one bounded terminal JSON object with one nonnegative integer
// `aborted` field. Unknown extension fields remain compatible, while duplicate/missing fields,
// fractional or overflowing values, trailing JSON and asynchronous/empty bodies are rejected.
func parseDrainResponse(body string) (int, error) {
	dec := json.NewDecoder(strings.NewReader(body))
	token, err := dec.Token()
	if err != nil {
		return 0, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return 0, fmt.Errorf("expected one JSON object")
	}
	seen, aborted := false, 0
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return 0, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return 0, fmt.Errorf("object key is not a string")
		}
		if key == "aborted" {
			if seen {
				return 0, fmt.Errorf("duplicate aborted field")
			}
			seen = true
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return 0, fmt.Errorf("aborted must be an integer: %w", err)
			}
			if string(raw) == "null" {
				return 0, fmt.Errorf("aborted must be an integer, not null")
			}
			if err := json.Unmarshal(raw, &aborted); err != nil {
				return 0, fmt.Errorf("aborted must be an integer: %w", err)
			}
			continue
		}
		var ignored json.RawMessage
		if err := dec.Decode(&ignored); err != nil {
			return 0, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return 0, err
	}
	if !seen {
		return 0, fmt.Errorf("aborted field is required")
	}
	if aborted < 0 {
		return 0, fmt.Errorf("aborted must be nonnegative")
	}
	if token, err := dec.Token(); err != io.EOF {
		if err == nil {
			return 0, fmt.Errorf("unexpected trailing JSON token %v", token)
		}
		return 0, fmt.Errorf("trailing response data: %w", err)
	}
	return aborted, nil
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
// Handler syntax validation is not destination authorization: any production implementation must
// enforce a separate operator-owned peer allowlist before dialing tenant-declared endpoints.
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

const migAgentLabelKey = "phorvex.ai/mig-agent"

// execInPodFunc runs argv inside a container of a pod and returns stdout. The real implementation is
// a remotecommand SPDY exec (needs the clientset + REST config) injected by the deployment; the
// DEFAULT (pkgNodeRunner == nil) makes execNodeRunner fail-closed [PENDING-GPU-VALIDATION] rather than
// fabricate a node exec.
type execInPodFunc func(ctx context.Context, ns, pod, container string, argv []string) (string, error)

var pkgNodeRunner *execNodeRunner // nil by default; no production caller wires it

type unwiredNodeRunner struct{}

func (unwiredNodeRunner) Prepare(context.Context, string) (preparedNodeRunner, error) {
	return nil, fmt.Errorf("MIG node-exec not wired [PENDING-GPU-VALIDATION]: no validated transport and agent policy")
}

// execNodeRunner is the GPU-Operator-mig-manager / privileged-node-agent transport: it resolves a
// privileged MIG node-agent DaemonSet pod ON the target node (REAL K8s) and execs argv into it. The
// agent-pod resolution is real + unit-tested; the exec syscall is injected ([PENDING-GPU-VALIDATION]).
type execNodeRunner struct {
	client kubernetes.Interface
	exec   execInPodFunc
	policy MIGAgentPolicy
	cache  *migObservationCache
}

type migObservationCache struct {
	mu          sync.Mutex
	allocations map[string]cachedAllocations
	inventories map[string]cachedInventory
}
type cachedAllocations struct {
	at    time.Time
	value podresources.Snapshot
}
type cachedInventory struct {
	at    time.Time
	value string
}

const (
	migObservationCacheTTL        = 2 * time.Second
	maxMIGObservationCacheEntries = 32
)

func (c *migObservationCache) pruneLocked(now time.Time) {
	for key, cached := range c.allocations {
		if now.Sub(cached.at) > migObservationCacheTTL {
			delete(c.allocations, key)
		}
	}
	for key, cached := range c.inventories {
		if now.Sub(cached.at) > migObservationCacheTTL {
			delete(c.inventories, key)
		}
	}
}

func (c *migObservationCache) allocation(key string) (podresources.Snapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.pruneLocked(now)
	cached, ok := c.allocations[key]
	return cached.value, ok && now.Sub(cached.at) <= migObservationCacheTTL
}

func (c *migObservationCache) inventory(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.pruneLocked(now)
	cached, ok := c.inventories[key]
	return cached.value, ok && now.Sub(cached.at) <= migObservationCacheTTL
}

func (c *migObservationCache) storeAllocation(key string, value podresources.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.allocations == nil {
		c.allocations = make(map[string]cachedAllocations)
	}
	now := time.Now()
	c.pruneLocked(now)
	if _, exists := c.allocations[key]; !exists && len(c.allocations) >= maxMIGObservationCacheEntries {
		return
	}
	c.allocations[key] = cachedAllocations{at: now, value: value}
}

func (c *migObservationCache) storeInventory(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inventories == nil {
		c.inventories = make(map[string]cachedInventory)
	}
	now := time.Now()
	c.pruneLocked(now)
	if _, exists := c.inventories[key]; !exists && len(c.inventories) >= maxMIGObservationCacheEntries {
		return
	}
	c.inventories[key] = cachedInventory{at: now, value: value}
}

type migCapabilityProbeKey struct{}

func migCapabilityProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, migCapabilityProbeKey{}, true)
}
func isMIGCapabilityProbe(ctx context.Context) bool {
	v, _ := ctx.Value(migCapabilityProbeKey{}).(bool)
	return v
}

func (r *boundNodeRunner) observationCacheKey() string {
	return r.ref.node + "\x00" + string(r.ref.daemonSetUID) + "\x00" + string(r.ref.uid)
}

type agentRef struct {
	namespace, name, container, allocationContainer, node string
	uid, daemonSetUID                                     types.UID
}

type boundNodeRunner struct {
	client kubernetes.Interface
	exec   execInPodFunc
	policy MIGAgentPolicy
	ref    agentRef
	cache  *migObservationCache
}

// Prepare resolves exactly one trusted pod through direct API reads and binds its identity for the
// complete MIG operation. Namespace is an administrative trust boundary; pod fields alone do not
// authenticate a creator with unrestricted write access inside that namespace.
func (r execNodeRunner) Prepare(ctx context.Context, node string) (preparedNodeRunner, error) {
	if r.client == nil || r.exec == nil {
		return nil, fmt.Errorf("MIG node-exec not wired [PENDING-GPU-VALIDATION]: no validated transport")
	}
	ds, err := r.client.AppsV1().DaemonSets(r.policy.Namespace).Get(ctx, r.policy.DaemonSet, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get configured MIG agent DaemonSet %s/%s: %w", r.policy.Namespace, r.policy.DaemonSet, err)
	}
	if ds.UID == "" || ds.DeletionTimestamp != nil {
		return nil, fmt.Errorf("configured MIG agent DaemonSet %s/%s has no stable live identity", r.policy.Namespace, r.policy.DaemonSet)
	}
	selector, err := metav1.LabelSelectorAsSelector(ds.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("configured MIG agent DaemonSet selector: %w", err)
	}
	pods, err := r.client.CoreV1().Pods(r.policy.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: migAgentLabelKey + "=true",
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list MIG node agents in namespace %s: %w", r.policy.Namespace, err)
	}
	var matches []agentRef
	for i := range pods.Items {
		p := &pods.Items[i]
		if r.validPod(p, ds, selector, node, "") == nil {
			matches = append(matches, agentRef{namespace: p.Namespace, name: p.Name, uid: p.UID, container: r.policy.Container, allocationContainer: r.policy.AllocationContainer, node: node, daemonSetUID: ds.UID})
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("MIG node-agent selection on node %q: require exactly one trusted candidate, got %d", node, len(matches))
	}
	return &boundNodeRunner{client: r.client, exec: r.exec, policy: r.policy, ref: matches[0], cache: r.cache}, nil
}

func (r execNodeRunner) validPod(p *corev1.Pod, ds *appsv1.DaemonSet, selector labels.Selector, node string, uid types.UID) error {
	if p.Namespace != r.policy.Namespace || p.Spec.NodeName != node || p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil || p.UID == "" || (uid != "" && p.UID != uid) {
		return fmt.Errorf("pod identity or lifecycle mismatch")
	}
	if p.Labels[migAgentLabelKey] != "true" || !selector.Matches(labels.Set(p.Labels)) {
		return fmt.Errorf("pod labels do not match configured agent")
	}
	allowed := false
	for _, sa := range r.policy.ServiceAccounts {
		if p.Spec.ServiceAccountName == sa {
			allowed = true
			break
		}
	}
	if !allowed || !podHasContainer(p, r.policy.Container) || !podHasContainer(p, r.policy.AllocationContainer) || !migAgentReady(p) {
		return fmt.Errorf("pod service account, container, or readiness mismatch")
	}
	for _, owner := range p.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == "apps/v1" && owner.Kind == "DaemonSet" && owner.Name == r.policy.DaemonSet && owner.UID == ds.UID && ds.UID != "" {
			return nil
		}
	}
	return fmt.Errorf("pod is not controlled by configured DaemonSet UID")
}

func (r *boundNodeRunner) revalidate(ctx context.Context) error {
	ds, err := r.client.AppsV1().DaemonSets(r.ref.namespace).Get(ctx, r.policy.DaemonSet, metav1.GetOptions{})
	if err != nil || ds.UID != r.ref.daemonSetUID || ds.DeletionTimestamp != nil {
		return fmt.Errorf("revalidate MIG agent DaemonSet identity: uid=%q err=%v", daemonSetUID(ds), err)
	}
	pod, err := r.client.CoreV1().Pods(r.ref.namespace).Get(ctx, r.ref.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("revalidate MIG agent pod %s/%s: %w", r.ref.namespace, r.ref.name, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(ds.Spec.Selector)
	if err != nil || (execNodeRunner{policy: r.policy}).validPod(pod, ds, selector, r.ref.node, r.ref.uid) != nil {
		return fmt.Errorf("revalidate MIG agent pod %s/%s: bound identity or readiness changed", r.ref.namespace, r.ref.name)
	}
	return nil
}

func podHasContainer(p *corev1.Pod, name string) bool {
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == name {
			return true
		}
	}
	return false
}

func migAgentReady(p *corev1.Pod) bool {
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *boundNodeRunner) Run(ctx context.Context, argv ...string) (string, error) {
	if err := r.revalidate(ctx); err != nil {
		return "", err
	}
	capabilityInventory := isMIGCapabilityProbe(ctx) && len(argv) == 2 && argv[0] == "nvidia-smi" && argv[1] == "-L" && r.cache != nil
	if capabilityInventory {
		key := r.observationCacheKey()
		if cached, ok := r.cache.inventory(key); ok {
			return cached, nil
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, r.policy.ExecTimeout)
	defer cancel()
	// pods/exec is name-addressed and has no UID precondition. This direct GET narrows but cannot
	// eliminate the GET-to-POST replacement race; the configured namespace must be protected.
	out, err := r.exec(execCtx, r.ref.namespace, r.ref.name, r.ref.container, argv)
	if err == nil && capabilityInventory {
		r.cache.storeInventory(r.observationCacheKey(), out)
	}
	return out, err
}

func (r *boundNodeRunner) Allocations(ctx context.Context) (podresources.Snapshot, error) {
	if err := r.revalidate(ctx); err != nil {
		return podresources.Snapshot{}, err
	}
	if isMIGCapabilityProbe(ctx) && r.cache != nil {
		key := r.observationCacheKey()
		if cached, ok := r.cache.allocation(key); ok {
			return cached, nil
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, r.policy.AllocationReadTimeout)
	defer cancel()
	out, err := r.exec(execCtx, r.ref.namespace, r.ref.name, r.ref.allocationContainer,
		[]string{r.policy.AllocationHelper, "--socket", r.policy.AllocationSocket, "--timeout", r.policy.AllocationReadTimeout.String()})
	if err != nil {
		return podresources.Snapshot{}, fmt.Errorf("read node PodResources: %w", err)
	}
	s, err := podresources.Decode([]byte(out))
	if err == nil && isMIGCapabilityProbe(ctx) && r.cache != nil {
		r.cache.storeAllocation(r.observationCacheKey(), s)
	}
	return s, err
}

func (r *boundNodeRunner) allocationReleaseTimeout() time.Duration {
	return r.policy.AllocationReleaseTimeout
}

func daemonSetUID(ds *appsv1.DaemonSet) types.UID {
	if ds == nil {
		return ""
	}
	return ds.UID
}

// ---- EnactCtx resolvers (injected client or real default) ----

var (
	pkgGuardrail guardrailController  = httpGuardrail{v: newHTTPVLLM()}
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
