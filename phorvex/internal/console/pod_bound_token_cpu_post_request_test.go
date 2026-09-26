package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func cpuPostRequestFixture(t *testing.T) (*RunManager, *RunStatus, string, cpuCleanupProof) {
	t.Helper()
	const target = "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"
	const runID = "run-controlled"
	const nonce = "60bf41c9878d9056727f1b15"
	base := "pod-token-" + nonce
	uid := map[string]string{}
	for i, resource := range []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"} {
		uid[resource] = fmt.Sprintf("%08d-1111-4111-8111-%012d", i+1, i+1)
	}
	const nsUID = "a1b25080-ee41-4485-918b-e67481b0c4ed"
	const clusterUID = "f113d464-d8cb-4145-b83d-45638c2a196e"
	const sourceUID = "95c1b8ab-ffd1-4f95-ba9e-c166c0f120c0"
	const peerUID = "9c1f34d5-aee1-441e-8126-75ecf9533574"
	const rsUID = "ee2d1530-1dad-4ba8-bb26-e181d8e49fb8"
	const amtdUID = "84d76124-b101-4b9c-a9c5-292ccea6b7a4"
	sourceName, peerName := base+"-abcde", base+"-fghij"
	start := time.Date(2026, 9, 26, 19, 53, 0, 0, time.UTC)
	at := start
	var rows []podBoundPhaseRow
	add := func(op, resource, name, identity string) {
		rows = append(rows, podBoundPhaseRow{Schema: "pod-bound-token-phase-v1", RunID: runID,
			Nonce: nonce, Operation: op, Resource: resource, Name: name, UID: identity,
			At: at.Format(time.RFC3339Nano)})
		at = at.Add(time.Second)
	}
	resources := []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"}
	for _, resource := range resources[:6] {
		add("CREATE_INTENT", resource, base, "")
		add("CREATE_ACK", resource, base, uid[resource])
	}
	add("PATCH_INTENT", "pods", sourceName, sourceUID)
	add("PATCH_ACK", "pods", sourceName, sourceUID)
	for _, resource := range resources[6:] {
		add("CREATE_INTENT", resource, base, "")
		add("CREATE_ACK", resource, base, uid[resource])
	}
	requested := at.Add(65 * time.Second)
	at = requested.Add(20 * time.Second)
	add("DELETE_INTENT", "phorvexpolicies", base, uid["phorvexpolicies"])
	add("DELETE_ACK", "phorvexpolicies", base, uid["phorvexpolicies"])
	add("DELETE_INTENT", "adaptivemovingtargetdefenses", "phorvex-"+podBoundTokenCPUNamespace+"-"+nonce, amtdUID)
	add("DELETE_ACK", "adaptivemovingtargetdefenses", "phorvex-"+podBoundTokenCPUNamespace+"-"+nonce, amtdUID)
	for _, resource := range []string{"podmonitors", "poddisruptionbudgets", "deployments", "rolebindings", "roles", "services", "serviceaccounts"} {
		add("DELETE_INTENT", resource, base, uid[resource])
		add("DELETE_ACK", resource, base, uid[resource])
	}
	var journal bytes.Buffer
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		journal.Write(encoded)
		journal.WriteByte('\n')
	}
	created := make([]string, 0, len(resources))
	for _, resource := range resources {
		created = append(created, resource+"/"+base+"/"+uid[resource])
	}
	sort.Strings(created)
	unsafe := PodBoundTokenUnsafeReceipt{Schema: "pod-bound-token-unsafe-v1", RunID: runID,
		Nonce: nonce, NamespaceUID: nsUID, CreatedUIDs: created, DeploymentUID: uid["deployments"],
		ReplicaSetUID: rsUID, SourcePodUID: sourceUID, PeerPodUID: peerUID,
		PhaseJournalSHA256: podBoundHash(journal.Bytes()), CleanupStatus: "CONFIRMED_ABSENT",
		InventorySHA256: strings.Repeat("c", 64), ErrorSHA256: podBoundHash([]byte("synthetic late error")),
		RecordedAt: at.Format(time.RFC3339Nano)}
	req := podBoundTokenRequest{Schema: "pod-bound-token-request-v1", CaseID: podBoundTokenCPUCaseID,
		RunID: runID, Nonce: nonce, ClusterUID: clusterUID, Namespace: podBoundTokenCPUNamespace,
		NamespaceUID: nsUID, SourcePodName: sourceName, SourcePodUID: sourceUID,
		PeerPodName: peerName, PeerPodUID: peerUID, ServiceName: base, ServiceUID: uid["services"],
		PDBUID: uid["poddisruptionbudgets"], DeploymentUID: uid["deployments"], ReplicaSetUID: rsUID,
		PolicyName: base, PolicyUID: uid["phorvexpolicies"], PolicyGeneration: 1,
		PolicySpecSHA256: strings.Repeat("a", 64), ManagerPodUID: "manager-uid",
		ManagerContainerID: "containerd://manager", ManagerImageID: "manager@sha256:1",
		ProfileSHA256: strings.Repeat("b", 64), SourceBeforeHTTP: 200, PeerBeforeHTTP: 200,
		ServiceBeforeHTTP: 200, SourceExpiry: requested.Add(8 * time.Minute).Format(time.RFC3339Nano),
		PeerExpiry:            requested.Add(8 * time.Minute).Format(time.RFC3339Nano),
		SourceBeforeRequestAt: requested.Add(-20 * time.Second).Format(time.RFC3339Nano),
		SourceBeforeAt:        requested.Add(-19 * time.Second).Format(time.RFC3339Nano),
		PeerBeforeRequestAt:   requested.Add(-18 * time.Second).Format(time.RFC3339Nano),
		PeerBeforeAt:          requested.Add(-17 * time.Second).Format(time.RFC3339Nano),
		RequestedAt:           requested.Format(time.RFC3339Nano), SourceCaptureID: strings.Repeat("1", 32),
		PeerCaptureID: strings.Repeat("2", 32), MetricStatus: "MEASURED_FRESH",
		MetricFirstAt:    requested.Add(-65 * time.Second).Format(time.RFC3339Nano),
		MetricSecondAt:   requested.Add(-35 * time.Second).Format(time.RFC3339Nano),
		MetricFirstValue: 48, MetricSecondValue: 64, MetricSourcePodName: sourceName,
		PodMonitorUID: uid["podmonitors"], MetricQuerySHA256: strings.Repeat("d", 64)}
	// Keep both samples after the exact monitor and source PATCH acknowledgements.
	req.MetricFirstAt = start.Add(30 * time.Second).Format(time.RFC3339Nano)
	req.MetricSecondAt = start.Add(60 * time.Second).Format(time.RFC3339Nano)
	req.RequestedAt = start.Add(68 * time.Second).Format(time.RFC3339Nano)
	requested = start.Add(68 * time.Second)
	req.SourceExpiry = requested.Add(8 * time.Minute).Format(time.RFC3339Nano)
	req.PeerExpiry = req.SourceExpiry
	req.SourceBeforeRequestAt = requested.Add(-20 * time.Second).Format(time.RFC3339Nano)
	req.SourceBeforeAt = requested.Add(-19 * time.Second).Format(time.RFC3339Nano)
	req.PeerBeforeRequestAt = requested.Add(-18 * time.Second).Format(time.RFC3339Nano)
	req.PeerBeforeAt = requested.Add(-17 * time.Second).Format(time.RFC3339Nano)
	cfg := Config{StateDir: t.TempDir()}
	prior := &RunStatus{ID: runID, Config: podBoundTokenCPUConfig, State: "partial",
		Namespace: podBoundTokenCPUNamespace, CleanupStatus: "UNVERIFIED", UnsafeToRetry: true,
		ScopeTenant: podBoundTokenCPUNamespace, ScopeTarget: target, Finished: "2026-09-26 19:58:00 UTC",
		Owner: "reviewed-owner", Error: "Pod-bound token early unsafe receipt: 8 created UIDs, cleanup CONFIRMED_ABSENT; exact reconciliation required"}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{runID: prior}, procs: map[string]*exec.Cmd{}, stopping: map[string]bool{}}
	out := cfg.runOutputPath(runID)
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		t.Helper()
		var raw []byte
		if b, ok := value.([]byte); ok {
			raw = b
		} else {
			raw, _ = json.Marshal(value)
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(podBoundPhaseFile, journal.Bytes())
	write("pod-bound-token-unsafe.json", unsafe)
	write(podBoundRequestFile, req)
	reqRaw, _ := os.ReadFile(filepath.Join(out, podBoundRequestFile))
	write("pod-bound-token-audit-start.json", podBoundTokenAuditStart{Schema: "pod-bound-token-audit-start-v1",
		RunID: runID, Nonce: nonce, SourceIdentity: "reviewed-audit-source", RequestSHA256: podBoundHash(reqRaw),
		Segment: audittransport.Segment{ID: "live", Generation: "one", Anchor: strings.Repeat("f", 32), Size: 100}, Offset: 100})
	proof, err := cpuPostRequestCleanupProofAt(prior, out, target)
	if err != nil {
		t.Fatalf("controlled post-request cleanup refused: %v", err)
	}
	return rm, prior, out, proof
}

func TestCPUPostRequestCleanupOriginalAndTamper(t *testing.T) {
	rm, prior, out, _ := cpuPostRequestFixture(t)
	if proofs, err := rm.cpuCleanupProofsLocked(prior.ScopeTarget); err != nil || len(proofs) != 1 || !proofs[0].postRequest {
		t.Fatalf("controlled predecessor refused: %v %+v", err, proofs)
	}
	if prior.State != "partial" || !prior.UnsafeToRetry || prior.CleanupStatus != "UNVERIFIED" {
		t.Fatal("historical failure was relabeled")
	}
	for _, name := range []string{podBoundRequestFile, "pod-bound-token-audit-start.json", podBoundPhaseFile} {
		original, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		mutated := append([]byte{}, original...)
		if name == "pod-bound-token-audit-start.json" {
			mutated = bytes.Replace(mutated, []byte(`"sourceIdentity":"reviewed-audit-source"`), []byte(`"sourceIdentity":""`), 1)
		} else {
			mutated = append(mutated, ' ')
		}
		if err := os.WriteFile(filepath.Join(out, name), mutated, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := rm.cpuCleanupProofsLocked(prior.ScopeTarget); err == nil {
			t.Fatalf("tampered %s admitted", name)
		}
		if err := os.WriteFile(filepath.Join(out, name), original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{podBoundBarrierFile, podBoundTerminalFile, podBoundObservationEndFile} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := rm.cpuCleanupProofsLocked(prior.ScopeTarget); err == nil {
			t.Fatalf("contradictory %s admitted", name)
		}
		if err := os.Remove(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	requestRaw, err := os.ReadFile(filepath.Join(out, podBoundRequestFile))
	if err != nil {
		t.Fatal(err)
	}
	auditRaw, err := os.ReadFile(filepath.Join(out, "pod-bound-token-audit-start.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req podBoundTokenRequest
	var start podBoundTokenAuditStart
	if json.Unmarshal(requestRaw, &req) != nil || json.Unmarshal(auditRaw, &start) != nil {
		t.Fatal("fixture decode")
	}
	wrong := req
	wrong.SourcePodUID = "95c1b8ab-ffd1-4f95-ba9e-c166c0f120c1"
	wrongRaw, _ := json.Marshal(wrong)
	start.RequestSHA256 = podBoundHash(wrongRaw)
	wrongStart, _ := json.Marshal(start)
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), wrongRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pod-bound-token-audit-start.json"), wrongStart, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.cpuCleanupProofsLocked(prior.ScopeTarget); err == nil {
		t.Fatal("request with rehashed audit but changed source UID admitted")
	}
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), requestRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pod-bound-token-audit-start.json"), auditRaw, 0600); err != nil {
		t.Fatal(err)
	}
	// This would otherwise decode to the same UID: only the case-folded key
	// ambiguity guard distinguishes it after the audit SHA is recomputed.
	aliased := append(append([]byte{}, requestRaw[:len(requestRaw)-1]...),
		[]byte(`,"SourcePodUID":"`+req.SourcePodUID+`"}`)...)
	if err := json.Unmarshal(auditRaw, &start); err != nil {
		t.Fatal(err)
	}
	start.RequestSHA256 = podBoundHash(aliased)
	aliasStart, _ := json.Marshal(start)
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), aliased, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pod-bound-token-audit-start.json"), aliasStart, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.cpuCleanupProofsLocked(prior.ScopeTarget); err == nil {
		t.Fatal("case-alias request with matching audit SHA admitted")
	}
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), requestRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pod-bound-token-audit-start.json"), auditRaw, 0600); err != nil {
		t.Fatal(err)
	}
	prior.ScopeTarget = "unknown-target"
	if _, err := rm.cpuCleanupProofsLocked("arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"); err == nil {
		t.Fatal("changed destination scope admitted")
	}
}

func TestCPUPostRequestOriginalRun23Shape(t *testing.T) {
	originals := os.Getenv("CPU_RUN23_ORIGINALS")
	if originals == "" {
		t.Skip("set CPU_RUN23_ORIGINALS to the preserved private originals")
	}
	cfg := Config{StateDir: t.TempDir()}
	prior := &RunStatus{ID: "run-23", Config: podBoundTokenCPUConfig, State: "partial",
		Namespace: podBoundTokenCPUNamespace, CleanupStatus: "UNVERIFIED", UnsafeToRetry: true,
		ScopeTenant: podBoundTokenCPUNamespace,
		ScopeTarget: "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks",
		Finished:    "2026-09-26 19:57:47 UTC", Owner: "reviewed-owner",
		Error: "Pod-bound token early unsafe receipt: 8 created UIDs, cleanup CONFIRMED_ABSENT; exact reconciliation required"}
	out := cfg.runOutputPath(prior.ID)
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{podBoundPhaseFile, "pod-bound-token-unsafe.json", podBoundRequestFile, "pod-bound-token-audit-start.json"} {
		raw, err := os.ReadFile(filepath.Join(originals, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cpuPostRequestCleanupProofAt(prior, out, prior.ScopeTarget); err != nil {
		t.Fatalf("preserved run23 cleanup shape refused: %v", err)
	}
}

func TestCPUPostRequestLiveCleanupRefusesReplacementAndLedger(t *testing.T) {
	_, _, _, proof := cpuPostRequestFixture(t)
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(proof.clusterUID)}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: podBoundTokenCPUNamespace,
		UID: types.UID(proof.namespaceUID), Labels: map[string]string{"phorvex.ai/cpu-token-fixture": "true"}}}
	kc := kubefake.NewSimpleClientset(cluster, namespace)
	gvrPolicy := schema.GroupVersionResource{Group: "phorvex.ai", Version: "v1alpha1", Resource: "phorvexpolicies"}
	gvrMonitor := schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}
	gvrAMTD := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "adaptivemovingtargetdefenses"}
	gvrEvent := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"}
	dc := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		gvrPolicy: "PhorvexPolicyList", gvrMonitor: "PodMonitorList", gvrAMTD: "AdaptiveMovingTargetDefenseList", gvrEvent: "SecurityEventList"})
	sum := sha256.Sum256([]byte(proof.namespaceUID))
	ledgerName := fmt.Sprintf("phorvex-quarantine-capacity-%x", sum[:20])
	check := func() error {
		return podBoundCPUCleanupLiveAbsence(context.Background(), kc, dc, proof, "phorvex-system", ledgerName)
	}
	if err := check(); err != nil {
		t.Fatalf("clean predecessor refused: %v", err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: proof.sourcePodName, Namespace: podBoundTokenCPUNamespace, UID: "replacement-uid"}}
	if _, err := kc.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("new incarnation at old source name admitted")
	}
	if err := kc.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
		Name:      "phorvex-quarantine-" + podBoundHash([]byte(proof.sourcePodUID)),
		Namespace: podBoundTokenCPUNamespace, UID: "policy-uid"}}
	if _, err := kc.NetworkingV1().NetworkPolicies(policy.Namespace).Create(context.Background(), policy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("old source NetworkPolicy admitted")
	}
	if err := kc.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.Background(), policy.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	renamedPolicy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
		Name: "renamed-neutral-policy", Namespace: podBoundTokenCPUNamespace, UID: "renamed-policy-uid",
		OwnerReferences: []metav1.OwnerReference{{UID: types.UID(proof.amtdUID), Kind: "AdaptiveMovingTargetDefense"}}}}
	if _, err := kc.NetworkingV1().NetworkPolicies(renamedPolicy.Namespace).Create(context.Background(), renamedPolicy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("renamed NetworkPolicy owned by old AMTD admitted")
	}
	if err := kc.NetworkingV1().NetworkPolicies(renamedPolicy.Namespace).Delete(context.Background(), renamedPolicy.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	amtd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "AdaptiveMovingTargetDefense",
		"metadata": map[string]any{"name": "renamed-amtd", "namespace": podBoundTokenCPUNamespace,
			"annotations": map[string]any{"phorvex.ai/policy-uid": proof.created["phorvexpolicies"]}},
	}}
	if _, err := dc.Resource(gvrAMTD).Namespace(podBoundTokenCPUNamespace).Create(context.Background(), amtd, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("renamed AMTD bound to old policy UID admitted")
	}
	if err := dc.Resource(gvrAMTD).Namespace(podBoundTokenCPUNamespace).Delete(context.Background(), "renamed-amtd", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ledger := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ledgerName, Namespace: "phorvex-system", UID: "ledger-uid", Labels: map[string]string{"phorvex.ai/quarantine-capacity": "v1"}}, Data: map[string]string{"ledger": fmt.Sprintf(`{"version":1,"namespace":%q,"namespaceUID":%q,"records":{%q:{"podUID":%q,"namespaceUID":%q}}}`, podBoundTokenCPUNamespace, proof.namespaceUID, proof.sourcePodUID, proof.sourcePodUID, proof.namespaceUID)}}
	if _, err := kc.CoreV1().ConfigMaps("phorvex-system").Create(context.Background(), ledger, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("protected reservation admitted")
	}
	if err := kc.CoreV1().ConfigMaps("phorvex-system").Delete(context.Background(), ledgerName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	changed := namespace.DeepCopy()
	changed.UID = "other-uid"
	if _, err := kc.CoreV1().Namespaces().Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("changed namespace admitted")
	}
	changed.UID = types.UID(proof.namespaceUID)
	if _, err := kc.CoreV1().Namespaces().Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	kc.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "next"}}, nil
	})
	if err := check(); err == nil {
		t.Fatal("truncated Pod inventory admitted")
	}
}
