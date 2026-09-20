package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/podresources"
)

// m070ProofMIG supplies allocation and inventory evidence at the existing MIG seam. Tests
// still enter through dispatch and its registered mig-rebind handler; this fixture does not
// replace the handler, receipt store, Kubernetes writes, or identity checks under proof.
type m070ProofMIG struct {
	mu            sync.Mutex
	gpuByTarget   map[string]string
	prepares      int
	binds         int
	captures      int
	revalidations int
	repartitions  int
}

type m070PreparedMIG struct {
	owner *m070ProofMIG
}

type m070MIGCounts struct {
	prepares, binds, captures, revalidations, repartitions int
}

func (m *m070ProofMIG) Prepare(_ context.Context, _ string) (preparedMIG, error) {
	m.mu.Lock()
	m.prepares++
	m.mu.Unlock()
	return &m070PreparedMIG{owner: m}, nil
}

func (m *m070ProofMIG) counts() m070MIGCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m070MIGCounts{m.prepares, m.binds, m.captures, m.revalidations, m.repartitions}
}

func (m *m070PreparedMIG) BindAllocation(_ context.Context, target migAllocationTarget, rule MIGProfileRule) (migAllocationBinding, error) {
	m.owner.mu.Lock()
	defer m.owner.mu.Unlock()
	m.owner.binds++
	gpu := m.owner.gpuByTarget[target.Namespace+"/"+target.Pod]
	if gpu == "" {
		gpu = testGPUUUID
	}
	return migAllocationBinding{
		Version:         1,
		Namespace:       target.Namespace,
		Pod:             target.Pod,
		PodUID:          target.UID,
		Node:            target.Node,
		Container:       "vllm",
		Resource:        target.Resource,
		DeviceID:        "MIG-" + strings.TrimPrefix(gpu, "GPU-"),
		GPUUUID:         gpu,
		ProfileRule:     rule.Namespace + "/" + rule.Resource,
		TargetProfile:   rule.Profile,
		SnapshotVersion: podresources.Version,
		SnapshotDigest:  strings.Repeat("a", 64),
	}, nil
}

func (m *m070PreparedMIG) RevalidateAllocation(_ context.Context, _ migAllocationBinding, _ bool) error {
	m.owner.mu.Lock()
	m.owner.revalidations++
	m.owner.mu.Unlock()
	return nil
}

func (m *m070PreparedMIG) allocationReleaseTimeout() time.Duration { return 10 * time.Millisecond }

func (m *m070PreparedMIG) Capture(_ context.Context, gpu, _ string) (migGeometry, error) {
	m.owner.mu.Lock()
	m.owner.captures++
	m.owner.mu.Unlock()
	prior := migTestPrior()
	prior.GPUUUID = gpu
	return prior, nil
}

func (m *m070PreparedMIG) Repartition(ctx context.Context, prior migGeometry, _ string, stillOwned func(context.Context) error) (migEffect, error) {
	m.owner.mu.Lock()
	m.owner.repartitions++
	m.owner.mu.Unlock()
	if err := stillOwned(ctx); err != nil {
		return migEffect{Outcome: "no-destructive-effect", OriginalErr: err}, err
	}
	return migEffect{Outcome: "new-geometry-verified", Current: prior}, nil
}

type m070Effects struct {
	mu             sync.Mutex
	ackLostOnRoute bool
	podUpdates     int
	receiptCreates int
}

func (e *m070Effects) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Labels[migRecoveryLabel] == "v2" {
				e.mu.Lock()
				e.receiptCreates++
				e.mu.Unlock()
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			pod, isPod := obj.(*corev1.Pod)
			if !isPod || pod.Labels[labelRole] != roleRetiring {
				return c.Update(ctx, obj, opts...)
			}
			err := c.Update(ctx, obj, opts...)
			e.mu.Lock()
			e.podUpdates++
			ackLost := e.ackLostOnRoute
			e.mu.Unlock()
			if err == nil && ackLost {
				return errors.New("injected route update acknowledgement loss")
			}
			return err
		},
	}
}

func (e *m070Effects) counts() (podUpdates, receiptCreates int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.podUpdates, e.receiptCreates
}

func m070ServingPod(pod *corev1.Pod) *corev1.Pod {
	pod.Annotations["phorvex.ai/model-id"] = "m070-model"
	pod.Annotations[annoServingPort] = "8000"
	return pod
}

func m070Dispatch(ctx context.Context, c client.Client, reader client.Reader, security *ServingSecurityConfig, mig migController, vllm *mockVLLM, req Request) (Result, error) {
	return dispatch(ctx, EnactCtx{
		Client: c, Reader: reader, JournalNamespace: "operator",
		MIG: mig, VLLM: vllm, MIGProfiles: testMIGProfilesFor(req.Namespace), ServingSecurity: security,
	}, req)
}

// A retry selected against UID A cannot operate on a same-name UID B even when the manager's
// cached writer still returns A. Production serving-security preparation reads B through the
// direct authority before dispatching the registered handler. The current UID B positive then
// traverses that handler and completes, proving the negative does not disable MIG rebind.
func TestM070RegisteredMIGRefusesStaleUIDBeforeEffectsAndRetainsCurrentPositive(t *testing.T) {
	original := m070ServingPod(migPod("ns", "infer"))
	original.UID = types.UID("uid-original-a")
	successor := original.DeepCopy()
	successor.UID = types.UID("uid-successor-b")
	successor.ResourceVersion = "8"
	staleEffects := &m070Effects{}
	staleDeletes := &m069Delete{}
	staleWriter := m069Client(staleDeletes, staleEffects.funcs(), original)
	directReader := fakeC(successor)
	mig := &m070ProofMIG{}
	vllm := &mockVLLM{}
	security := legacyServingSecurityForTest(t)

	stale := boundReq(original, model.ActionMIGRebind)
	result, err := m070Dispatch(t.Context(), staleWriter, directReader, security, mig, vllm, stale)
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || !strings.Contains(err.Error(), "serving security target identity changed") {
		t.Fatalf("stale registered request result=%+v err=%v", result, err)
	}
	if got := mig.counts(); got != (m070MIGCounts{}) {
		t.Fatalf("stale identity reached helper/inventory/GPU seam: %+v", got)
	}
	if updates, creates := staleEffects.counts(); updates != 0 || creates != 0 || len(staleDeletes.opts) != 0 || vllm.drainCalls != 0 {
		t.Fatalf("stale identity crossed effect boundary: updates=%d receipts=%d deletes=%v drains=%d", updates, creates, staleDeletes.opts, vllm.drainCalls)
	}
	live, ok := m069Get(t, directReader, successor.Namespace, successor.Name)
	if !ok || live.UID != successor.UID || live.Labels[labelRole] != roleLeader {
		t.Fatalf("same-name successor changed: present=%v pod=%+v", ok, live)
	}

	currentEffects := &m070Effects{}
	currentDeletes := &m069Delete{}
	currentClient := m069Client(currentDeletes, currentEffects.funcs(), successor)
	current := boundReq(successor, model.ActionMIGRebind)
	result, err = m070Dispatch(t.Context(), currentClient, currentClient, security, mig, vllm, current)
	if err != nil || !result.Emitted || result.MutationKind != "swap" || result.Handler != string(model.ActionMIGRebind) {
		t.Fatalf("current registered request result=%+v err=%v", result, err)
	}
	if got := mig.counts(); got.repartitions != 1 {
		t.Fatalf("current UID positive did not reach one scripted repartition: %+v", got)
	}
	if updates, creates := currentEffects.counts(); updates != 1 || creates != 1 || len(currentDeletes.opts[successor.Name]) != 1 || vllm.drainCalls != 1 {
		t.Fatalf("current UID positive effects: updates=%d receipts=%d deletes=%v drains=%d", updates, creates, currentDeletes.opts, vllm.drainCalls)
	}
}

// A route Update may persist and still return an error. The first call must report that
// confirmed partial effect and retain the physical-GPU receipt. Exact and different-target
// retries for the same GPU may repeat supporting reads, but cannot cross a second tenant or
// destructive effect boundary.
func TestM070RegisteredMIGAckLostRouteRetainsReceiptAndBlocksSameGPU(t *testing.T) {
	first := m070ServingPod(migPod("ns", "infer-a"))
	second := m070ServingPod(migPod("ns", "infer-b"))
	effects := &m070Effects{ackLostOnRoute: true}
	deletes := &m069Delete{}
	c := m069Client(deletes, effects.funcs(), first, second)
	mig := &m070ProofMIG{gpuByTarget: map[string]string{"ns/infer-a": testGPUUUID, "ns/infer-b": testGPUUUID}}
	vllm := &mockVLLM{}
	security := legacyServingSecurityForTest(t)
	req := boundReq(first, model.ActionMIGRebind)

	result, err := m070Dispatch(t.Context(), c, c, security, mig, vllm, req)
	if err == nil || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "route-removal update uncertain") {
		t.Fatalf("ack-lost route result=%+v err=%v", result, err)
	}
	receipt := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "operator", Name: migRecoveryName(first.Spec.NodeName, testGPUUUID)}
	if err := c.Get(t.Context(), key, receipt); err != nil {
		t.Fatalf("retained physical-GPU receipt: %v", err)
	}
	beforeUID, beforeRV, beforeBytes := receipt.UID, receipt.ResourceVersion, receipt.Data["receipt"]
	var recorded migRecoveryReceipt
	if err := json.Unmarshal([]byte(beforeBytes), &recorded); err != nil || recorded.GPUUUID != testGPUUUID || recorded.TargetUID != string(first.UID) || recorded.Phase != "prepared" {
		t.Fatalf("retained receipt=%+v decode=%v", recorded, err)
	}
	readsAfterFirst := mig.counts()
	if updates, creates := effects.counts(); updates != 1 || creates != 1 || len(deletes.opts) != 0 || vllm.drainCalls != 0 || readsAfterFirst.repartitions != 0 {
		t.Fatalf("first partial boundaries: updates=%d receipts=%d deletes=%v drains=%d mig=%+v", updates, creates, deletes.opts, vllm.drainCalls, readsAfterFirst)
	}

	for name, retry := range map[string]Request{
		"exact-request":            req,
		"distinct-target-same-gpu": boundReq(second, model.ActionMIGRebind),
	} {
		t.Run(name, func(t *testing.T) {
			blocked, retryErr := m070Dispatch(t.Context(), c, c, security, mig, vllm, retry)
			if retryErr == nil || blocked.Emitted || !strings.Contains(retryErr.Error(), "pending MIG operation already exists") {
				t.Fatalf("same-GPU retry result=%+v err=%v", blocked, retryErr)
			}
		})
	}
	after := &corev1.ConfigMap{}
	if err := c.Get(t.Context(), key, after); err != nil {
		t.Fatal(err)
	}
	if after.UID != beforeUID || after.ResourceVersion != beforeRV || after.Data["receipt"] != beforeBytes {
		t.Fatalf("winner receipt changed: uid=%s/%s rv=%s/%s bytesEqual=%v", beforeUID, after.UID, beforeRV, after.ResourceVersion, beforeBytes == after.Data["receipt"])
	}
	if updates, creates := effects.counts(); updates != 1 || creates != 1 || len(deletes.opts) != 0 || vllm.drainCalls != 0 {
		t.Fatalf("retry crossed effect boundary: updates=%d receipts=%d deletes=%v drains=%d", updates, creates, deletes.opts, vllm.drainCalls)
	}
	if got := mig.counts(); got.prepares <= readsAfterFirst.prepares || got.binds <= readsAfterFirst.binds || got.captures <= readsAfterFirst.captures || got.repartitions != 0 {
		t.Fatalf("supporting reads were not distinguished from destructive effects: first=%+v final=%+v", readsAfterFirst, got)
	}
}

type m070APIEffects struct {
	routeUpdates atomic.Int32
	podDeletes   atomic.Int32
}

func m070RunConcurrent(run func(int) (Result, error)) ([2]Result, [2]error) {
	var results [2]Result
	var errs [2]error
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range 2 {
		go func() {
			defer wg.Done()
			results[i], errs[i] = run(i)
		}()
	}
	wg.Wait()
	return results, errs
}

// The real API server is the receipt CAS authority. A barrier makes both same-GPU
// requests observe absence before Create; only one acknowledged Create may cross into the
// tenant route update. Different physical GPU names are the non-vacuous concurrent positive.
func TestM070RealAPIMIGReceiptCreateCASAndDistinctGPUPositive(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly, CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	apiClient, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if err := apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}); err != nil {
		t.Fatal(err)
	}
	ns := m069Namespace(t, apiClient, "m070-cas")

	const (
		gpuB = "GPU-bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
		gpuC = "GPU-cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"
	)
	names := []string{"same-a", "same-b", "distinct-b", "distinct-c"}
	gpus := []string{testGPUUUID, testGPUUUID, gpuB, gpuC}
	pods := make([]*corev1.Pod, len(names))
	requests := make([]Request, len(names))
	for i, name := range names {
		pod := m070ServingPod(migPod(ns, name))
		pod.Spec.NodeName = "node-cas"
		pod.Annotations[annoGPUID] = gpus[i]
		pods[i] = m069Create(t, apiClient, pod)
		requests[i] = m069Request(t, apiClient, pods[i], model.ActionMIGRebind)
	}

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var barrier atomic.Bool
	barrier.Store(true)
	effects := &m070APIEffects{}
	wrapped := interceptor.NewClient(apiClient, interceptor.Funcs{
		Create: func(callCtx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Labels[migRecoveryLabel] == "v2" && barrier.Load() {
				arrived <- struct{}{}
				<-release
			}
			return c.Create(callCtx, obj, opts...)
		},
		Update: func(callCtx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Labels[labelRole] != roleRetiring {
				return c.Update(callCtx, obj, opts...)
			}
			if err := c.Update(callCtx, obj, opts...); err != nil {
				return err
			}
			effects.routeUpdates.Add(1)
			return errors.New("injected route update acknowledgement loss")
		},
		Delete: func(callCtx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				effects.podDeletes.Add(1)
			}
			return c.Delete(callCtx, obj, opts...)
		},
	})
	mig := &m070ProofMIG{gpuByTarget: map[string]string{
		ns + "/same-a": testGPUUUID, ns + "/same-b": testGPUUUID,
		ns + "/distinct-b": gpuB, ns + "/distinct-c": gpuC,
	}}
	vllms := []*mockVLLM{{}, {}, {}, {}}
	security := legacyServingSecurityForTest(t)

	var sameResults [2]Result
	var sameErrs [2]error
	done := make(chan struct{})
	go func() {
		sameResults, sameErrs = m070RunConcurrent(func(i int) (Result, error) {
			return m070Dispatch(ctx, wrapped, wrapped, security, mig, vllms[i], requests[i])
		})
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			unblock()
			<-done
			t.Fatalf("same-GPU request %d did not reach receipt Create barrier", i)
		}
	}
	unblock()
	<-done

	winners := 0
	for i := range 2 {
		if sameResults[i].Emitted {
			winners++
			if sameResults[i].MutationKind != "partial" || sameErrs[i] == nil {
				t.Fatalf("same-GPU winner %d result=%+v err=%v", i, sameResults[i], sameErrs[i])
			}
		} else if sameErrs[i] == nil || !strings.Contains(sameErrs[i].Error(), "persist recovery intent") {
			t.Fatalf("same-GPU loser %d result=%+v err=%v", i, sameResults[i], sameErrs[i])
		}
	}
	if winners != 1 || effects.routeUpdates.Load() != 1 || effects.podDeletes.Load() != 0 {
		t.Fatalf("same-GPU CAS winners=%d routeUpdates=%d podDeletes=%d", winners, effects.routeUpdates.Load(), effects.podDeletes.Load())
	}
	var receipts corev1.ConfigMapList
	if err := apiClient.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{migRecoveryLabel: "v2"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("same-GPU receipt count=%d err=%v", len(receipts.Items), err)
	}
	winnerCM := receipts.Items[0].DeepCopy()
	var winnerReceipt migRecoveryReceipt
	if err := json.Unmarshal([]byte(winnerCM.Data["receipt"]), &winnerReceipt); err != nil || winnerReceipt.GPUUUID != testGPUUUID {
		t.Fatalf("winner receipt=%+v err=%v", winnerReceipt, err)
	}
	for i := range 2 {
		live := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(pods[i]), live); err != nil {
			t.Fatal(err)
		}
		want := roleLeader
		if pods[i].Name == winnerReceipt.TargetName {
			want = roleRetiring
		}
		if live.UID != pods[i].UID || live.Labels[labelRole] != want {
			t.Fatalf("same-GPU pod %s uid/role=%s/%s want=%s/%s", live.Name, live.UID, live.Labels[labelRole], pods[i].UID, want)
		}
	}
	unchanged := &corev1.ConfigMap{}
	if err := apiClient.Get(ctx, client.ObjectKeyFromObject(winnerCM), unchanged); err != nil || unchanged.UID != winnerCM.UID || unchanged.ResourceVersion != winnerCM.ResourceVersion || unchanged.Data["receipt"] != winnerCM.Data["receipt"] {
		t.Fatalf("loser removed or rewrote winner receipt: after=%+v err=%v", unchanged, err)
	}

	barrier.Store(false)
	distinctResults, distinctErrs := m070RunConcurrent(func(i int) (Result, error) {
		index := i + 2
		return m070Dispatch(ctx, wrapped, wrapped, security, mig, vllms[index], requests[index])
	})
	for i := range 2 {
		if distinctErrs[i] == nil || !distinctResults[i].Emitted || distinctResults[i].MutationKind != "partial" {
			t.Fatalf("distinct-GPU positive %d result=%+v err=%v", i, distinctResults[i], distinctErrs[i])
		}
	}
	if effects.routeUpdates.Load() != 3 || effects.podDeletes.Load() != 0 {
		t.Fatalf("distinct-GPU positives routeUpdates=%d podDeletes=%d", effects.routeUpdates.Load(), effects.podDeletes.Load())
	}
	receipts = corev1.ConfigMapList{}
	if err := apiClient.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{migRecoveryLabel: "v2"}); err != nil || len(receipts.Items) != 3 {
		t.Fatalf("distinct physical GPUs did not acquire independent receipts: count=%d err=%v", len(receipts.Items), err)
	}
	if got := mig.counts(); got.repartitions != 0 {
		t.Fatalf("ack-lost fixture crossed destructive GPU boundary: %+v", got)
	}
	for i, vllm := range vllms {
		if vllm.drainCalls != 0 {
			t.Fatalf("request %d crossed drain boundary: %d", i, vllm.drainCalls)
		}
	}

	t.Logf("same physical GPU admitted one route effect and retained winner %s/%s; distinct GPUs admitted two independent receipts", winnerReceipt.TargetName, winnerReceipt.TargetUID)
}

var _ migController = (*m070ProofMIG)(nil)
var _ preparedMIG = (*m070PreparedMIG)(nil)
var _ migAllocationAuthority = (*m070PreparedMIG)(nil)
