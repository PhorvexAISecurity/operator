package actuator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m068VLLMCallSpy struct {
	*mockVLLM
	readyCalls int
}

func (s *m068VLLMCallSpy) ModelReady(ctx context.Context, endpoint servingEndpoint) (bool, error) {
	s.readyCalls++
	return s.mockVLLM.ModelReady(ctx, endpoint)
}

type m068GroupTransitionReader struct {
	client.Reader
	target client.ObjectKey
	gets   int
}

func (r *m068GroupTransitionReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if key != r.target {
		return nil
	}
	r.gets++
	if r.gets >= 2 {
		object.(*corev1.Pod).Labels[labelParallelGroup] = "parallel-added"
	}
	return nil
}

func TestM068NativeSupportsActionRefusesParallelGroupAndRetainsScalar(t *testing.T) {
	native := NewNativeActuator(nil)
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	target := Target{Namespace: "ns", Pod: "leader", Labels: map[string]string{
		labelModelShard: "shard-a", labelParallelGroup: "parallel-a",
	}}
	if ok, why := native.SupportsAction(t.Context(), model.ActionModelShardReplace, target); ok || why != ReasonParallelGroupUnavailable {
		t.Fatalf("grouped native support = (%v, %q), want stable unsupported reason", ok, why)
	}
	delete(target.Labels, labelParallelGroup)
	if ok, why := native.SupportsAction(t.Context(), model.ActionModelShardReplace, target); !ok || why != "" {
		t.Fatalf("scalar native support = (%v, %q)", ok, why)
	}
}

func TestM068ScalarRechecksAuthoritativeGroupBeforeServingOrEffects(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelModelShard: "shard-a", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelModelShard: "shard-a", labelRole: roleShadow, labelModelLoaded: "true"})
	writerSpy := &m087Spy{}
	writer := m087Client(writerSpy, leader, shadow)
	reader := &m068GroupTransitionReader{Reader: m087Client(&m087Spy{}, leader, shadow), target: client.ObjectKeyFromObject(leader)}
	stack := &m068VLLMCallSpy{mockVLLM: &mockVLLM{loaded: true}}

	result, err := modelShardReplaceHandler{}.Enact(t.Context(), EnactCtx{
		Client: writer,
		Reader: reader,
		VLLM:   stack,
	}, boundReq(leader, model.ActionModelShardReplace))
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, ReasonParallelGroupUnavailable) {
		t.Fatalf("read-to-read group transition = %+v, %v", result, err)
	}
	if reader.gets != 2 {
		t.Fatalf("fixture did not exercise both authoritative target reads: %d", reader.gets)
	}
	if writerSpy.writes != 0 || stack.readyCalls != 0 || stack.drainCalls != 0 {
		t.Fatalf("group transition crossed an effect boundary: writes=%d ready=%d drain=%d", writerSpy.writes, stack.readyCalls, stack.drainCalls)
	}
}

func TestM068RegisteredDispatchRefusesParallelGroupsBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		objects []client.Object
	}{
		{name: "invalid-size", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 0),
		}},
		{name: "incomplete", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 2),
			tpPod("ns", "shadow-0", "parallel-a", "0", roleShadow, true, 2),
		}},
		{name: "duplicate", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 2),
			tpPod("ns", "shadow-0a", "parallel-a", "0", roleShadow, true, 2),
			tpPod("ns", "shadow-0b", "parallel-a", "0", roleShadow, true, 2),
		}},
		{name: "complete", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 2),
			tpPod("ns", "leader-1", "parallel-a", "1", roleLeader, true, 2),
			tpPod("ns", "shadow-0", "parallel-a", "0", roleShadow, true, 2),
			tpPod("ns", "shadow-1", "parallel-a", "1", roleShadow, true, 2),
		}},
		{name: "extra", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 2),
			tpPod("ns", "shadow-0", "parallel-a", "0", roleShadow, true, 2),
			tpPod("ns", "shadow-1", "parallel-a", "1", roleShadow, true, 2),
			tpPod("ns", "shadow-2", "parallel-a", "2", roleShadow, true, 2),
		}},
		{name: "foreign-group", objects: []client.Object{
			tpPod("ns", "leader-0", "parallel-a", "0", roleLeader, true, 2),
			tpPod("ns", "shadow-0", "parallel-b", "0", roleShadow, true, 2),
			tpPod("ns", "shadow-1", "parallel-b", "1", roleShadow, true, 2),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &m087Spy{}
			writer := m087Client(spy, tc.objects...)
			stack := &mockVLLM{loaded: true}
			request := boundReq(tc.objects[0].(*corev1.Pod), model.ActionModelShardReplace)

			result, err := dispatch(t.Context(), EnactCtx{Client: writer, Reader: writer, VLLM: stack}, request)
			if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || result.Handler != string(model.ActionModelShardReplace) || !strings.Contains(result.Note, ReasonParallelGroupUnavailable) {
				t.Fatalf("grouped dispatch = %+v, %v", result, err)
			}
			if spy.writes != 0 {
				t.Fatalf("grouped dispatch crossed Kubernetes write boundary: %d", spy.writes)
			}
			if stack.drainCalls != 0 {
				t.Fatalf("grouped dispatch crossed serving seam: drain calls=%d", stack.drainCalls)
			}
			for _, object := range tc.objects {
				want := object.(*corev1.Pod)
				got := &corev1.Pod{}
				if err := writer.Get(t.Context(), client.ObjectKeyFromObject(want), got); err != nil {
					t.Fatalf("group member %s missing after refusal: %v", want.Name, err)
				}
				if got.UID != want.UID || got.Labels[labelRole] != want.Labels[labelRole] {
					t.Fatalf("group member %s changed after refusal: uid=%s role=%q", want.Name, got.UID, got.Labels[labelRole])
				}
			}
		})
	}
}

func TestM068RegisteredNativeUsesAuthoritativeGroupAndHasNoEffect(t *testing.T) {
	var httpCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		httpCalls.Add(1)
	}))
	t.Cleanup(server.Close)
	_, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}

	current := aiPod("ns", "leader", map[string]string{
		"app": "infer", labelModelShard: "shard-a", labelParallelGroup: "parallel-a", labelRole: roleLeader,
	})
	current.Status.PodIP = "127.0.0.1"
	current.Annotations[annoServingPort] = strconv.Itoa(port)
	stale := current.DeepCopy()
	delete(stale.Labels, labelParallelGroup)
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", ResourceVersion: "1"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode:     v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "infer"}},
			Actions:  v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionModelShardReplace)}},
		},
	}
	namespaces := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", UID: "ns-uid", ResourceVersion: "1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid", ResourceVersion: "1"}},
	}
	writerSpy, readerSpy := &m087Spy{}, &m087Spy{}
	writerObjects := append([]client.Object{stale, policy.DeepCopy()}, namespaces...)
	readerObjects := append([]client.Object{current, policy.DeepCopy()}, namespaces...)
	writer := m087Client(writerSpy, writerObjects...)
	reader := m087Client(readerSpy, readerObjects...)
	native := NewNativeActuator(writer)
	native.SetBoundaryReader(reader)
	native.JournalNamespace = "operator"
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	if err := native.EnsurePolicy(t.Context(), TenantTarget{Tenant: "tenant-a", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid"}); err != nil {
		t.Fatal(err)
	}
	req := boundReq(current, model.ActionModelShardReplace)
	req.Tenant = "tenant-a"

	result, err := native.Actuate(t.Context(), req)
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || result.Handler != string(model.ActionModelShardReplace) || !strings.Contains(result.Note, ReasonParallelGroupUnavailable) {
		t.Fatalf("registered grouped refusal = %+v, %v", result, err)
	}
	if readerSpy.reads == 0 {
		t.Fatal("fixture did not reach authoritative serving/target reads")
	}
	if writerSpy.writes != 0 {
		t.Fatalf("grouped refusal crossed Kubernetes write boundary: %d", writerSpy.writes)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("grouped refusal crossed serving HTTP boundary: %d", got)
	}
	got := &corev1.Pod{}
	if err := reader.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "leader"}, got); err != nil || got.UID != current.UID || got.Labels[labelRole] != roleLeader || got.Labels[labelParallelGroup] != "parallel-a" {
		t.Fatalf("authoritative target changed: pod=%+v err=%v", got, err)
	}
	if err := writer.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "leader"}, got); err != nil || got.Labels[labelParallelGroup] != "" {
		t.Fatalf("stale writer fixture changed or unexpectedly carried group: pod=%+v err=%v", got, err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "same-name-replacement", mutate: func(r *Request) { r.TargetUID = "replacement-uid" }},
		{name: "foreign-policy", mutate: func(r *Request) { r.PolicyUID = "foreign-policy-uid" }},
		{name: "foreign-namespace", mutate: func(r *Request) { r.Namespace = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writerSpy.reset()
			readerSpy.reset()
			httpCalls.Store(0)
			attempt := req
			tc.mutate(&attempt)
			result, err := native.Actuate(t.Context(), attempt)
			if err == nil || result.Emitted {
				t.Fatalf("authority violation reached success: result=%+v err=%v", result, err)
			}
			if writerSpy.writes != 0 || httpCalls.Load() != 0 {
				t.Fatalf("authority violation crossed an effect boundary: writes=%d HTTP=%d", writerSpy.writes, httpCalls.Load())
			}
		})
	}
}

func TestM068GroupedHandlerRetainsIdentityAndAuthorityGuards(t *testing.T) {
	grouped := aiPod("ns", "leader", map[string]string{
		labelModelShard: "shard-a", labelParallelGroup: "parallel-a", labelRole: roleLeader,
	})
	reader := fakeC(grouped)
	stack := &mockVLLM{loaded: true}
	ec := EnactCtx{Client: reader, Reader: reader, JournalNamespace: "operator", VLLM: stack}

	stale := boundReq(grouped, model.ActionModelShardReplace)
	stale.TargetUID = "same-name-replacement-uid"
	result, err := modelShardReplaceHandler{}.Enact(t.Context(), ec, stale)
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, reasonTargetUIDMismatch) {
		t.Fatalf("same-name replacement guard = %+v, %v", result, err)
	}
	if stack.drainCalls != 0 {
		t.Fatalf("identity refusal reached serving seam: %+v", stack)
	}

	missingReader := ec
	missingReader.Reader = nil
	result, err = modelShardReplaceHandler{}.Enact(t.Context(), missingReader, boundReq(grouped, model.ActionModelShardReplace))
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, "authoritative reader") {
		t.Fatalf("missing-reader guard = %+v, %v", result, err)
	}
}
