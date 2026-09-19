package actuator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type m078Readiness struct {
	mockVLLM
	calls   []string
	readyAt int
	cancel  context.CancelFunc
}

func (s *m078Readiness) ModelReady(ctx context.Context, ep servingEndpoint) (bool, error) {
	s.calls = append(s.calls, ep.podIP)
	if s.cancel != nil {
		s.cancel()
		return false, ctx.Err()
	}
	return s.readyAt > 0 && len(s.calls) == s.readyAt, nil
}

type m078InventoryReader struct {
	items         []corev1.Pod
	continueToken string
	listErr       error
	calls         int
}

func (r *m078InventoryReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("unexpected candidate Get")
}

func (r *m078InventoryReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.calls++
	if r.listErr != nil {
		return r.listErr
	}
	lo := &client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(lo)
	}
	if lo.Namespace != "ns" || lo.Limit != warmPoolMaxMembers+1 || lo.LabelSelector.String() != labelRole+"="+roleShadow+","+labelSwapGroup+"=group" {
		return fmt.Errorf("candidate inventory was not authoritative and bounded: namespace=%q limit=%d selector=%q", lo.Namespace, lo.Limit, lo.LabelSelector.String())
	}
	pods, ok := list.(*corev1.PodList)
	if !ok {
		return fmt.Errorf("unexpected list type %T", list)
	}
	pods.Items = make([]corev1.Pod, len(r.items))
	for i := range r.items {
		r.items[i].DeepCopyInto(&pods.Items[i])
	}
	pods.Continue = r.continueToken
	return nil
}

func m078Candidate(name, uid, ip string, created int64) corev1.Pod {
	p := aiPod("ns", name, map[string]string{labelSwapGroup: "group", labelRole: roleShadow, labelModelLoaded: "true"})
	p.UID = types.UID(uid)
	p.Status.PodIP = ip
	p.CreationTimestamp = metav1.NewTime(time.Unix(created, 0))
	return *p
}

func m078Pick(ctx context.Context, reader client.Reader, stack vLLMClient) (*corev1.Pod, bool, error) {
	return pickReadyShadow(ctx, EnactCtx{Reader: reader, VLLM: stack, ServingRequest: Request{Namespace: "ns", Action: model.ActionWarmSwap}}, "ns", client.MatchingLabels{labelSwapGroup: "group", labelRole: roleShadow}, "leader")
}

func TestM078WarmCandidatesUseStableOldestFirstOrder(t *testing.T) {
	oldest := m078Candidate("z-oldest", "uid-z", "10.0.0.10", 100)
	tieB := m078Candidate("b-tie", "uid-b", "10.0.0.12", 200)
	tieA := m078Candidate("a-tie", "uid-a", "10.0.0.11", 200)
	reader := &m078InventoryReader{items: []corev1.Pod{tieB, tieA, oldest}}
	stack := &m078Readiness{readyAt: 1}

	picked, pending, err := m078Pick(t.Context(), reader, stack)
	if err != nil || pending || picked == nil || picked.UID != oldest.UID {
		t.Fatalf("oldest candidate selection: picked=%v pending=%t err=%v", picked, pending, err)
	}
	if len(stack.calls) != 1 || stack.calls[0] != oldest.Status.PodIP {
		t.Fatalf("readiness order=%v, want first=%s", stack.calls, oldest.Status.PodIP)
	}
}

func TestM078WarmCandidateComparatorHasTotalTieBreakers(t *testing.T) {
	timestamp := metav1.NewTime(time.Unix(100, 0))
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: timestamp, Namespace: "b", Name: "a", UID: "1"}},
		{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: timestamp, Namespace: "a", Name: "b", UID: "1"}},
		{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: timestamp, Namespace: "a", Name: "a", UID: "2"}},
		{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: timestamp, Namespace: "a", Name: "a", UID: "1"}},
	}
	sort.Slice(pods, func(i, j int) bool { return warmCandidateLess(&pods[i], &pods[j]) })
	got := make([]string, 0, len(pods))
	for i := range pods {
		got = append(got, pods[i].Namespace+"/"+pods[i].Name+"/"+string(pods[i].UID))
	}
	want := []string{"a/a/1", "a/a/2", "a/b/1", "b/a/1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("total candidate order=%v want=%v", got, want)
	}
}

func TestM078WarmCandidateBudgetRefusesBeforeFifthAndMutatesNothing(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "group", labelRole: roleLeader})
	objects := []client.Object{leader}
	for i := 0; i < warmCandidateAttemptLimit+1; i++ {
		p := aiPod("ns", fmt.Sprintf("shadow-%d", i), map[string]string{labelSwapGroup: "group", labelRole: roleShadow, labelModelLoaded: "true"})
		p.CreationTimestamp = metav1.NewTime(time.Unix(int64(100+i), 0))
		p.Status.PodIP = fmt.Sprintf("10.0.0.%d", i+10)
		objects = append(objects, p)
	}
	c := fakeC(objects...)
	stack := &m078Readiness{readyAt: warmCandidateAttemptLimit + 1}
	_, err := warmSwapHandler{}.Enact(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: stack}, boundReq(leader, model.ActionWarmSwap))
	if !errors.Is(err, errWarmCandidateAttemptBudget) || len(stack.calls) != warmCandidateAttemptLimit {
		t.Fatalf("bounded traversal: calls=%d err=%v", len(stack.calls), err)
	}
	for _, obj := range objects {
		before := obj.(*corev1.Pod)
		var after corev1.Pod
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(before), &after); err != nil {
			t.Fatalf("candidate disappeared before mutation authority: %s: %v", before.Name, err)
		}
		if after.Labels[labelRole] != before.Labels[labelRole] {
			t.Fatalf("candidate role mutated under exhausted traversal: %s role=%q", after.Name, after.Labels[labelRole])
		}
	}
}

func TestM078FourCompletedNotReadyCandidatesRemainNoReady(t *testing.T) {
	items := make([]corev1.Pod, warmCandidateAttemptLimit)
	for i := range items {
		items[i] = m078Candidate(fmt.Sprintf("shadow-%d", i), fmt.Sprintf("uid-%d", i), fmt.Sprintf("10.0.0.%d", i+10), int64(100+i))
	}
	stack := &m078Readiness{}
	picked, pending, err := m078Pick(t.Context(), &m078InventoryReader{items: items}, stack)
	if err != nil || picked != nil || pending || len(stack.calls) != warmCandidateAttemptLimit {
		t.Fatalf("completed no-ready traversal: picked=%v pending=%t calls=%d err=%v", picked, pending, len(stack.calls), err)
	}
}

func TestM078IncompleteInventoryRefusesBeforeServingProbe(t *testing.T) {
	valid := m078Candidate("shadow", "uid-shadow", "10.0.0.10", 100)
	tests := []struct {
		name   string
		reader *m078InventoryReader
	}{
		{name: "pagination", reader: &m078InventoryReader{items: []corev1.Pod{valid}, continueToken: "next"}},
		{name: "overflow", reader: &m078InventoryReader{items: func() []corev1.Pod {
			items := make([]corev1.Pod, warmPoolMaxMembers+1)
			for i := range items {
				items[i] = m078Candidate(fmt.Sprintf("shadow-%03d", i), fmt.Sprintf("uid-%03d", i), fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), int64(100+i))
			}
			return items
		}()}},
		{name: "identity", reader: &m078InventoryReader{items: []corev1.Pod{func() corev1.Pod { p := valid.DeepCopy(); p.UID = ""; return *p }()}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stack := &m078Readiness{readyAt: 1}
			if picked, _, err := m078Pick(t.Context(), tc.reader, stack); err == nil || picked != nil || len(stack.calls) != 0 {
				t.Fatalf("incomplete inventory reached serving probe: picked=%v calls=%d err=%v", picked, len(stack.calls), err)
			}
		})
	}
}

func TestM078CancellationBeforeAndDuringCandidateProbe(t *testing.T) {
	item := m078Candidate("shadow", "uid-shadow", "10.0.0.10", 100)
	t.Run("before inventory", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		reader := &m078InventoryReader{items: []corev1.Pod{item}}
		if _, _, err := m078Pick(ctx, reader, &m078Readiness{readyAt: 1}); !errors.Is(err, context.Canceled) || reader.calls != 0 {
			t.Fatalf("pre-cancel outcome: lists=%d err=%v", reader.calls, err)
		}
	})
	t.Run("during first attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		stack := &m078Readiness{cancel: cancel}
		if picked, _, err := m078Pick(ctx, &m078InventoryReader{items: []corev1.Pod{item}}, stack); !errors.Is(err, context.Canceled) || picked != nil || len(stack.calls) != 1 {
			t.Fatalf("mid-probe cancellation: picked=%v calls=%d err=%v", picked, len(stack.calls), err)
		}
	})
}

func TestM078OldestForeignServiceAccountStopsBeforeCredentialUse(t *testing.T) {
	oldest := m078Candidate("a-oldest", "uid-oldest", "10.0.0.10", 100)
	younger := m078Candidate("z-younger", "uid-younger", "10.0.0.11", 200)
	oldest.Spec.ServiceAccountName = "foreign"
	younger.Spec.ServiceAccountName = "allowed"
	for _, pod := range []*corev1.Pod{&oldest, &younger} {
		pod.Annotations["phorvex.ai/model-id"] = "model"
	}
	c := fakeC(&oldest, &younger)
	req := Request{Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", Action: model.ActionWarmSwap}
	stack := &m078Readiness{readyAt: 1}
	ec := EnactCtx{
		Reader:          c,
		VLLM:            stack,
		ServingSecurity: &ServingSecurityConfig{mode: ServingSecuritySecureRequired},
		ServingAttempt: &servingCredentialSnapshot{
			binding:         ServingSecurityBinding{ServiceAccount: "allowed"},
			token:           "must-not-be-sent",
			policyNamespace: req.Namespace,
			policyName:      req.PolicyName,
			policyUID:       req.PolicyUID,
			selector:        labels.SelectorFromSet(map[string]string{labelSwapGroup: "group", labelRole: roleShadow}),
			action:          req.Action,
		},
		ServingRequest: req,
	}
	picked, _, err := pickReadyShadow(t.Context(), ec, "ns", client.MatchingLabels{labelSwapGroup: "group", labelRole: roleShadow}, "leader")
	if err == nil || !strings.Contains(err.Error(), "ServiceAccount") || picked != nil || len(stack.calls) != 0 {
		t.Fatalf("foreign oldest authority: picked=%v calls=%d err=%v", picked, len(stack.calls), err)
	}
}

type m078CancelAfterHealthTransport struct {
	cancel context.CancelFunc
	calls  int
}

func (t *m078CancelAfterHealthTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	t.cancel()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
}

func TestM078HTTPReadinessChecksCancellationBeforeSecondLeg(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	transport := &m078CancelAfterHealthTransport{cancel: cancel}
	ready, err := (&httpVLLM{hc: &http.Client{Transport: transport}}).ModelReady(ctx, servingEndpoint{podIP: "127.0.0.1", port: 8000})
	if ready || !errors.Is(err, context.Canceled) || transport.calls != 1 {
		t.Fatalf("second readiness leg ran after cancellation: ready=%t calls=%d err=%v", ready, transport.calls, err)
	}
}
