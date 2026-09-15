package actuator

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type t3FaultClient struct {
	client.Client
	updates     []string
	lists       int
	gets        []string
	updateFault func(client.Object) error
	listFault   func(int) error
	getFault    func(string) error
}

type t3DrainHook struct {
	*mockVLLM
	hook func()
}

func (m *t3DrainHook) DrainRequests(_ context.Context, _ servingEndpoint) (int, error) {
	if m.hook != nil {
		m.hook()
	}
	return 0, m.drainErr
}

func (c *t3FaultClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	name := obj.GetName()
	c.updates = append(c.updates, name)
	if c.updateFault != nil {
		if err := c.updateFault(obj); err != nil {
			return err
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}
func (c *t3FaultClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	c.lists++
	if c.listFault != nil {
		if err := c.listFault(c.lists); err != nil {
			return err
		}
	}
	return c.Client.List(ctx, list, opts...)
}
func (c *t3FaultClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.gets = append(c.gets, key.Name)
	if c.getFault != nil {
		if err := c.getFault(key.Name); err != nil {
			return err
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}
func t3Group() ([]client.Object, Request) {
	objs := []client.Object{tpPod("ns", "l0", "g", "0", roleLeader, true, 3), tpPod("ns", "l1", "g", "1", roleLeader, true, 3), tpPod("ns", "l2", "g", "2", roleLeader, true, 3), tpPod("ns", "s0", "g", "0", roleShadow, true, 3), tpPod("ns", "s1", "g", "1", roleShadow, true, 3), tpPod("ns", "s2", "g", "2", roleShadow, true, 3)}
	return objs, boundReq(objs[0].(*corev1.Pod), "model-shard-replace")
}
func t3Role(t *testing.T, c client.Client, name string) string {
	t.Helper()
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: name}, &p); err != nil {
		t.Fatal(err)
	}
	return p.Labels[labelRole]
}

func TestT3GroupFlipFailureAttemptsEveryReverseCompensation(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary, restore := errors.New("promote s2 refused"), errors.New("restore s1 refused")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Name == "s2" && p.Labels[labelRole] == roleLeader {
			return primary
		}
		if p.Name == "s1" && p.Labels[labelRole] == roleShadow {
			return restore
		}
		return nil
	}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, primary) || !errors.Is(err, restore) {
		t.Fatalf("must retain both failures: %v", err)
	}
	if hr.Emitted || len(hr.ObjectsTouched) != 2 {
		t.Fatalf("accepted writes require partial non-success: %+v", hr)
	}
	if got, want := c.updates, []string{"s0", "s1", "s2", "s1", "s0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v want %v", got, want)
	}
	if got := t3Role(t, base, "s0"); got != roleShadow {
		t.Fatalf("s0 %s", got)
	}
	if got := t3Role(t, base, "s1"); got != roleLeader {
		t.Fatalf("s1 %s", got)
	}
	if got := t3Role(t, base, "s2"); got != roleShadow {
		t.Fatalf("s2 %s", got)
	}
	if got := t3Role(t, base, "l0"); got != roleLeader {
		t.Fatalf("old leader retired on failed flip: %s", got)
	}
}

func TestT3GroupCompensationRefusesSameNameReplacement(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary := errors.New("promote s2 refused")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Name == "s2" && p.Labels[labelRole] == roleLeader {
			var old corev1.Pod
			if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "s1"}, &old); err != nil {
				t.Fatal(err)
			}
			if err := base.Delete(context.Background(), &old); err != nil {
				t.Fatal(err)
			}
			old.UID = types.UID("replacement-s1")
			old.ResourceVersion = ""
			old.Labels[labelRole] = roleLeader
			old.Annotations["concurrent"] = "preserve"
			if err := base.Create(context.Background(), &old); err != nil {
				t.Fatal(err)
			}
			return primary
		}
		return nil
	}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, primary) || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("replacement refusal: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "s1"}, &saved); getErr != nil {
		t.Fatal(getErr)
	}
	if saved.UID != types.UID("replacement-s1") || saved.Labels[labelRole] != roleLeader || saved.Annotations["concurrent"] != "preserve" {
		t.Fatalf("replacement overwritten: %+v", saved.ObjectMeta)
	}
	if got := t3Role(t, base, "s0"); got != roleShadow {
		t.Fatalf("independent compensation skipped s0: %s", got)
	}
}

func TestT3GroupFailedPromotionAppliedDespiteErrorIsReconciled(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary := errors.New("s2 acknowledgement lost")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Name == "s2" && p.Labels[labelRole] == roleLeader {
			if err := base.Update(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			return primary
		}
		return nil
	}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, primary) || hr.Emitted || len(hr.ObjectsTouched) != 3 {
		t.Fatalf("applied-error compensation: %+v %v", hr, err)
	}
	if got, want := c.updates, []string{"s0", "s1", "s2", "s2", "s1", "s0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v want %v", got, want)
	}
	for _, name := range []string{"s0", "s1", "s2"} {
		if role := t3Role(t, base, name); role != roleShadow {
			t.Fatalf("%s role %s", name, role)
		}
	}
}

func TestT3GroupFailedPromotionReadFailureReportsUnresolved(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary, readErr := errors.New("s2 promote refused"), errors.New("s2 reconciliation read refused")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Name == "s2" && p.Labels[labelRole] == roleLeader {
			return primary
		}
		return nil
	}
	c.getFault = func(name string) error {
		if name == "s2" {
			return readErr
		}
		return nil
	}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, primary) || !errors.Is(err, readErr) || hr.Emitted || len(hr.ObjectsTouched) != 3 || !containsStr(err.Error(), "unresolved") {
		t.Fatalf("unresolved: %+v %v", hr, err)
	}
	for _, name := range []string{"s0", "s1"} {
		if role := t3Role(t, base, name); role != roleShadow {
			t.Fatalf("%s role %s", name, role)
		}
	}
}

func TestT3GroupInventoryReadFailureRetainsPromotions(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary := errors.New("old group list refused")
	c := &t3FaultClient{Client: base, listFault: func(n int) error {
		if n == 2 {
			return primary
		}
		return nil
	}}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, primary) || hr.Emitted || len(hr.ObjectsTouched) != 3 {
		t.Fatalf("inventory partial: %+v %v", hr, err)
	}
	for _, name := range []string{"s0", "s1", "s2"} {
		if t3Role(t, base, name) != roleLeader {
			t.Fatalf("%s not promoted", name)
		}
	}
	for _, name := range []string{"l0", "l1", "l2"} {
		if t3Role(t, base, name) != roleLeader {
			t.Fatalf("%s touched despite inventory failure", name)
		}
	}
}

func TestT3GroupRetirementNeverClassifiesPromotedNameReplacementAsOld(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	c := &t3FaultClient{Client: base}
	c.listFault = func(n int) error {
		if n != 2 {
			return nil
		}
		var old corev1.Pod
		if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "s0"}, &old); err != nil {
			t.Fatal(err)
		}
		if err := base.Delete(context.Background(), &old); err != nil {
			t.Fatal(err)
		}
		old.UID = types.UID("replacement-s0")
		old.ResourceVersion = ""
		old.Labels[labelRole] = roleLeader
		old.Annotations["replacement"] = "preserve"
		if err := base.Create(context.Background(), &old); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, req, "g")
	if !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("promoted replacement drift: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "s0"}, &saved); getErr != nil {
		t.Fatalf("replacement deleted: %v", getErr)
	}
	if saved.UID != types.UID("replacement-s0") || saved.Labels[labelRole] != roleLeader || saved.Annotations["replacement"] != "preserve" {
		t.Fatalf("replacement mutated: %+v", saved.ObjectMeta)
	}
}

func TestT3GroupRelabelFailureDoesNotDrainOrDeleteThatLeader(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary := errors.New("l0 relabel refused")
	c := &t3FaultClient{Client: base, updateFault: func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Name == "l0" && p.Labels[labelRole] == roleRetiring {
			return primary
		}
		return nil
	}}
	mv := &mockVLLM{readyErr: errStackUnreachable}
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: mv}, req, "g")
	if !errors.Is(err, primary) || hr.Emitted {
		t.Fatalf("relabel failure: %+v %v", hr, err)
	}
	if got := t3Role(t, base, "l0"); got != roleLeader {
		t.Fatalf("l0 relabel failed but role %s", got)
	}
	var p corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "l0"}, &p); getErr != nil {
		t.Fatalf("l0 incorrectly retired: %v", getErr)
	}
	if mv.drainCalls != 2 {
		t.Fatalf("only verified relabeled leaders drain, calls=%d", mv.drainCalls)
	}
}

func TestT3GroupDrainFailureBlocksUnverifiedRetirement(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	primary := errors.New("reachable drain failed")
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: base, VLLM: &mockVLLM{readyErr: errStackUnreachable, drainErr: primary}}, req, "g")
	if !errors.Is(err, primary) || hr.Emitted {
		t.Fatalf("drain failure: %+v %v", hr, err)
	}
	for _, name := range []string{"l0", "l1", "l2"} {
		if got := t3Role(t, base, name); got != roleRetiring {
			t.Fatalf("%s role %s", name, got)
		}
	}
}

func TestT3GroupUnreachableDrainIsPendingAndNotConfirmed(t *testing.T) {
	objs, req := t3Group()
	base := fakeC(objs...)
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: base, VLLM: &mockVLLM{readyErr: errStackUnreachable, drainErr: errStackUnreachable}}, req, "g")
	if err == nil || hr.Emitted || !containsStr(err.Error(), "PENDING-GPU-VALIDATION") {
		t.Fatalf("pending drain: %+v %v", hr, err)
	}
	for _, name := range []string{"l0", "l1", "l2"} {
		if got := t3Role(t, base, name); got != roleRetiring {
			t.Fatalf("%s %s", name, got)
		}
	}
}

func TestT3RequestDrainRestoreExactAbsentLabelAndJoinFailure(t *testing.T) {
	p := aiPod("ns", "infer", map[string]string{"unrelated": "keep"})
	base := fakeC(p)
	drainErr, restoreErr := errors.New("drain HTTP 500"), errors.New("restore update refused")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		pod := obj.(*corev1.Pod)
		if _, exists := pod.Labels[labelServing]; !exists {
			return restoreErr
		}
		return nil
	}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{drainErr: drainErr}}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, drainErr) || !errors.Is(err, restoreErr) || hr.Emitted || len(hr.ObjectsTouched) != 1 {
		t.Fatalf("partial %v %+v", err, hr)
	}
	var saved corev1.Pod
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Labels[labelServing] != "drained" || saved.Labels[labelDrainEpoch] == "" || saved.Labels["unrelated"] != "keep" {
		t.Fatalf("persisted %+v", saved.Labels)
	}
	// Complete compensation of an absent label must remove the key, not write an empty value.
	completeBase := fakeC(aiPod("ns", "infer", map[string]string{"unrelated": "keep"}))
	_, err = requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: completeBase, VLLM: &mockVLLM{drainErr: drainErr}}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, drainErr) {
		t.Fatal(err)
	}
	if err := completeBase.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); err != nil {
		t.Fatal(err)
	}
	if _, present := saved.Labels[labelServing]; present {
		t.Fatalf("absent prior serving label restored as %q", saved.Labels[labelServing])
	}
	if saved.Labels[labelDrainEpoch] == "" {
		t.Fatal("drain event epoch lost")
	}
}

func TestT3RequestDrainRestoreUpdateFailureRetainsBothErrors(t *testing.T) {
	base := fakeC(aiPod("ns", "infer", map[string]string{labelServing: "true"}))
	primary, restoreErr := errors.New("reachable drain HTTP 500"), errors.New("restore update refused")
	c := &t3FaultClient{Client: base}
	c.updateFault = func(obj client.Object) error {
		p := obj.(*corev1.Pod)
		if p.Labels[labelServing] == "true" {
			return restoreErr
		}
		return nil
	}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{drainErr: primary}}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, primary) || !errors.Is(err, restoreErr) || hr.Emitted || len(hr.ObjectsTouched) != 1 {
		t.Fatalf("swallowed restore or lost effects: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); getErr != nil {
		t.Fatal(getErr)
	}
	if saved.Labels[labelServing] != "drained" || saved.Labels[labelDrainEpoch] == "" {
		t.Fatalf("failed restore did not retain stop-admit: %+v", saved.Labels)
	}
}

func TestT3RequestDrainRestorePreservesConcurrentMetadata(t *testing.T) {
	base := fakeC(aiPod("ns", "infer", map[string]string{labelServing: "standby"}))
	primary := errors.New("reachable drain refused")
	mv := &t3DrainHook{mockVLLM: &mockVLLM{drainErr: primary}}
	mv.hook = func() {
		var current corev1.Pod
		if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &current); err != nil {
			t.Fatal(err)
		}
		current.Annotations = ensureMap(current.Annotations)
		current.Annotations["concurrent"] = "new-value"
		if err := base.Update(context.Background(), &current); err != nil {
			t.Fatal(err)
		}
	}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: base, VLLM: mv}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, primary) || hr.Emitted {
		t.Fatalf("failed drain: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); getErr != nil {
		t.Fatal(getErr)
	}
	if saved.Labels[labelServing] != "standby" || saved.Annotations["concurrent"] != "new-value" || saved.Labels[labelDrainEpoch] == "" {
		t.Fatalf("metadata lost: %+v", saved.ObjectMeta)
	}
}

func TestT3RequestDrainRestoreRefusesSameNameReplacement(t *testing.T) {
	base := fakeC(aiPod("ns", "infer", map[string]string{labelServing: "true"}))
	primary := errors.New("reachable drain refused")
	mv := &t3DrainHook{mockVLLM: &mockVLLM{drainErr: primary}}
	mv.hook = func() {
		var old corev1.Pod
		if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &old); err != nil {
			t.Fatal(err)
		}
		if err := base.Delete(context.Background(), &old); err != nil {
			t.Fatal(err)
		}
		old.UID = types.UID("replacement-infer")
		old.ResourceVersion = ""
		old.Labels[labelServing] = "replacement"
		if err := base.Create(context.Background(), &old); err != nil {
			t.Fatal(err)
		}
	}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: base, VLLM: mv}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, primary) || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("replacement: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); getErr != nil {
		t.Fatal(getErr)
	}
	if saved.UID != types.UID("replacement-infer") || saved.Labels[labelServing] != "replacement" {
		t.Fatalf("replacement overwritten: %+v", saved.ObjectMeta)
	}
}

func TestT3RequestDrainRestoreRefusesLaterDrainEpoch(t *testing.T) {
	base := fakeC(aiPod("ns", "infer", map[string]string{labelServing: "true"}))
	primary := errors.New("reachable drain refused")
	mv := &t3DrainHook{mockVLLM: &mockVLLM{drainErr: primary}}
	mv.hook = func() {
		var current corev1.Pod
		if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &current); err != nil {
			t.Fatal(err)
		}
		current.Labels[labelDrainEpoch] = "newer-drain-event"
		if err := base.Update(context.Background(), &current); err != nil {
			t.Fatal(err)
		}
	}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: base, VLLM: mv}, Request{Namespace: "ns", Pod: "infer"})
	if !errors.Is(err, primary) || !containsStr(err.Error(), "drain epoch changed") || hr.Emitted {
		t.Fatalf("later drain: %+v %v", hr, err)
	}
	var saved corev1.Pod
	if getErr := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &saved); getErr != nil {
		t.Fatal(getErr)
	}
	if saved.Labels[labelServing] != "drained" || saved.Labels[labelDrainEpoch] != "newer-drain-event" {
		t.Fatalf("later drain overwritten: %+v", saved.Labels)
	}
}
