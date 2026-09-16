package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m009ControlledRotateFixture() (*amtdv1beta1.AdaptiveMovingTargetDefense, *corev1.Pod, *amtdv1beta1.SecurityEvent) {
	rule := amtdv1beta1.Rule{Type: PHORVEX_ROTATE_RULE_TYPE, ThreatLevel: PHORVEX_ROTATE_THREAT_LEVEL, Source: PHORVEX_CONTROLLED_RULE_SOURCE}
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "phorvex-ns-tenant", Namespace: "ns", UID: "amtd-uid"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "api"},
			// This Delete mapping is the actual long-standing Phorvex producer contract.
			Strategy: []amtdv1beta1.ResponseStrategy{{Rule: rule, Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}}},
		},
	}
	pod := managedPod("api-0", "ns", "ns", amtd.Name)
	pod.UID, pod.ResourceVersion = types.UID("pod-old"), "1"
	pod.Labels = map[string]string{"app": "api"}
	event := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "phorvex-rotate-a", UID: "event-uid", Annotations: map[string]string{PHORVEX_ROTATE_TARGET_UID: string(pod.UID)}},
		Spec:       amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/api-0"}, Rule: rule},
	}
	return amtd, pod, event
}

type m009DeleteInspectClient struct {
	crclient.Client
	uid types.UID
	rv  string
}

type m009ReplaceOnNthPodRead struct {
	crclient.Reader
	client      crclient.Client
	oldPod      *corev1.Pod
	replacement *corev1.Pod
	nth, reads  int
}

func (r *m009ReplaceOnNthPodRead) Get(ctx context.Context, key crclient.ObjectKey, obj crclient.Object, opts ...crclient.GetOption) error {
	if _, ok := obj.(*corev1.Pod); ok && key.Namespace == r.oldPod.Namespace && key.Name == r.oldPod.Name {
		r.reads++
		if r.reads == r.nth {
			if err := r.client.Delete(ctx, r.oldPod); err != nil {
				return err
			}
			if err := r.client.Create(ctx, r.replacement); err != nil {
				return err
			}
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (c *m009DeleteInspectClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	o := &crclient.DeleteOptions{}
	for _, apply := range opts {
		apply.ApplyToDelete(o)
	}
	if o.Preconditions != nil && o.Preconditions.UID != nil && o.Preconditions.ResourceVersion != nil {
		c.uid, c.rv = *o.Preconditions.UID, *o.Preconditions.ResourceVersion
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestM009ControlledRotateDeleteWritesExactReceipt(t *testing.T) {
	ctx := context.Background()
	amtd, pod, event := m009ControlledRotateFixture()
	base := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event).WithStatusSubresource(event).Build()
	cl := &m009DeleteInspectClient{Client: base}
	r := &SecurityEventReconciler{Client: cl, APIReader: base, Scheme: seTestScheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := base.Get(ctx, crclient.ObjectKeyFromObject(pod), &corev1.Pod{}); err == nil {
		t.Fatal("controlled rotate target survived accepted Delete")
	}
	if cl.uid != pod.UID || cl.rv == "" {
		t.Fatalf("Delete preconditions uid=%q rv=%q, want exact target UID and fresh RV", cl.uid, cl.rv)
	}
	got := &amtdv1beta1.SecurityEvent{}
	if err := base.Get(ctx, crclient.ObjectKey{Name: event.Name}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AppliedAction != "rotate" || got.Status.ProcessedAt.IsZero() {
		t.Fatalf("execution receipt=%+v, want terminal rotate after accepted Delete", got.Status)
	}
}

func TestM009ControlledRotateRejectsMissingOrWrongTargetUID(t *testing.T) {
	for _, envelope := range []string{"", "pod-recreated"} {
		t.Run(envelope, func(t *testing.T) {
			amtd, pod, event := m009ControlledRotateFixture()
			event.Annotations[PHORVEX_ROTATE_TARGET_UID] = envelope
			cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event).WithStatusSubresource(event).Build()
			r := &SecurityEventReconciler{Client: cl, APIReader: cl, Scheme: seTestScheme}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err == nil {
				t.Fatal("invalid target identity envelope was accepted")
			}
			got := &corev1.Pod{}
			if err := cl.Get(context.Background(), crclient.ObjectKeyFromObject(pod), got); err != nil {
				t.Fatalf("refusal deleted target: %v", err)
			}
			if got.Annotations[AMTD_APPLIED_SECURITY_EVENTS] != "" {
				t.Fatal("refusal mutated target before identity validation")
			}
		})
	}
}

func TestM009ControlledRotateRejectsNonExactTargetSet(t *testing.T) {
	for name, targets := range map[string][]string{
		"missing":  nil,
		"multiple": []string{"ns/api-0", "ns/api-1"},
	} {
		t.Run(name, func(t *testing.T) {
			amtd, pod, event := m009ControlledRotateFixture()
			event.Spec.Targets = targets
			cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event).WithStatusSubresource(event).Build()
			r := &SecurityEventReconciler{Client: cl, APIReader: cl, Scheme: seTestScheme}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err == nil {
				t.Fatal("non-exact controlled target set was accepted")
			}
			if err := cl.Get(context.Background(), crclient.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
				t.Fatalf("refusal deleted target: %v", err)
			}
		})
	}
}

func TestM009ControlledRotateRejectsNonCompatibilityAction(t *testing.T) {
	amtd, pod, event := m009ControlledRotateFixture()
	amtd.Spec.Strategy[0].Action = amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{}}
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event).WithStatusSubresource(event).Build()
	r := &SecurityEventReconciler{Client: cl, APIReader: cl, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err == nil {
		t.Fatal("controlled producer tuple escaped its historical Delete compatibility action")
	}
	got := &corev1.Pod{}
	if err := cl.Get(context.Background(), crclient.ObjectKeyFromObject(pod), got); err != nil {
		t.Fatalf("action mismatch deleted target: %v", err)
	}
	if got.Annotations[AMTD_APPLIED_SECURITY_EVENTS] != "" {
		t.Fatal("action mismatch mutated target")
	}
}

func TestM009ControlledRotateRejectsSameNameReplacementBeforeMutation(t *testing.T) {
	amtd, original, event := m009ControlledRotateFixture()
	replacement := original.DeepCopy()
	replacement.UID, replacement.ResourceVersion = "pod-new", ""
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, original, event).WithStatusSubresource(event).Build()
	boundary := &replaceOnThirdPodRead{Reader: cl, client: cl, oldPod: original.DeepCopy(), replacement: replacement}
	r := &SecurityEventReconciler{Client: cl, APIReader: boundary, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err == nil {
		t.Fatal("same-name replacement between validation and mutation was accepted")
	}
	got := &corev1.Pod{}
	if err := cl.Get(context.Background(), crclient.ObjectKeyFromObject(replacement), got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[AMTD_APPLIED_SECURITY_EVENTS] != "" {
		t.Fatal("same-name replacement was mutated")
	}
}

func TestM009ControlledRotateRejectsSameNameReplacementAtDeleteBoundary(t *testing.T) {
	amtd, original, event := m009ControlledRotateFixture()
	replacement := original.DeepCopy()
	replacement.UID, replacement.ResourceVersion = "pod-new", ""
	delete(replacement.Annotations, AMTD_APPLIED_SECURITY_EVENTS)
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, original, event).WithStatusSubresource(event).Build()
	// Reads 1-4 cover preparation, loop entry, and the annotation update. Read 5
	// is the authoritative read immediately before the UID/RV-preconditioned Delete.
	boundary := &m009ReplaceOnNthPodRead{Reader: cl, client: cl, oldPod: original.DeepCopy(), replacement: replacement, nth: 5}
	r := &SecurityEventReconciler{Client: cl, APIReader: boundary, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err == nil {
		t.Fatal("same-name replacement at Delete boundary was accepted")
	}
	got := &corev1.Pod{}
	if err := cl.Get(context.Background(), crclient.ObjectKeyFromObject(replacement), got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[AMTD_APPLIED_SECURITY_EVENTS] != "" {
		t.Fatal("replacement inherited stale event mutation")
	}
	gotEvent := &amtdv1beta1.SecurityEvent{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Name: event.Name}, gotEvent); err != nil {
		t.Fatal(err)
	}
	if gotEvent.Status.AppliedAction != "" || !gotEvent.Status.ProcessedAt.IsZero() {
		t.Fatalf("replacement refusal wrote receipt: %+v", gotEvent.Status)
	}
}

type m009FailStatusWriter struct{ crclient.SubResourceWriter }

func (m009FailStatusWriter) Update(context.Context, crclient.Object, ...crclient.SubResourceUpdateOption) error {
	return errors.New("status write lost")
}

type m009StatusLossClient struct{ crclient.Client }

func (c *m009StatusLossClient) Status() crclient.SubResourceWriter {
	return m009FailStatusWriter{SubResourceWriter: c.Client.Status()}
}

func TestM009AcceptedDeleteWithStatusLossHasNoReceipt(t *testing.T) {
	amtd, pod, event := m009ControlledRotateFixture()
	base := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event).WithStatusSubresource(event).Build()
	cl := &m009StatusLossClient{Client: base}
	r := &SecurityEventReconciler{Client: cl, APIReader: base, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}}); err != nil {
		t.Fatal(err)
	}
	got := &amtdv1beta1.SecurityEvent{}
	if err := base.Get(context.Background(), crclient.ObjectKey{Name: event.Name}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AppliedAction != "" || !got.Status.ProcessedAt.IsZero() {
		t.Fatalf("lost status write fabricated receipt: %+v", got.Status)
	}
}

func TestM009ReceiptWriteRejectsRecreatedEvent(t *testing.T) {
	_, _, original := m009ControlledRotateFixture()
	recreated := original.DeepCopy()
	recreated.UID, recreated.ResourceVersion = "event-recreated", "2"
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(recreated).WithStatusSubresource(recreated).Build()
	r := &SecurityEventReconciler{Client: cl, APIReader: cl, Scheme: seTestScheme}
	r.recordControlledRotateReceipt(context.Background(), original, ctrl.Log.WithName("test"))
	got := &amtdv1beta1.SecurityEvent{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Name: recreated.Name}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AppliedAction != "" || !got.Status.ProcessedAt.IsZero() {
		t.Fatalf("recreated event received predecessor receipt: %+v", got.Status)
	}
}

func TestM009ReceiptWriteRejectsChangedEventEnvelope(t *testing.T) {
	for name, mutate := range map[string]func(*amtdv1beta1.SecurityEvent){
		"rule":       func(e *amtdv1beta1.SecurityEvent) { e.Spec.Rule.ThreatLevel = "critical" },
		"target":     func(e *amtdv1beta1.SecurityEvent) { e.Spec.Targets = []string{"ns/other"} },
		"target-uid": func(e *amtdv1beta1.SecurityEvent) { e.Annotations[PHORVEX_ROTATE_TARGET_UID] = "pod-other" },
	} {
		t.Run(name, func(t *testing.T) {
			_, _, original := m009ControlledRotateFixture()
			fresh := original.DeepCopy()
			mutate(fresh)
			cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(fresh).WithStatusSubresource(fresh).Build()
			r := &SecurityEventReconciler{Client: cl, APIReader: cl, Scheme: seTestScheme}
			r.recordControlledRotateReceipt(context.Background(), original, ctrl.Log.WithName("test"))
			got := &amtdv1beta1.SecurityEvent{}
			if err := cl.Get(context.Background(), crclient.ObjectKey{Name: fresh.Name}, got); err != nil {
				t.Fatal(err)
			}
			if got.Status.AppliedAction != "" || !got.Status.ProcessedAt.IsZero() {
				t.Fatalf("changed event envelope received predecessor receipt: %+v", got.Status)
			}
		})
	}
}
