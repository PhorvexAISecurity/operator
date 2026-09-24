package ingest

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
)

const tokenVectorType = "phorvex.attack.pod-bound-api-auth"

func TestPodBoundTokenVectorSourceCRDTypeIsOpenString(t *testing.T) {
	data, err := os.ReadFile("../../../build/phoenix-extended/config/crd/bases/amtd.r6security.com_securityevents.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	if crd.Spec.Names.Kind != "SecurityEvent" {
		t.Fatalf("unexpected CRD kind %q", crd.Spec.Names.Kind)
	}
	for _, version := range crd.Spec.Versions {
		if !version.Served || version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}
		spec := version.Schema.OpenAPIV3Schema.Properties["spec"]
		rule := spec.Properties["rule"]
		typeField := rule.Properties["type"]
		if typeField.Type != "string" || len(typeField.Enum) != 0 {
			t.Fatalf("served %s rejects the named credential vector: type=%q enum=%v", version.Name, typeField.Type, typeField.Enum)
		}
		return
	}
	t.Fatal("SecurityEvent CRD has no served typed rule schema")
}

var tokenVectorNow = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// The fake API supplies admitted Pod/ServiceAccount and SecurityEvent objects to
// the actual snapshot producer. The event description/source is deliberately
// nonauthoritative; trust comes from the admitted creator identity.
func tokenVectorSnapshot(t *testing.T, edit func(*corev1.Pod, *corev1.ServiceAccount, *amtd.SecurityEvent), allowCreator bool) *Snapshot {
	t.Helper()
	started, automount := true, false
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "owned", Name: "source", UID: types.UID("pod-uid"),
			ResourceVersion: "23", CreationTimestamp: metav1.NewTime(tokenVectorNow.Add(-time.Hour))},
		Spec: corev1.PodSpec{ServiceAccountName: "reader", AutomountServiceAccountToken: &automount,
			Containers: []corev1.Container{{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "api-token", MountPath: "/credential", ReadOnly: true}}}},
			Volumes: []corev1.Volume{{Name: "api-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}},
			}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Started: &started,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "owned", Name: "reader",
		UID: types.UID("sa-uid"), ResourceVersion: "11", CreationTimestamp: metav1.NewTime(tokenVectorNow.Add(-2 * time.Hour))}}
	event := &amtd.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "observed", UID: types.UID("event-uid"),
			CreationTimestamp: metav1.NewTime(tokenVectorNow.Add(-8 * time.Minute)),
			Annotations: map[string]string{CreatorIdentityAnnotation: "system:serviceaccount:owned:detector",
				ConsoleTargetPodUIDAnnotation: "pod-uid"}},
		Spec: amtd.SecurityEventSpec{Targets: []string{"owned/source"},
			Description: "synthetic bound API bearer observed",
			Rule:        amtd.Rule{Type: tokenVectorType, ThreatLevel: "critical", Source: "self-declared-detector"}},
	}
	if edit != nil {
		edit(pod, sa, event)
	}
	if allowCreator {
		trustEvents(t, "owned/detector")
	} else {
		trustEvents(t)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sa, event,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned"}}).Build()
	snapshot, err := CollectSnapshot(context.Background(), c, tokenVectorNow, nil, c)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func tokenVectorTrace(t *testing.T, snapshot *Snapshot) (*model.DecisionTraceV2, *model.WorkloadView) {
	t.Helper()
	pod := snapshot.PodByKey["owned/source"]
	if pod == nil {
		t.Fatal("source Pod absent from actual snapshot")
	}
	view := &model.WorkloadView{Pod: *pod, Physics: model.NeutralPhysics(),
		Phase: model.PhaseWarm, Events: snapshot.EventByPod["owned/source"],
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour}}
	engine := decision.NewCoverageEngine()
	engine.Now = func() time.Time { return tokenVectorNow }
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("production recon profile absent")
	}
	engine.Recon = profile
	policy := model.Policy{Tenant: "owned-tenant", Namespace: "owned", PolicyName: "owned-policy",
		PolicyUID: "policy-uid", TickID: "tick", BrainImage: "image", GitSHA: "sha", DryRun: true,
		Lambda: .4, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8,
		MaxMovesPerTick: 1, ProactiveFloor: time.Hour, AntiOverRotationWindow: time.Minute,
		EventAgeHorizon: 10 * time.Minute, EnabledActions: map[model.Action]bool{
			model.ActionRotate: true, model.ActionQuarantine: true}, TraceEnabled: true}
	decisions := engine.Decide([]*model.WorkloadView{view}, policy)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("actual producer decision trace absent: %+v", decisions)
	}
	return decisions[0].Trace, view
}

func tokenVectorFact(t *testing.T, trace *model.DecisionTraceV2) model.DecisionFactV2 {
	t.Helper()
	for _, fact := range trace.Facts {
		if fact.FactType == recon.FactPodBoundKubeAPIAuthPotential {
			return fact
		}
	}
	return model.DecisionFactV2{}
}

func TestPodBoundTokenVectorActualProducerToDecisionTrace(t *testing.T) {
	snapshot := tokenVectorSnapshot(t, nil, true)
	trace, view := tokenVectorTrace(t, snapshot)
	fact := tokenVectorFact(t, trace)
	if fact.FactType == "" || fact.SteeredBy == nil || fact.SteeredBy.RuleType != tokenVectorType ||
		fact.SteeredBy.AppliedMultiplier != 3 || len(fact.SteeredBy.Events) != 1 {
		t.Fatalf("narrow fact lacked one bounded typed attribution: %+v", fact)
	}
	ref := fact.SteeredBy.Events[0]
	if ref.EventName != "observed" || ref.EventUID != "event-uid" ||
		ref.CreatorIdentity != "system:serviceaccount:owned:detector" ||
		ref.TrustVerdict != TrustTrusted || ref.TargetPodUID != "pod-uid" {
		t.Fatalf("attribution lost exact admitted event: %+v", ref)
	}
	if len(fact.CoveringActions) != 1 || fact.CoveringActions[0] != string(model.ActionRotate) {
		t.Fatalf("narrow potential fact cover changed: %+v", fact.CoveringActions)
	}
	profile, _ := recon.Registry.Get("ucw-recon")
	ctx := recon.FactContext{AssetValue: 7, PHold: 1, StageUrgency: 1, EventAgeHorizon: 10 * time.Minute}
	boosted := profile.AssetFacts(view, ctx)
	baselineView := *view
	baselineView.Events = nil
	baseline := profile.AssetFacts(&baselineView, ctx)
	var boostedWeight, baselineWeight float64
	for _, f := range boosted.Facts {
		if f.Kind == recon.FactPodBoundKubeAPIAuthPotential {
			boostedWeight = f.Weight
		}
	}
	for _, f := range baseline.Facts {
		if f.Kind == recon.FactPodBoundKubeAPIAuthPotential {
			baselineWeight = f.Weight
		}
	}
	if baselineWeight <= 0 || boostedWeight != baselineWeight*3 {
		t.Fatalf("actual producer multiplier=%g baseline=%g", boostedWeight, baselineWeight)
	}
	if len(trace.Candidates) == 0 {
		t.Fatal("decision did not expose any candidate or exclusion")
	}
	if !trace.Inputs.Clocks.SinceEvidence.Present {
		t.Fatal("qualified event absent from the evidence clock")
	}
	raw, err := json.Marshal(trace)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("decision trace could not be serialized: %v", err)
	}
}

func TestPodBoundTokenVectorRejectedEventDoesNotSetEvidenceClock(t *testing.T) {
	snapshot := tokenVectorSnapshot(t, func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
		e.Annotations[ConsoleTargetPodUIDAnnotation] = "former-pod-uid"
	}, true)
	trace, _ := tokenVectorTrace(t, snapshot)
	if trace.Inputs.Clocks.SinceEvidence.Present {
		t.Fatalf("rejected token event appeared as admitted evidence: %+v", trace.Inputs.Clocks.SinceEvidence)
	}
}

func TestPodBoundTokenVectorProducerRefusesUnsafeInputs(t *testing.T) {
	tests := []struct {
		name         string
		edit         func(*corev1.Pod, *corev1.ServiceAccount, *amtd.SecurityEvent)
		allowCreator bool
		factAbsent   bool
	}{
		{"no allowlist", nil, false, false},
		{"forged source", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.Annotations[CreatorIdentityAnnotation] = "system:serviceaccount:foreign:detector"
			e.Spec.Rule.Source = "owned-detector"
		}, true, false},
		{"unstamped", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			delete(e.Annotations, CreatorIdentityAnnotation)
		}, true, false},
		{"missing UID", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.UID = ""
		}, true, false},
		{"wrong Pod UID", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.Annotations[ConsoleTargetPodUIDAnnotation] = "previous-pod-uid"
		}, true, false},
		{"unbound event", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			delete(e.Annotations, ConsoleTargetPodUIDAnnotation)
		}, true, false},
		{"extra target", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.Spec.Targets = append(e.Spec.Targets, "owned/peer")
		}, true, false},
		{"generic prose", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.Spec.Rule.Type = "Panic"
			e.Spec.Description = "copied Pod-bound API bearer"
		}, true, false},
		{"expired at policy horizon", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.CreationTimestamp = metav1.NewTime(tokenVectorNow.Add(-10 * time.Minute))
		}, true, false},
		{"future timestamp", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.CreationTimestamp = metav1.NewTime(tokenVectorNow.Add(time.Minute))
		}, true, false},
		{"zero timestamp", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			e.CreationTimestamp = metav1.Time{}
		}, true, false},
		{"deleting event", func(_ *corev1.Pod, _ *corev1.ServiceAccount, e *amtd.SecurityEvent) {
			deleting := metav1.NewTime(tokenVectorNow)
			e.DeletionTimestamp = &deleting
			e.Finalizers = []string{"fixture.test/retain"}
		}, true, false},
		{"replacement Pod", func(p *corev1.Pod, _ *corev1.ServiceAccount, _ *amtd.SecurityEvent) {
			p.UID = types.UID("replacement-uid")
		}, true, false},
		{"replacement ServiceAccount", func(_ *corev1.Pod, sa *corev1.ServiceAccount, _ *amtd.SecurityEvent) {
			sa.CreationTimestamp = metav1.NewTime(tokenVectorNow)
		}, true, true},
		{"projection absent", func(p *corev1.Pod, _ *corev1.ServiceAccount, _ *amtd.SecurityEvent) {
			p.Spec.Volumes = nil
		}, true, true},
		{"foreign audience", func(p *corev1.Pod, _ *corev1.ServiceAccount, _ *amtd.SecurityEvent) {
			p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "foreign"
		}, true, true},
		{"shadowed token", func(p *corev1.Pod, _ *corev1.ServiceAccount, _ *amtd.SecurityEvent) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts,
				corev1.VolumeMount{Name: "shadow", MountPath: "/credential/token"})
		}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := tokenVectorSnapshot(t, tc.edit, tc.allowCreator)
			trace, _ := tokenVectorTrace(t, snapshot)
			fact := tokenVectorFact(t, trace)
			if tc.factAbsent {
				if fact.FactType != "" {
					t.Fatalf("absent structural witness minted a fact: %+v", fact)
				}
			} else if fact.FactType == "" || fact.SteeredBy != nil {
				t.Fatalf("unsafe event steered or removed structural fact: %+v", fact)
			}
		})
	}
}
