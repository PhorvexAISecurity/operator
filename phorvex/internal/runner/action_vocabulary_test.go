package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

func policySchemaCRD(uid string, values ...string) *apiextv1.CustomResourceDefinition {
	enum := make([]apiextv1.JSON, 0, len(values))
	for _, value := range values {
		enum = append(enum, apiextv1.JSON{Raw: []byte("\"" + value + "\"")})
	}
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: policyCRDName, UID: types.UID(uid), ResourceVersion: "17"},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: "phorvex.ai", Names: apiextv1.CustomResourceDefinitionNames{Plural: "phorvexpolicies", Kind: "PhorvexPolicy"},
			Versions: []apiextv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true,
				Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{
					"spec": {Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{
						"actions": {Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{
							"enabled": {Type: "array", Items: &apiextv1.JSONSchemaPropsOrArray{Schema: &apiextv1.JSONSchemaProps{Type: "string", Enum: enum}}},
						}},
					}},
				}}},
			}},
		},
	}
}

func fakeVocabularyReader(t *testing.T, crd *apiextv1.CustomResourceDefinition) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apiextv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(crd).Build()
}

func TestInstalledSchemaReaderReachesRuntimeWitness(t *testing.T) {
	reader := fakeVocabularyReader(t, policySchemaCRD("old", "rotate", "quarantine", "noop"))
	m := &Manager{VocabularyReader: reader, Log: logr.Discard()}
	now := time.Now()
	old := m.refreshVocabulary(context.Background(), now)
	if !old.Known || !old.NotInstallable.Has(model.ActionKVReset) || old.NotInstallable.Has(model.ActionRotate) {
		t.Fatalf("older enum complement wrong: %+v", old)
	}
	pod := model.Pod{Namespace: "ns", Name: "pod", Ready: true}
	witness := capability.BuildWitness(context.Background(), capability.BuildIndex([]model.Pod{pod}, nil, nil), old.NotInstallable, nil, nil)
	if got := witness.Eligible(&model.WorkloadView{Pod: pod}, model.ActionKVReset, []string{"fact"}); got == nil || got.Kind != capability.ReasonNotInstallable {
		t.Fatalf("real witness did not exclude absent action: %+v", got)
	}
	if got := witness.Eligible(&model.WorkloadView{Pod: pod}, model.ActionRotate, []string{"fact"}); got != nil && got.Kind == capability.ReasonNotInstallable {
		t.Fatalf("present action excluded: %+v", got)
	}
	if readerGet := m.VocabularySnapshot(); readerGet.NotInstallable != nil {
		delete(readerGet.NotInstallable, model.ActionKVReset)
	}
	if !m.VocabularySnapshot().NotInstallable.Has(model.ActionKVReset) {
		t.Fatal("published snapshot mutated by caller")
	}

	current := policySchemaCRD("new", "rotate", "quarantine", "noop", "kv-reset", "future-action")
	current.ResourceVersion = ""
	if err := reader.Delete(context.Background(), policySchemaCRD("old", "rotate", "quarantine", "noop")); err != nil {
		t.Fatal(err)
	}
	if err := reader.Create(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if early := m.refreshVocabulary(context.Background(), now.Add(10*time.Second)); early.UID != "old" {
		t.Fatalf("unbounded refresh: %+v", early)
	}
	upgraded := m.refreshVocabulary(context.Background(), now.Add(vocabularyRefreshInterval))
	if !upgraded.Known || upgraded.UID != "new" || upgraded.NotInstallable.Has(model.ActionKVReset) {
		t.Fatalf("upgrade not observed: %+v", upgraded)
	}
}

func TestAbsentActionReachesCandidateStatus(t *testing.T) {
	m := &Manager{VocabularyReader: fakeVocabularyReader(t, policySchemaCRD("subset", "rotate", "noop")), Log: logr.Discard()}
	observed := m.refreshVocabulary(context.Background(), time.Now())
	pod := model.Pod{Namespace: "ns", Name: "pod", UID: "pod-uid", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, MountedSecrets: []string{"secret-ref"}}
	witness := capability.BuildWitness(context.Background(), capability.BuildIndex([]model.Pod{pod}, nil, nil), observed.NotInstallable, nil, supportsAll{})
	ce := decision.NewCoverageEngine()
	exposure := map[string]time.Duration{}
	for _, variable := range model.LiveExposureVariables {
		exposure[variable] = 2 * time.Hour
	}
	views := []*model.WorkloadView{{Pod: pod, Phase: model.PhaseWarm, BlastRadius: .6, ExposureByVariable: exposure}}
	pol := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyUID: "policy", PolicyName: "policy", TraceEnabled: true, BrainImage: "fixture", GitSHA: "fixture", DryRun: true, Lambda: .4, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, MaxMovesPerTick: 2, ProactiveFloor: time.Hour, AntiOverRotationWindow: 5 * time.Minute, MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}}
	wireCapabilityGates(ce, witness, false, func(*model.WorkloadView) bool { return false })
	decisions, err := ce.DecideChecked(views, pol)
	if err != nil || len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("candidate trace unavailable: %v %+v", err, decisions)
	}
	var absent, present *model.DecisionActionStatusV3
	for i := range decisions[0].Trace.ActionStatus {
		row := &decisions[0].Trace.ActionStatus[i]
		if row.Action == string(model.ActionQuarantine) {
			absent = row
		}
		if row.Action == string(model.ActionRotate) {
			present = row
		}
	}
	if absent == nil || absent.Status != model.ActionStatusNotInstallable || absent.ExclusionKind != model.ExclusionNotInstallable {
		t.Fatalf("absent candidate not labelled: %+v", absent)
	}
	if present == nil || present.Status == model.ActionStatusNotInstallable {
		t.Fatalf("present action marked absent: %+v", present)
	}
}

func TestSchemaAmbiguityAndReadFailureRemainUnknown(t *testing.T) {
	malformed := policySchemaCRD("bad", "rotate")
	spec := malformed.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	actions := spec.Properties["actions"]
	delete(actions.Properties, "enabled")
	spec.Properties["actions"] = actions
	malformed.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"] = spec
	if _, err := installedPolicyActions(malformed); err == nil {
		t.Fatal("missing path verified")
	}
	unserved := policySchemaCRD("bad", "rotate")
	unserved.Spec.Versions[0].Served = false
	if _, err := installedPolicyActions(unserved); err == nil {
		t.Fatal("unserved schema verified")
	}
	missingUID := policySchemaCRD("", "rotate")
	if _, err := installedPolicyActions(missingUID); err == nil {
		t.Fatal("CRD without stable UID verified")
	}
	missingRV := policySchemaCRD("bad", "rotate")
	missingRV.ResourceVersion = ""
	if _, err := installedPolicyActions(missingRV); err == nil {
		t.Fatal("CRD without resourceVersion verified")
	}
	deleting := policySchemaCRD("bad", "rotate")
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	if _, err := installedPolicyActions(deleting); err == nil {
		t.Fatal("deleting CRD verified")
	}
	conflicting := policySchemaCRD("bad", "rotate")
	second := conflicting.Spec.Versions[0]
	second.Name = "v1beta1"
	second.Schema = second.Schema.DeepCopy()
	second.Schema.OpenAPIV3Schema.Properties = policySchemaCRD("other", "quarantine").Spec.Versions[0].Schema.OpenAPIV3Schema.Properties
	conflicting.Spec.Versions = append(conflicting.Spec.Versions, second)
	if _, err := installedPolicyActions(conflicting); err == nil {
		t.Fatal("conflicting served versions verified")
	}
	invalidJSON := policySchemaCRD("bad", "rotate")
	spec = invalidJSON.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	actions = spec.Properties["actions"]
	enabled := actions.Properties["enabled"]
	enabled.Items.Schema.Enum[0].Raw = []byte("4")
	actions.Properties["enabled"] = enabled
	spec.Properties["actions"] = actions
	invalidJSON.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"] = spec
	if _, err := installedPolicyActions(invalidJSON); err == nil {
		t.Fatal("nonstring enum verified")
	}

	m := &Manager{VocabularyReader: fakeVocabularyReader(t, policySchemaCRD("known", "rotate")), Log: logr.Discard()}
	now := time.Now()
	if !m.refreshVocabulary(context.Background(), now).Known {
		t.Fatal("positive control failed")
	}
	m.VocabularyReader = failureReader{err: errors.New("forbidden")}
	failed := m.refreshVocabulary(context.Background(), now.Add(vocabularyRefreshInterval))
	if failed.Known || failed.NotInstallable != nil || failed.UID != "known" {
		t.Fatalf("failure reuses current exclusion: %+v", failed)
	}
	status, _, msg := failed.diagnostic()
	if status != metav1.ConditionUnknown || !strings.Contains(msg, "historical only") {
		t.Fatalf("unknown diagnostic missing history: %s", msg)
	}
	m.VocabularyReader = fakeVocabularyReader(t, policySchemaCRD("recovered", "rotate", "kv-reset"))
	if got := m.refreshVocabulary(context.Background(), now.Add(2*vocabularyRefreshInterval)); !got.Known || got.UID != "recovered" {
		t.Fatalf("recovery failed: %+v", got)
	}
	other := &Manager{Log: logr.Discard()}
	if other.VocabularySnapshot().Known {
		t.Fatal("manager instances shared global knowledge")
	}
}

func TestFullVocabularyAndCancelledRead(t *testing.T) {
	names := make([]string, 0, len(model.AllKnownActions()))
	for _, action := range model.AllKnownActions() {
		names = append(names, string(action))
	}
	m := &Manager{VocabularyReader: fakeVocabularyReader(t, policySchemaCRD("full", names...)), Log: logr.Discard()}
	now := time.Now()
	full := m.refreshVocabulary(context.Background(), now)
	if !full.Known || len(full.NotInstallable) != 0 {
		t.Fatalf("verified full vocabulary is not empty: %+v", full)
	}
	m.VocabularyReader = waitingReader{}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	result := m.refreshVocabulary(cancelled, now.Add(vocabularyRefreshInterval))
	if result.Known || result.Error == "" || result.NotInstallable != nil {
		t.Fatalf("cancelled read treated as known: %+v", result)
	}
}

func TestVocabularyUnknownIsPublishedOnPolicyStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", Generation: 1}}
	policyClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(policy).Build()
	m := &Manager{Client: policyClient, VocabularyReader: failureReader{err: errors.New("forbidden")}, Log: logr.Discard()}
	entry := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "policy"}}
	now := time.Now()
	m.refreshVocabulary(context.Background(), now)
	m.updateStatus(context.Background(), entry, 1, 0, 0, false, now)
	var got v1alpha1.PhorvexPolicy
	if err := policyClient.Get(context.Background(), entry.key, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "PolicyActionVocabulary")
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "DiscoveryUnavailable" {
		t.Fatalf("unverified read hidden from status: %+v", cond)
	}
	m.VocabularyReader = fakeVocabularyReader(t, policySchemaCRD("known", "rotate"))
	m.refreshVocabulary(context.Background(), now.Add(vocabularyRefreshInterval))
	m.updateStatus(context.Background(), entry, 1, 0, 0, false, now.Add(vocabularyRefreshInterval))
	if err := policyClient.Get(context.Background(), entry.key, &got); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(got.Status.Conditions, "PolicyActionVocabulary")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "SchemaObserved" {
		t.Fatalf("recovered status not verified: %+v", cond)
	}
}

func TestVocabularySnapshotConcurrentPublicationIsImmutable(t *testing.T) {
	m := &Manager{VocabularyReader: fakeVocabularyReader(t, policySchemaCRD("stable", "rotate")), Log: logr.Discard()}
	start := time.Now()
	m.refreshVocabulary(context.Background(), start)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for i := 1; i <= 40; i++ {
			m.refreshVocabulary(context.Background(), start.Add(time.Duration(i)*vocabularyRefreshInterval))
		}
	}()
	go func() {
		defer group.Done()
		for i := 0; i < 400; i++ {
			s := m.VocabularySnapshot()
			delete(s.NotInstallable, model.ActionQuarantine)
		}
	}()
	group.Wait()
	if !m.VocabularySnapshot().NotInstallable.Has(model.ActionQuarantine) {
		t.Fatal("concurrent caller mutated published exclusions")
	}
}

type failureReader struct{ err error }

func (r failureReader) Get(ctx context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return r.err
}
func (r failureReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	panic("unexpected list")
}

type waitingReader struct{}

func (waitingReader) Get(ctx context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	<-ctx.Done()
	return ctx.Err()
}
func (waitingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	panic("unexpected list")
}
