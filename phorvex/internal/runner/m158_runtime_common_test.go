package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// Baseline adapter: the CRD GET above produces a realistic older schema, but the
// pre-M158 runtime has no discovery reader to configure. The head-only adapter
// replaces this function with the manager's real discovery wiring.
var m158ConfigureRuntimeVocabulary = func(context.Context, *Manager, client.Reader, time.Time) error { return nil }
var m158AssertFailedReadTrace func(*testing.T, *Manager, *policyEntry, *ingest.Snapshot, *bytes.Buffer, *model.DecisionTraceV2)

func TestM158ReaderToProcessTenantTrace(t *testing.T) {
	now := time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)
	crd := m158RuntimeCRD()
	crdReader := m158RuntimeReader(t, crd)
	var observed apiextv1.CustomResourceDefinition
	if err := crdReader.Get(context.Background(), client.ObjectKey{Name: crd.Name}, &observed); err != nil {
		t.Fatal(err)
	}
	enabled := observed.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["actions"].Properties["enabled"]
	if !observed.Spec.Versions[0].Served || len(enabled.Items.Schema.Enum) != 2 {
		t.Fatalf("older served policy schema not produced: %+v", enabled)
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	spec := v1.PhorvexPolicySpec{Tenant: "m158-runtime", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}, Actions: v1.ActionsSpec{Enabled: []v1.ActionType{v1.ActionRotate, v1.ActionQuarantine}}}
	policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: types.UID("policy-uid"), Generation: 1}, Spec: spec}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(policy).Build()
	var auditSink bytes.Buffer
	m := &Manager{Client: c, Clock: exposure.NewClock(), Intents: exposure.NewIntents(), Optimizer: decision.NewCoverageEngine(), Audit: audit.New(logr.Discard(), &auditSink), Actuator: m158RuntimeActuator{}, Log: logr.Discard(), DecisionTraceEnabled: true, BrainImage: "fixture", GitSHA: "fixture", policies: map[string]*policyEntry{}}
	if err := m158ConfigureRuntimeVocabulary(context.Background(), m, crdReader, now); err != nil {
		t.Fatal(err)
	}
	// Exercise automatic maintenance refresh in the actual manager tick, before
	// any tenant witness. Empty registry makes this a bounded no-snapshot tick.
	m.tick(context.Background())
	entry := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "policy-uid", tenant: "m158-runtime", namespace: "ns", spec: spec, selector: labels.SelectorFromSet(map[string]string{"app": "api"})}
	m.policies[entry.key.String()] = entry
	pod := model.Pod{Namespace: "ns", Name: "api-0", UID: "pod-uid", Labels: map[string]string{"app": "api"}, StartedAt: now.Add(-2 * time.Hour), Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, MountedSecrets: []string{"secret-ref"}}
	snap := &ingest.Snapshot{Pods: []model.Pod{pod}, PodByKey: map[string]*model.Pod{"ns/api-0": &pod}, Graph: graph.Build(graph.Input{}), EventByPod: map[string][]model.SecurityEventInfo{}, Now: now}
	m.processTenant(context.Background(), snap, entry, false)
	decoder := json.NewDecoder(&auditSink)
	var trace *model.DecisionTraceV2
	for {
		var record audit.Record
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if record.DecisionTrace != nil {
			trace = record.DecisionTrace
			break
		}
	}
	if trace == nil {
		t.Fatalf("processTenant produced no decision trace: %s", auditSink.String())
	}
	var absent, present *model.DecisionActionStatusV3
	for i := range trace.ActionStatus {
		row := &trace.ActionStatus[i]
		if row.Action == string(model.ActionQuarantine) {
			absent = row
		}
		if row.Action == string(model.ActionRotate) {
			present = row
		}
	}
	if present == nil || present.Status == model.ActionStatusNotInstallable {
		t.Fatalf("present action falsely absent: %+v", present)
	}
	t.Logf("positive control reached: installed rotate status=%s", present.Status)
	if absent == nil || absent.Status != model.ActionStatusNotInstallable || absent.ExclusionKind != model.ExclusionNotInstallable {
		t.Fatalf("reader did not reach runtime not-installable candidate: %+v", absent)
	}
	if m158AssertFailedReadTrace != nil {
		m158AssertFailedReadTrace(t, m, entry, snap, &auditSink, trace)
	}
}

func m158RuntimeCRD() *apiextv1.CustomResourceDefinition {
	item := apiextv1.JSONSchemaProps{Type: "string", Enum: []apiextv1.JSON{{Raw: []byte(`"rotate"`)}, {Raw: []byte(`"noop"`)}}}
	enabled := apiextv1.JSONSchemaProps{Type: "array", Items: &apiextv1.JSONSchemaPropsOrArray{Schema: &item}}
	actions := apiextv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{"enabled": enabled}}
	spec := apiextv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{"actions": actions}}
	root := apiextv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{"spec": spec}}
	return &apiextv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: "phorvexpolicies.phorvex.ai", UID: "old-schema", ResourceVersion: "17"}, Spec: apiextv1.CustomResourceDefinitionSpec{Group: "phorvex.ai", Names: apiextv1.CustomResourceDefinitionNames{Plural: "phorvexpolicies", Kind: "PhorvexPolicy"}, Versions: []apiextv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true, Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &root}}}}}
}
func m158RuntimeReader(t *testing.T, crd *apiextv1.CustomResourceDefinition) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apiextv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(crd).Build()
}

type m158RuntimeActuator struct{}

func (m158RuntimeActuator) Name() string                                              { return "fixture" }
func (m158RuntimeActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (m158RuntimeActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}
func (m158RuntimeActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
