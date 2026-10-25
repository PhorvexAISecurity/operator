// Package budgettest supplies API objects for offline contract tests only.
package budgettest

import (
	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	b "github.com/phorvex/phorvex/internal/servingbudget"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	apps "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v2"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"time"
)

const Namespace = "costbench-opus"
const SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const Image = "example.test/phorvex@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func Owner(kind, name, uid string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: kind, Name: name, UID: types.UID(uid), Controller: &yes}}
}
func Meta(name, uid string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: Namespace, UID: types.UID(uid)}
}
func Fixture() (client.Client, *model.ServingRateBudgetObservation) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = core.AddToScheme(scheme)
	_ = apps.AddToScheme(scheme)
	_ = discovery.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	_ = amtd.AddToScheme(scheme)
	c := b.Contract{Version: 1, SourceSHA256: SHA, ProxyImage: Image, AbusiveAccount: "system:serviceaccount:costbench-opus:default", LegitimateAccount: "system:serviceaccount:costbench-opus:cost-legit", Path: "/"}
	now := time.Now().Add(-time.Second)
	o := &model.ServingRateBudgetObservation{EventName: "cost-event", EventUID: "event-uid", CreatorIdentity: b.DetectorIdentity, ScenarioID: "aml-t0034-cost-harvest", EvidenceSource: "AUTHORITATIVE_PROXY", PolicyName: "cost-defense", PolicyUID: "policy-uid", PolicyGeneration: 1, TargetPodUID: "target-uid", ControllerUID: "target-rs-uid", ServiceUID: "service-uid", LimiterDeploymentUID: "proxy-deployment-uid", LimiterConfigMapUID: "config-uid", LimiterSourceSHA256: SHA, LimiterBootID: "boot-id", OffendingCallerScope: c.AbusiveAccount + "|/", BaselineReqPerSec: 42, ObservedReqPerSec: 1821, ReservedReqPerSec: 42, WindowSeconds: 60, ObservedAt: now}
	target := &core.Pod{ObjectMeta: Meta("cost-target-test", "target-uid"), Status: core.PodStatus{Phase: core.PodRunning, PodIP: "10.0.0.1", Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue}}}}
	target.Labels = map[string]string{"app": "cost-target", "data-class": "restricted"}
	target.OwnerReferences = Owner("ReplicaSet", "cost-target-rs", "target-rs-uid")
	proxy := target.DeepCopy()
	proxy.Name = "cost-admission-test"
	proxy.UID = "proxy-pod-uid"
	proxy.Labels = map[string]string{"app": b.DeploymentName}
	proxy.Status.PodIP = "10.0.0.2"
	proxy.OwnerReferences = Owner("ReplicaSet", "cost-admission-rs", "proxy-rs-uid")
	proxy.Spec = core.PodSpec{ServiceAccountName: "cost-admission", Containers: []core.Container{{Name: "proxy", Image: Image}}}
	replicas := int32(1)
	dep := &apps.Deployment{ObjectMeta: Meta(b.DeploymentName, "proxy-deployment-uid"), Spec: apps.DeploymentSpec{Replicas: &replicas, Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}}}
	prs := &apps.ReplicaSet{ObjectMeta: Meta("cost-admission-rs", "proxy-rs-uid")}
	prs.OwnerReferences = Owner("Deployment", b.DeploymentName, string(dep.UID))
	rs := &apps.ReplicaSet{ObjectMeta: Meta("cost-target-rs", "target-rs-uid")}
	svc := &core.Service{ObjectMeta: Meta(b.ServiceName, "service-uid"), Spec: core.ServiceSpec{Selector: map[string]string{"app": b.DeploymentName}, Ports: []core.ServicePort{{Port: 80, TargetPort: intstr.FromInt(8080)}}}}
	backend := &core.Service{ObjectMeta: Meta(b.BackendName, "backend-uid"), Spec: core.ServiceSpec{Selector: map[string]string{"app": "cost-target"}, Ports: []core.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}}}}
	policy := &api.PhorvexPolicy{ObjectMeta: Meta("cost-defense", "policy-uid"), Spec: api.PhorvexPolicySpec{Mode: api.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "cost-target"}}, Actions: api.ActionsSpec{Enabled: []api.ActionType{api.ActionThrottle}}}}
	policy.Generation = 1
	status := b.Status{PodUID: string(proxy.UID), BootID: "boot-id", ConfigUID: "config-uid", Contract: c, UpdatedAt: now, CalibrationStart: now.Add(-120 * time.Second), CalibrationEnd: now.Add(-60 * time.Second), Baseline: 42, Reserved: 42}
	yes := true
	slice := &discovery.EndpointSlice{ObjectMeta: Meta("admission-slice", "slice-uid"), Endpoints: []discovery.Endpoint{{Conditions: discovery.EndpointConditions{Ready: &yes}, TargetRef: &core.ObjectReference{Kind: "Pod", Name: proxy.Name, UID: proxy.UID}}}}
	slice.Labels = map[string]string{discovery.LabelServiceName: b.ServiceName}
	payload := *o
	payload.EventName = ""
	payload.EventUID = ""
	payload.CreatorIdentity = ""
	event := &amtd.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: o.EventName, UID: types.UID(o.EventUID), CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{"phorvex.ai/creator-identity": b.DetectorIdentity, model.ConsoleTargetPodUIDAnnotation: o.TargetPodUID, b.Annotation: b.Encode(payload)}}, Spec: amtd.SecurityEventSpec{Targets: []string{Namespace + "/" + target.Name}, Rule: amtd.Rule{Source: b.Source, Type: model.AttackVectorServingCostHarvest, ThreatLevel: "high"}}}
	config := &core.ConfigMap{ObjectMeta: Meta(b.ConfigName, "config-uid"), Data: map[string]string{b.Key: b.Encode(c)}}
	stat := &core.ConfigMap{ObjectMeta: Meta(b.StatusName, "status-uid"), Data: map[string]string{b.Key: b.Encode(status)}}
	journal := &core.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: b.JournalName, Namespace: "phorvex-system", UID: "journal-uid"}, Data: map[string]string{}}
	hpa := &autoscaling.HorizontalPodAutoscaler{ObjectMeta: Meta("cost-target", "hpa-uid"), Spec: autoscaling.HorizontalPodAutoscalerSpec{MaxReplicas: 5}}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(hpa, target, proxy, dep, prs, rs, svc, backend, policy, config, stat, slice, event, journal).Build(), o
}
