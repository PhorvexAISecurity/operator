package servingbudget

import (
	"context"
	"errors"
	"time"

	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type Live struct {
	Config     *core.ConfigMap
	Contract   Contract
	Status     Status
	Pod        core.Pod
	Proxy      core.Pod
	Service    core.Service
	Policy     api.PhorvexPolicy
	Deployment apps.Deployment
}

func ready(p core.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.Phase != core.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == core.PodReady && c.Status == core.ConditionTrue {
			return true
		}
	}
	return false
}
func ReadStatus(ctx context.Context, r client.Reader, ns string) (Status, error) {
	var cm core.ConfigMap
	var s Status
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: StatusName}, &cm)
	if err == nil {
		err = jsonDecode(cm.Data[Key], &s)
	}
	return s, err
}
func jsonDecode(raw string, v any) error { return decode(raw, v) }

// Validate re-reads the selecting policy, target lifetime, Service route, controller,
// singleton proxy and effective status. Nothing here writes replicas or autoscaling.
func Validate(ctx context.Context, r client.Reader, ns, podName string, o *model.ServingRateBudgetObservation, snapshotTime ...time.Time) (Live, error) {
	var l Live
	fail := func() (Live, error) { return l, errors.New("serving admission authority or epoch drift") }
	if r == nil || o == nil || ns != "costbench-opus" || o.PolicyName != "cost-defense" {
		return fail()
	}
	l.Config = &core.ConfigMap{}
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: ConfigName}, l.Config) != nil || l.Config.DeletionTimestamp != nil {
		return fail()
	}
	c, err := Parse(l.Config.Data[Key])
	if err != nil || !Approved(c) || c.Calibrating || !c.Enabled && c.Revision != o.PriorRevision {
		return fail()
	}
	l.Contract = c
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: podName}, &l.Pod) != nil || string(l.Pod.UID) != o.TargetPodUID || !ready(l.Pod) {
		return fail()
	}
	owner := metav1.GetControllerOf(&l.Pod)
	if owner == nil || string(owner.UID) != o.ControllerUID || owner.Kind != "ReplicaSet" {
		return fail()
	}
	var rs apps.ReplicaSet
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: owner.Name}, &rs) != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return fail()
	}
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: o.PolicyName}, &l.Policy) != nil || string(l.Policy.UID) != o.PolicyUID || l.Policy.Generation != o.PolicyGeneration || l.Policy.DeletionTimestamp != nil || l.Policy.Spec.IsDryRun() {
		return fail()
	}
	enabled := false
	for _, a := range l.Policy.Spec.Actions.Enabled {
		if a == api.ActionThrottle {
			enabled = true
		}
	}
	sel, e := metav1.LabelSelectorAsSelector(&l.Policy.Spec.Selector)
	if e != nil || sel.Empty() || !enabled || !sel.Matches(labels.Set(l.Pod.Labels)) {
		return fail()
	}
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: ServiceName}, &l.Service) != nil || string(l.Service.UID) != o.ServiceUID || l.Service.DeletionTimestamp != nil || len(l.Service.Spec.Selector) != 1 || l.Service.Spec.Selector["app"] != DeploymentName {
		return fail()
	}
	if len(l.Service.Spec.Ports) != 1 || l.Service.Spec.Ports[0].Port != 80 || l.Service.Spec.Ports[0].TargetPort.IntVal != 8080 || l.Service.Spec.Type == core.ServiceTypeExternalName {
		return fail()
	}
	var backend core.Service
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: BackendName}, &backend) != nil || backend.Spec.Selector["app"] != "cost-target" || len(backend.Spec.Selector) != 1 || backend.DeletionTimestamp != nil || len(backend.Spec.Ports) != 1 || backend.Spec.Ports[0].Port != 8080 || backend.Spec.Ports[0].TargetPort.IntVal != 8080 || l.Pod.Labels["app"] != "cost-target" {
		return fail()
	}
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: DeploymentName}, &l.Deployment) != nil || string(l.Deployment.UID) != o.LimiterDeploymentUID || l.Deployment.DeletionTimestamp != nil || l.Deployment.Spec.Replicas == nil || *l.Deployment.Spec.Replicas != 1 || l.Deployment.Spec.Strategy.Type != apps.RecreateDeploymentStrategyType {
		return fail()
	}
	var pods core.PodList
	if r.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app": DeploymentName}) != nil {
		return fail()
	}
	// Even an unready second live proxy could retain connections: refuse it too.
	if len(pods.Items) != 1 || !ready(pods.Items[0]) {
		return fail()
	}
	l.Proxy = pods.Items[0]
	po := metav1.GetControllerOf(&l.Proxy)
	if po == nil || po.Kind != "ReplicaSet" {
		return fail()
	}
	var prs apps.ReplicaSet
	if r.Get(ctx, client.ObjectKey{Namespace: ns, Name: po.Name}, &prs) != nil || prs.UID != po.UID {
		return fail()
	}
	d := metav1.GetControllerOf(&prs)
	if d == nil || d.UID != l.Deployment.UID {
		return fail()
	}
	if len(l.Proxy.Spec.Containers) != 1 || l.Proxy.Spec.Containers[0].Image != c.ProxyImage || l.Proxy.Spec.ServiceAccountName != "cost-admission" {
		return fail()
	}
	if string(l.Config.UID) != o.LimiterConfigMapUID || c.SourceSHA256 != o.LimiterSourceSHA256 || o.OffendingCallerScope != c.AbusiveAccount+"|"+c.Path {
		return fail()
	}
	var slices discovery.EndpointSliceList
	if r.List(ctx, &slices, client.InNamespace(ns), client.MatchingLabels{discovery.LabelServiceName: ServiceName}) != nil {
		return fail()
	}
	n := 0
	for _, sl := range slices.Items {
		for _, ep := range sl.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				if ep.TargetRef == nil || ep.TargetRef.UID != l.Proxy.UID {
					return fail()
				}
				n++
			}
		}
	}
	if n != 1 {
		return fail()
	}
	l.Status, err = ReadStatus(ctx, r, ns)
	// Live authority is checked when read, after the preceding API calls. Ingest
	// uses its frozen snapshot clock with a bounded status-write skew so replay
	// stays deterministic even when the proxy publishes during snapshot assembly.
	now, futureMargin := time.Now(), time.Duration(0)
	if len(snapshotTime) > 0 {
		now, futureMargin = snapshotTime[0], 2*time.Second
	}
	if err != nil || !l.Status.fresh(now, futureMargin) || l.Status.PodUID != string(l.Proxy.UID) || l.Status.ConfigUID != string(l.Config.UID) || l.Status.Contract != c || l.Status.BootID != o.LimiterBootID || l.Status.CalibrationEnd.IsZero() || l.Status.Baseline != o.BaselineReqPerSec || l.Status.Reserved != o.ReservedReqPerSec {
		return fail()
	}
	return l, nil
}
