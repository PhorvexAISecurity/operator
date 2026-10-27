package servingbudget

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Detector requires a measured nonzero quiet baseline AND a full sustained window
// of fresh attempted-rate deltas. Missing/reset/stale/calm samples reset the run.
// Attempted counters keep the threat measurable after admission is capped.
type Detector struct {
	Now           func() time.Time
	emitted       map[string]time.Time
	previous      *Status
	since         time.Time
	windowMinimum float64
}

func (d *Detector) Observe(s Status, now time.Time) (float64, bool) {
	prev := d.previous
	d.previous = &s
	if !s.Fresh(now) || s.Contract.Calibrating || !Positive(s.Baseline) || !Positive(s.Reserved) || s.CalibrationEnd.IsZero() {
		d.since = time.Time{}
		return 0, false
	}
	if prev == nil || prev.BootID != s.BootID || prev.ConfigUID != s.ConfigUID || prev.Baseline != s.Baseline || prev.Reserved != s.Reserved || s.Abusive.Attempted < prev.Abusive.Attempted {
		d.since = time.Time{}
		return 0, false
	}
	dt := s.UpdatedAt.Sub(prev.UpdatedAt).Seconds()
	if dt <= 0 || dt > 10 {
		d.since = time.Time{}
		return 0, false
	}
	rate := float64(s.Abusive.Attempted-prev.Abusive.Attempted) / dt
	if rate <= 3*s.Baseline {
		d.since = time.Time{}
		return rate, false
	}
	if d.since.IsZero() {
		d.since = prev.UpdatedAt
		d.windowMinimum = rate
	}
	if rate < d.windowMinimum {
		d.windowMinimum = rate
	}
	return d.windowMinimum, s.UpdatedAt.Sub(d.since) >= Horizon
}

func DetectOnce(ctx context.Context, c client.Client, d *Detector, ns, policyName string) error {
	if ns != "costbench-opus" {
		return errors.New("unsupported detector namespace")
	}
	s, e := ReadStatus(ctx, c, ns)
	if e != nil {
		d.previous = nil
		d.since = time.Time{}
		return e
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	rate, fired := d.Observe(s, now)
	if !fired {
		return nil
	}
	// Seed dedupe from authenticated stored events after restart. A local backoff
	// alone would permit another replica/restart to re-fire within 30 seconds.
	if d.emitted == nil {
		var prior amtd.SecurityEventList
		if e = c.List(ctx, &prior, client.MatchingLabels{EventLabel: "true"}); e != nil {
			return e
		}
		d.emitted = map[string]time.Time{}
		for _, ev := range prior.Items {
			if ev.Annotations["phorvex.ai/creator-identity"] != DetectorIdentity || ev.CreationTimestamp.IsZero() || ev.CreationTimestamp.Time.After(now) || now.Sub(ev.CreationTimestamp.Time) >= EventRefresh {
				continue
			}
			o, err := ParseObservation(ev.Annotations[Annotation])
			if err != nil {
				continue
			}
			key := o.TargetPodUID + "|" + o.LimiterBootID + "|" + o.OffendingCallerScope
			if ev.CreationTimestamp.Time.After(d.emitted[key]) {
				d.emitted[key] = ev.CreationTimestamp.Time
			}
		}
	}
	// Bound memory as old Pod/boot incarnations leave the fixture.
	for key, at := range d.emitted {
		if now.Sub(at) >= Horizon {
			delete(d.emitted, key)
		}
	}
	var cm core.ConfigMap
	var dep apps.Deployment
	var svc core.Service
	var pol api.PhorvexPolicy
	for _, entry := range []struct {
		name string
		obj  client.Object
	}{{ConfigName, &cm}, {DeploymentName, &dep}, {ServiceName, &svc}, {policyName, &pol}} {
		if e = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: entry.name}, entry.obj); e != nil {
			return e
		}
	}
	if !Approved(s.Contract) {
		return errors.New("detector source approval unavailable")
	}
	var pods core.PodList
	if e = c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app": "cost-target"}); e != nil {
		return e
	}
	for _, pod := range pods.Items {
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || !ready(pod) {
			continue
		}
		key := string(pod.UID) + "|" + s.BootID + "|" + s.Contract.AbusiveAccount + "|" + s.Contract.Path
		if at, ok := d.emitted[key]; ok && now.Sub(at) < EventRefresh {
			continue
		}
		o := &model.ServingRateBudgetObservation{EventName: "pending", EventUID: "pending", CreatorIdentity: DetectorIdentity, ScenarioID: "aml-t0034-cost-harvest", EvidenceSource: "AUTHORITATIVE_PROXY", PolicyName: pol.Name, PolicyUID: string(pol.UID), PolicyGeneration: pol.Generation, TargetPodUID: string(pod.UID), ControllerUID: string(owner.UID), ServiceUID: string(svc.UID), LimiterDeploymentUID: string(dep.UID), LimiterConfigMapUID: string(cm.UID), LimiterSourceSHA256: s.Contract.SourceSHA256, LimiterBootID: s.BootID, PriorRevision: s.Contract.Revision, OffendingCallerScope: s.Contract.AbusiveAccount + "|" + s.Contract.Path, BaselineReqPerSec: s.Baseline, ReservedReqPerSec: s.Reserved, ObservedReqPerSec: rate, WindowSeconds: 60, ObservedAt: s.UpdatedAt}
		// Only injected-clock replay passes a frozen time. Live detection must
		// validate status freshness at the end of its authority reads.
		var snapshotTime []time.Time
		if d.Now != nil {
			snapshotTime = []time.Time{now}
		}
		if _, e = Validate(ctx, c, ns, pod.Name, o, snapshotTime...); e != nil {
			return e
		}
		// Create fresh immutable evidence; never update an admitted event. The API
		// admission webhook stamps the real caller. No creator annotation is supplied.
		o.EventName = ""
		o.EventUID = ""
		o.CreatorIdentity = ""
		score := "1"
		event := &amtd.SecurityEvent{ObjectMeta: metav1.ObjectMeta{GenerateName: "cost-load-", Labels: map[string]string{EventLabel: "true", "app.kubernetes.io/managed-by": "phorvex"}, Annotations: map[string]string{model.ConsoleTargetPodUIDAnnotation: string(pod.UID), Annotation: Encode(o)}}, Spec: amtd.SecurityEventSpec{Targets: []string{ns + "/" + pod.Name}, Rule: amtd.Rule{Type: model.AttackVectorServingCostHarvest, Source: Source, ThreatLevel: "high"}, Description: "Sustained attributable serving load exceeds measured quiet baseline", AnomalyScore: &score, Metrics: map[string]string{"baselineReqPerSec": fmt.Sprint(s.Baseline), "observedReqPerSec": fmt.Sprint(rate), "reservedReqPerSec": fmt.Sprint(s.Reserved), "windowSeconds": "60"}}}
		if e = c.Create(ctx, event); e != nil {
			return e
		}
		d.emitted[key] = now
	}
	return nil
}
