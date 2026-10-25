package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	b "github.com/phorvex/phorvex/internal/servingbudget"
	bt "github.com/phorvex/phorvex/internal/servingbudget/budgettest"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	apps "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v2"
	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func throttleTest(t *testing.T) (client.Client, EnactCtx, Request) {
	t.Helper()
	t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", bt.SHA)
	t.Setenv("PHORVEX_THROTTLE_PROXY_IMAGE", bt.Image)
	c, o := bt.Fixture()
	return c, EnactCtx{Client: c, Reader: c, JournalNamespace: "phorvex-system"}, Request{Action: model.ActionThrottle, Namespace: bt.Namespace, Pod: "cost-target-test", TargetUID: o.TargetPodUID, PolicyName: o.PolicyName, PolicyUID: o.PolicyUID, PolicyGeneration: o.PolicyGeneration, OperationID: "test-operation", ServingRateBudgetObservation: o}
}

// Effective status simulates the separate proxy's periodic successful config
// reload, not an actuator-written acknowledgment. HTTP behavior is independently
// exercised by TestServingRateProxyBothDirections against a real httptest backend.
func simulateProxy(ctx context.Context, c client.Client) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			var cm, scm core.ConfigMap
			if c.Get(ctx, client.ObjectKey{Namespace: bt.Namespace, Name: b.ConfigName}, &cm) != nil || c.Get(ctx, client.ObjectKey{Namespace: bt.Namespace, Name: b.StatusName}, &scm) != nil {
				continue
			}
			contract, e := b.Parse(cm.Data[b.Key])
			if e != nil {
				continue
			}
			var s b.Status
			_ = json.Unmarshal([]byte(scm.Data[b.Key]), &s)
			s.Contract = contract
			s.UpdatedAt = time.Now()
			scm.Data[b.Key] = b.Encode(s)
			_ = c.Update(ctx, &scm)
		}
	}
}
func TestThrottleEnactRetryRollbackAndNoReplicaMutation(t *testing.T) {
	c, ec, req := throttleTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go simulateProxy(ctx, c)
	var beforePods core.PodList
	var beforeDeploy apps.DeploymentList
	var beforeHPA autoscaling.HorizontalPodAutoscalerList
	_ = c.List(ctx, &beforeHPA)
	_ = c.List(ctx, &beforePods)
	_ = c.List(ctx, &beforeDeploy)
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, ServingRateBudgetObservation: req.ServingRateBudgetObservation}
	if ok, why := throttleCapability(ctx, c, ec.JournalNamespace, target); !ok {
		t.Fatal(why)
	}
	result, e := (throttleHandler{}).Enact(ctx, ec, req)
	if e != nil || !result.Emitted {
		t.Fatalf("result=%+v err=%v", result, e)
	}
	var cm core.ConfigMap
	_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: b.ConfigName}, &cm)
	contract, e := b.Parse(cm.Data[b.Key])
	if e != nil || !contract.Enabled || contract.Baseline != 42 || contract.Reserved != 42 || contract.Burst != 42 {
		t.Fatal(contract, e)
	}
	if _, e = (throttleHandler{}).Enact(ctx, ec, req); e != nil {
		t.Fatal("retry failed", e)
	}
	if e = (throttleHandler{}).Rollback(ctx, ec, req, result.RollbackRef); e != nil {
		t.Fatal(e)
	}
	_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: b.ConfigName}, &cm)
	contract, _ = b.Parse(cm.Data[b.Key])
	if contract.Enabled || contract.Revision != 2 {
		t.Fatal("rollback state", contract)
	}
	var afterPods core.PodList
	var afterDeploy apps.DeploymentList
	var afterHPA autoscaling.HorizontalPodAutoscalerList
	_ = c.List(ctx, &afterHPA)
	_ = c.List(ctx, &afterPods)
	_ = c.List(ctx, &afterDeploy)
	if !reflect.DeepEqual(beforePods.Items, afterPods.Items) || !reflect.DeepEqual(beforeDeploy.Items, afterDeploy.Items) || !reflect.DeepEqual(beforeHPA.Items, afterHPA.Items) {
		t.Fatal("actuator changed workloads")
	}
	for _, v := range RequiredVerbs(model.ActionThrottle) {
		if v.Verb != "get" && v.Verb != "list" && v.Resource != "configmaps" {
			t.Fatalf("unexpected mutation authority: %+v", v)
		}
	}
	t.Log("ConfigMap CAS applied, proxy readback confirmed, retry safe, rollback restored; Pod/Deployment/HPA objects byte-identical")
}
func TestThrottleRefusesAuthorityDrift(t *testing.T) {
	for _, kind := range []string{"pod-uid", "policy-generation", "service-route", "source", "duplicate-proxy", "event-creator", "payload", "stale", "dry-run"} {
		t.Run(kind, func(t *testing.T) {
			c, ec, req := throttleTest(t)
			ctx := context.Background()
			switch kind {
			case "pod-uid":
				req.TargetUID = "other"
			case "policy-generation":
				req.PolicyGeneration++
			case "service-route":
				var svc core.Service
				_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: b.ServiceName}, &svc)
				svc.Spec.Selector = map[string]string{"app": "cost-target"}
				_ = c.Update(ctx, &svc)
			case "source":
				t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", "")
			case "duplicate-proxy":
				var p core.Pod
				_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: "cost-admission-test"}, &p)
				p.Name = "second-proxy"
				p.UID = "second-proxy"
				p.ResourceVersion = ""
				_ = c.Create(ctx, &p)
			case "event-creator":
				var ev amtd.SecurityEvent
				_ = c.Get(ctx, client.ObjectKey{Name: req.ServingRateBudgetObservation.EventName}, &ev)
				ev.Annotations["phorvex.ai/creator-identity"] = "untrusted"
				_ = c.Update(ctx, &ev)
			case "payload":
				req.ServingRateBudgetObservation.ObservedReqPerSec++
			case "stale":
				req.ServingRateBudgetObservation.ObservedAt = time.Now().Add(-time.Minute)
			case "dry-run":
				ec.DryRun = true
			}
			var before core.ConfigMap
			_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: b.ConfigName}, &before)
			result, e := (throttleHandler{}).Enact(ctx, ec, req)
			if e == nil && result.NoEffect != NoEffectRefused {
				t.Fatalf("did not refuse %s: %+v", kind, result)
			}
			var after core.ConfigMap
			_ = c.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: b.ConfigName}, &after)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refused operation wrote budget")
			}
		})
	}
}

func TestThrottleNativeDispatchAndAdministrativeRollback(t *testing.T) {
	c, ec, req := throttleTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go simulateProxy(ctx, c)
	req.Tenant = req.Namespace
	native := NewNativeActuator(c)
	native.Reader = c
	native.JournalNamespace = ec.JournalNamespace
	if e := native.EnsurePolicy(ctx, TenantTarget{Tenant: req.Tenant, Namespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}); e != nil {
		t.Fatal(e)
	}
	result, e := native.Actuate(ctx, req)
	if e != nil || !result.Emitted {
		t.Fatalf("native dispatch failed: %+v %v", result, e)
	}
	if e = RollbackThrottle(ctx, c, ec.JournalNamespace, "wrong-operation", req.PolicyUID); e == nil {
		t.Fatal("administrative rollback accepted another operation")
	}
	if e = RollbackThrottle(ctx, c, ec.JournalNamespace, req.OperationID, req.PolicyUID); e != nil {
		t.Fatal(e)
	}
	t.Log("native dispatch and exact-operation administrator rollback PASS")
}

type throttleLostAck struct {
	client.Client
	lost bool
}

func (c *throttleLostAck) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	e := c.Client.Update(ctx, obj, opts...)
	if e == nil && obj.GetName() == b.ConfigName && !c.lost {
		c.lost = true
		return errors.New("test: lost ConfigMap CAS acknowledgment")
	}
	return e
}
func TestThrottleLostCASAckRetainsIntentAndRetryReconciles(t *testing.T) {
	c, ec, req := throttleTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ec.Client = &throttleLostAck{Client: c}
	result, e := (throttleHandler{}).Enact(ctx, ec, req)
	if e == nil || result.NoEffect == NoEffectRefused {
		t.Fatalf("ambiguous CAS was classified as definite no-effect: %+v %v", result, e)
	}
	_, receipt, e := throttleJournal(ctx, ec)
	if e != nil || receipt.Phase != "prepared" {
		t.Fatal("lost intent", receipt, e)
	}
	go simulateProxy(ctx, c)
	// Wait for the out-of-process acknowledgment before retrying the same choice.
	if e = awaitThrottle(ctx, ec, req.Namespace, receipt.ConfigUID, "proxy-pod-uid", req.ServingRateBudgetObservation.LimiterBootID, receipt.After); e != nil {
		t.Fatal(e)
	}
	result, e = (throttleHandler{}).Enact(ctx, ec, req)
	if e != nil || result.Emitted || result.NoEffect != NoEffectReconciled {
		t.Fatalf("retry was not an honest reconciliation: %+v %v", result, e)
	}
}

func TestThrottleAutomaticReleaseClosesOnlyMatchingReceipt(t *testing.T) {
	for _, laterWriter := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact-operation", true: "later-writer"}[laterWriter], func(t *testing.T) {
			c, ec, req := throttleTest(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go simulateProxy(ctx, c)
			if result, err := (throttleHandler{}).Enact(ctx, ec, req); err != nil || !result.Emitted {
				t.Fatalf("enact=%+v %v", result, err)
			}
			_, receipt, err := throttleJournal(ctx, ec)
			if err != nil {
				t.Fatal(err)
			}
			// Proxy status owns the data-path quiet observation. The reconciler only
			// restores its protected receipt's exact budget, never an unrelated writer.
			cancel()
			time.Sleep(20 * time.Millisecond)
			var scm core.ConfigMap
			_ = c.Get(t.Context(), client.ObjectKey{Namespace: bt.Namespace, Name: b.StatusName}, &scm)
			var s b.Status
			_ = json.Unmarshal([]byte(scm.Data[b.Key]), &s)
			s.CapActive = false
			s.ReleasedAt = time.Now()
			s.ReleaseReason = "quiet-window"
			s.UpdatedAt = time.Now()
			scm.Data[b.Key] = b.Encode(s)
			_ = c.Update(t.Context(), &scm)
			if laterWriter {
				var cm core.ConfigMap
				_ = c.Get(t.Context(), client.ObjectKey{Namespace: bt.Namespace, Name: b.ConfigName}, &cm)
				changed := receipt.After
				changed.Revision++
				cm.Data[b.Key] = b.Encode(changed)
				_ = c.Update(t.Context(), &cm)
			}
			ctx2, cancel2 := context.WithCancel(t.Context())
			defer cancel2()
			go simulateProxy(ctx2, c)
			events := recoverThrottleRelease(ctx2, ec, nil)
			if len(events) != 1 {
				t.Fatalf("recovery events=%+v", events)
			}
			if laterWriter {
				if events[0].Err == nil {
					t.Fatal("automatic cleanup overwrote later writer")
				}
			} else {
				if events[0].Err != nil || events[0].Outcome != "recovered" {
					t.Fatal(events)
				}
				_, after, err := throttleJournal(ctx2, ec)
				if err != nil || after.Phase != "rolled-back" {
					t.Fatalf("receipt=%+v err=%v", after, err)
				}
			}
			t.Logf("laterWriter=%t automatic recovery outcome=%s error=%v", laterWriter, events[0].Outcome, events[0].Err)
		})
	}
}
