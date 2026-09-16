package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
)

// m127PausedWatch models the bounded informer-delay window deterministically: the
// cache performs a real API List and then receives no watch update. The API reader
// still performs a fresh GET against the same real API server.
type m127PausedWatch struct{ toolscache.ListerWatcher }

func (m127PausedWatch) Watch(metav1.ListOptions) (watch.Interface, error) {
	return watch.NewRaceFreeFake(), nil
}

func TestM127RealAPIDirectReaderClosesCachedDispatchWindow(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m127"}}); err != nil {
		t.Fatal(err)
	}
	sentinel := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "m127", Name: DefaultKillSwitchName},
		Data:       map[string]string{"engaged": "false"},
	}
	if err := direct.Create(ctx, sentinel); err != nil {
		t.Fatal(err)
	}

	informerCache, err := cache.New(cfg, cache.Options{
		Scheme: scheme,
		NewInformer: func(lw toolscache.ListerWatcher, obj runtime.Object, resync time.Duration, indexers toolscache.Indexers) toolscache.SharedIndexInformer {
			return toolscache.NewSharedIndexInformer(m127PausedWatch{ListerWatcher: lw}, obj, resync, indexers)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := informerCache.GetInformer(ctx, &corev1.ConfigMap{}); err != nil {
		t.Fatal(err)
	}
	cacheCtx, stopCache := context.WithCancel(context.Background())
	cacheDone := make(chan error, 1)
	go func() { cacheDone <- informerCache.Start(cacheCtx) }()
	t.Cleanup(func() {
		stopCache()
		select {
		case err := <-cacheDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("cache shutdown timed out")
		}
	})
	if !informerCache.WaitForCacheSync(ctx) {
		t.Fatal("ConfigMap cache did not sync its initial real API list")
	}
	if got := (&KillSwitch{Client: informerCache, Namespace: "m127"}).Observe(ctx); got.Cause != KillSwitchSentinelDisengaged {
		t.Fatalf("initial cached positive control = %+v", got)
	}

	var current corev1.ConfigMap
	if err := direct.Get(ctx, client.ObjectKeyFromObject(sentinel), &current); err != nil {
		t.Fatal(err)
	}
	current.Data["engaged"] = "true"
	if err := direct.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if got := (&KillSwitch{Client: direct, Namespace: "m127"}).Observe(ctx); !got.Engaged || got.Cause != KillSwitchSentinelEngaged {
		t.Fatalf("direct API reader did not observe real sentinel write: %+v", got)
	}
	if got := (&KillSwitch{Client: informerCache, Namespace: "m127"}).Observe(ctx); got.Engaged || got.Cause != KillSwitchSentinelDisengaged {
		t.Fatalf("paused cache negative control unexpectedly observed update: %+v", got)
	}

	var httpCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	newHands := func() *m127BoundaryActuator {
		hands := &m127BoundaryActuator{}
		hands.actuate = func(dispatchCtx context.Context, _ actuator.Request) (actuator.Result, error) {
			req, err := http.NewRequestWithContext(dispatchCtx, http.MethodPost, server.URL, nil)
			if err != nil {
				return actuator.Result{}, err
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				return actuator.Result{}, err
			}
			defer resp.Body.Close()
			return actuator.Result{Emitted: resp.StatusCode == http.StatusAccepted}, nil
		}
		return hands
	}
	pol := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	directHands := newHands()
	directManager := &Manager{Actuator: directHands, KillSwitch: &KillSwitch{Client: direct, Namespace: "m127"}, Log: logr.Discard()}
	directDecision := tracedSelectedDecision()
	if got := directManager.actuate(ctx, &policyEntry{namespace: "ns"}, pol, directDecision, m127FeasibleViews("p1")); got != 0 || directHands.actuateCalls != 0 || httpCalls.Load() != 0 {
		t.Fatalf("direct API boundary dispatched after engagement: got=%d dispatches=%d HTTP=%d", got, directHands.actuateCalls, httpCalls.Load())
	}
	if directDecision[0].KillSwitchCause != string(KillSwitchSentinelEngaged) || directDecision[0].Trace.DispatchOutcome != model.DispatchNotAttempted {
		t.Fatalf("direct refusal evidence = %+v", directDecision[0])
	}

	cachedHands := newHands()
	cachedManager := &Manager{
		Actuator: cachedHands, KillSwitch: &KillSwitch{Client: informerCache, Namespace: "m127"},
		Intents: exposure.NewIntents(), Log: logr.Discard(),
	}
	cachedDecision := tracedSelectedDecision()
	if got := cachedManager.actuate(ctx, &policyEntry{namespace: "ns"}, pol, cachedDecision, m127FeasibleViews("p1")); got != 1 || cachedHands.actuateCalls != 1 || httpCalls.Load() != 1 {
		t.Fatalf("stale cached-reader negative control got=%d dispatches=%d HTTP=%d", got, cachedHands.actuateCalls, httpCalls.Load())
	}
}
