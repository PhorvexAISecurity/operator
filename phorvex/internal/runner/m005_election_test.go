package runner

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// Embed the production classification method, while using an observable protected
// write instead of running a tenant optimizer or actuating a real workload.
type m005Probe struct {
	*Manager
	client client.Client
	name   string
	writes atomic.Int64
}

func (p *m005Probe) Start(ctx context.Context) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: "m005"}}
		err := p.client.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		if err != nil {
			err = p.client.Create(ctx, obj)
		} else {
			obj.Data = map[string]string{"tick": time.Now().String()}
			err = p.client.Update(ctx, obj)
		}
		if err == nil {
			p.writes.Add(1)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func TestM005TwoManagersAndHandoff(t *testing.T) {
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
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m005"}}); err != nil {
		t.Fatal(err)
	}
	wait := func(label string, fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if fn() {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal(label)
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled-positive-control", true: "enabled-handoff"}[enabled], func(t *testing.T) {
			var probes [2]*m005Probe
			var cancels [2]context.CancelFunc
			var done [2]chan error
			lease, renew, retry := 2*time.Second, 1500*time.Millisecond, 200*time.Millisecond
			for i, name := range []string{"a", "b"} {
				mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0", LeaderElection: enabled, LeaderElectionNamespace: "m005", LeaderElectionID: "phorvex.phorvex.ai", LeaseDuration: &lease, RenewDeadline: &renew, RetryPeriod: &retry})
				if err != nil {
					t.Fatal(err)
				}
				probes[i] = &m005Probe{Manager: &Manager{}, client: c, name: name}
				if err := mgr.Add(manager.Runnable(probes[i])); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancels[i] = cancel
				t.Cleanup(cancel)
				done[i] = make(chan error, 1)
				go func(i int) { done[i] <- mgr.Start(ctx) }(i)
			}
			if !enabled {
				wait("both disabled managers must write", func() bool { return probes[0].writes.Load() > 0 && probes[1].writes.Load() > 0 })
			} else {
				wait("leader must write", func() bool { return probes[0].writes.Load()+probes[1].writes.Load() > 0 })
				leader := 0
				if probes[1].writes.Load() > 0 {
					leader = 1
				}
				follower := 1 - leader
				time.Sleep(500 * time.Millisecond)
				if probes[follower].writes.Load() != 0 {
					t.Fatal("standby wrote before acquisition")
				}
				fault := time.Now()
				cancels[leader]()
				select {
				case err := <-done[leader]:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("leader shutdown timeout")
				}
				frozen := probes[leader].writes.Load()
				wait("standby must execute protected work after loss", func() bool { return probes[follower].writes.Load() > 0 })
				t.Logf("graceful cancel to first useful API write: %s (test timings only)", time.Since(fault))
				if probes[leader].writes.Load() != frozen {
					t.Fatal("old leader scheduled writes after shutdown")
				}
				done[leader] = nil
			}
			for i := range cancels {
				cancels[i]()
				if done[i] != nil {
					select {
					case err := <-done[i]:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(5 * time.Second):
						t.Error("shutdown timeout")
					}
				}
			}
		})
	}
}
