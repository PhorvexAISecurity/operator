// persistence-observer is the standing, independently-authenticated observer that detects
// control-plane persistence (an attacker-created, unmanaged controller whose child Pods
// RE-APPEAR after removal) and emits the trusted phorvex.attack.controller-persistence
// SecurityEvent bound to the exact owner UID. It never evicts a Pod to manufacture its
// signal; a restart or a gapped/failed inventory read discards recreation authority. The
// brain's controller-stop actuator is licensed only by this event (re-validated end to end).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/persistence"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }

func main() {
	var namespaces, operatorNamespace, identity string
	var interval, scanTimeout time.Duration
	flag.StringVar(&namespaces, "namespaces", "", "comma-separated protected namespaces to observe")
	flag.StringVar(&operatorNamespace, "operator-namespace", os.Getenv("POD_NAMESPACE"), "protected desired-state inventory + provenance namespace")
	flag.StringVar(&identity, "identity", "", "exact authenticated observer identity (system:serviceaccount:<ns>:<name>)")
	flag.DurationVar(&interval, "interval", 2*time.Second, "poll interval (>= 1s)")
	flag.DurationVar(&scanTimeout, "scan-timeout", 10*time.Second, "per-scan deadline (> 0)")
	flag.Parse()

	var scope []string
	for _, ns := range strings.Split(namespaces, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			scope = append(scope, ns)
		}
	}
	if len(scope) == 0 {
		fatalf("--namespaces is required")
	}
	if operatorNamespace == "" {
		fatalf("--operator-namespace (or POD_NAMESPACE) is required")
	}
	parts := strings.Split(identity, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		fatalf("--identity must be system:serviceaccount:<ns>:<name>")
	}
	if interval < time.Second {
		fatalf("--interval must be >= 1s")
	}
	if scanTimeout <= 0 {
		fatalf("--scan-timeout must be > 0")
	}

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			fatalf("register scheme: %v", err)
		}
	}
	rest, err := ctrlconfig.GetConfig()
	if err != nil {
		fatalf("load Kubernetes config: %v", err)
	}
	rest.QPS, rest.Burst = 10, 20
	kube, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		fatalf("create Kubernetes client: %v", err)
	}

	observer := &persistence.Observer{
		Client:            kube,
		OperatorNamespace: operatorNamespace,
		Identity:          identity,
		Namespaces:        scope,
		Interval:          interval,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("persistence-observer: identity=%s operatorNamespace=%s namespaces=%v interval=%s\n", identity, operatorNamespace, scope, interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
		created, err := observer.Scan(scanCtx, time.Now().UTC())
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "persistence-observer scan error: %v\n", err)
		}
		for _, name := range created {
			fmt.Printf("persistence observation created: %s\n", name)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
