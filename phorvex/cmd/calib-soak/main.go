/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// calib-soak runs the PHVX-74 shadow collector against live Kubernetes state
// without persisting any cluster mutation. It loads real PhorvexPolicy objects,
// forces their in-memory copies to dry-run, freezes the kill switch, and wraps
// the Kubernetes client with a local write-denial boundary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/runner"
)

var errReadOnly = errors.New("calibration soak client is read-only")

// denyWritesClient rejects mutations locally, before an HTTP request is built.
// Embedding preserves every read and scheme/mapper method from the real client.
type denyWritesClient struct{ client.Client }

func (*denyWritesClient) Create(context.Context, client.Object, ...client.CreateOption) error {
	return errReadOnly
}
func (*denyWritesClient) Update(context.Context, client.Object, ...client.UpdateOption) error {
	return errReadOnly
}
func (*denyWritesClient) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	return errReadOnly
}
func (*denyWritesClient) DeleteAllOf(context.Context, client.Object, ...client.DeleteAllOfOption) error {
	return errReadOnly
}
func (*denyWritesClient) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return errReadOnly
}
func (*denyWritesClient) Status() client.SubResourceWriter { return discardStatusWrites{} }
func (c *denyWritesClient) SubResource(name string) client.SubResourceClient {
	return &denySubResourceWrites{SubResourceClient: c.Client.SubResource(name)}
}

type denySubResourceWrites struct{ client.SubResourceClient }

// The runner publishes status after each comparison. The collector has no
// controller to serve, so status writes are acknowledged in memory and dropped.
type discardStatusWrites struct{}

func (discardStatusWrites) Create(context.Context, client.Object, client.Object, ...client.SubResourceCreateOption) error {
	return nil
}
func (discardStatusWrites) Update(context.Context, client.Object, ...client.SubResourceUpdateOption) error {
	return nil
}
func (discardStatusWrites) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return nil
}

func (*denySubResourceWrites) Create(context.Context, client.Object, client.Object, ...client.SubResourceCreateOption) error {
	return errReadOnly
}
func (*denySubResourceWrites) Update(context.Context, client.Object, ...client.SubResourceUpdateOption) error {
	return errReadOnly
}
func (*denySubResourceWrites) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return errReadOnly
}

func main() {
	var (
		kubeContext string
		epssCache   string
		outDir      string
		duration    time.Duration
		sample      time.Duration
		refresh     time.Duration
		base        time.Duration
	)
	flag.StringVar(&kubeContext, "context", "", "kubeconfig context (empty uses current context)")
	flag.StringVar(&epssCache, "epss-cache", "", "image-digest EPSS cache used by the live fleet")
	flag.StringVar(&outDir, "out", "", "required output directory for raw calibration evidence")
	flag.DurationVar(&duration, "duration", 65*time.Minute, "observation duration (65m exercises the 60m cadence candidate once)")
	flag.DurationVar(&sample, "sample", calib.DefaultSampleInterval, "snapshot sampling interval")
	flag.DurationVar(&refresh, "refresh", calib.DefaultSampleInterval, "evidence export interval")
	flag.DurationVar(&base, "base-interval", 10*time.Second, "read-only decision-loop interval")
	flag.Parse()

	if outDir == "" || duration <= 0 || sample <= 0 || refresh <= 0 || base <= 0 || sample > refresh {
		fmt.Fprintln(os.Stderr, "out is required; durations must be positive and sample must not exceed refresh")
		os.Exit(2)
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	restConfig, err := ctrlconfig.GetConfigWithContext(kubeContext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kube config:", err)
		os.Exit(1)
	}
	rawClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "kube client:", err)
		os.Exit(1)
	}
	readOnlyClient := &denyWritesClient{Client: rawClient}

	if epssCache != "" {
		if err := platform.LoadEPSSFromFile(epssCache); err != nil {
			fmt.Fprintln(os.Stderr, "EPSS cache:", err)
			os.Exit(1)
		}
	}

	var policies v1alpha1.PhorvexPolicyList
	if err := readOnlyClient.List(context.Background(), &policies); err != nil {
		fmt.Fprintln(os.Stderr, "list PhorvexPolicy:", err)
		os.Exit(1)
	}
	if len(policies.Items) == 0 {
		fmt.Fprintln(os.Stderr, "no PhorvexPolicy objects found; optimizer comparison would be unavailable")
		os.Exit(1)
	}

	log := zap.New(zap.UseDevMode(false))
	runtimeShadow := calib.NewRuntime(calib.RuntimeConfig{
		RefreshInterval: refresh,
		SampleInterval:  sample,
		Lookback:        calib.DefaultLookback,
		ExportDir:       outDir,
	}, log)
	manager := runner.NewManager(readOnlyClient, log)
	manager.BaseInterval = base
	manager.Calibration = runtimeShadow
	manager.KillSwitch = &runner.KillSwitch{Static: true}

	for i := range policies.Items {
		policy := policies.Items[i].DeepCopy()
		policy.Spec.Mode = v1alpha1.ModeDryRun
		if err := manager.Upsert(policy); err != nil {
			fmt.Fprintf(os.Stderr, "policy %s/%s: %v\n", policy.Namespace, policy.Name, err)
			os.Exit(1)
		}
	}

	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, duration)
	defer cancel()

	fmt.Printf("calibration soak: policies=%d duration=%s sample=%s refresh=%s out=%s localWriteDeny=true actuationFrozen=true\n",
		len(policies.Items), duration, sample, refresh, outDir)
	if err := manager.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "collector:", err)
		os.Exit(1)
	}
	latest := runtimeShadow.Latest()
	if latest.GeneratedAt.IsZero() {
		fmt.Fprintln(os.Stderr, "collector stopped before the first calibration snapshot")
		os.Exit(1)
	}
	if err := calib.Export(outDir, latest); err != nil {
		fmt.Fprintln(os.Stderr, "final export:", err)
		os.Exit(1)
	}
	fmt.Printf("complete: generatedAt=%s snapshotsExported=true comparisons=%d rotations=%d\n",
		latest.GeneratedAt.UTC().Format(time.RFC3339Nano), len(latest.Comparisons), len(latest.Rotations))
}
