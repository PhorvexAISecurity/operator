// Command sensor serves the Phorvex cluster projection over gRPC (ADR-0001). The
// manager reaches it with --sensor-endpoint; without that flag the manager
// observes the cluster in process.
//
// The sensor reads the cluster and never writes it. It lists the inventories
// through an informer cache and reads boundary evidence (SecurityEvents, Phoenix
// receipts, the live object bindings) directly from the API server. It holds no
// state but caches and the telemetry source's previous samples, which its rates
// are derived from, so it runs as one replica.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"phorvex.ai/libs/logging"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/cmd/internal/grpctlsconfig"
	"github.com/phorvex/phorvex/cmd/internal/policyscope"
	"github.com/phorvex/phorvex/cmd/internal/sensorconfig"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/ingest"
	phorvexmetrics "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorpb"
	"github.com/phorvex/phorvex/internal/sensorsvc"
	"github.com/phorvex/phorvex/internal/wire"
)

type config struct {
	listen, metricsAddr, probeAddr string
	tls                            grpctlsconfig.Config
	shutdownGrace                  time.Duration
	sensor                         sensorconfig.Flags
	log                            logging.Options
}

func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(amtdv1beta1.AddToScheme(scheme))
	return scheme
}

func main() {
	cfg := config{log: logging.Options{Service: "phorvex-sensor", Version: buildinfo.Current().GitSHA}}
	flag.StringVar(&cfg.listen, "listen", ":9090", "Address the gRPC sensor service binds to.")
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "Address the metric endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "Address the health probe binds to.")
	flag.DurationVar(&cfg.shutdownGrace, "shutdown-grace", 20*time.Second, "Time in-flight observations get to finish on shutdown.")
	cfg.sensor.Register(flag.CommandLine)
	logging.RegisterFlags(flag.CommandLine, &cfg.log)
	cfg.tls.RegisterServer(flag.CommandLine)
	flag.Parse()

	logger, err := logging.New(os.Stderr, cfg.log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	slog.SetDefault(logger)
	ctrl.SetLogger(logging.Logr(logger))
	klog.SetLogger(logging.Logr(logger).WithName("client-go"))

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		logger.Error("no Kubernetes configuration", "error", err)
		os.Exit(1)
	}
	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		logger.Error("sensor service cannot listen", "listen", cfg.listen, "error", err)
		os.Exit(1)
	}
	if err := run(ctrl.SetupSignalHandler(), cfg, restConfig, lis, logger); err != nil {
		logger.Error("sensor service stopped", "error", err)
		os.Exit(1)
	}
}

// run serves the sensor on lis until ctx ends.
func run(ctx context.Context, cfg config, restConfig *rest.Config, lis net.Listener, logger *slog.Logger) error {
	log := logging.Logr(logger)
	if err := cfg.sensor.ApplyTrust(); err != nil {
		return err
	}
	policyNamespaces, err := cfg.sensor.Scope.List()
	if err != nil {
		return err
	}
	pcie, err := ingest.ParsePCIeClassTable(cfg.sensor.PCIeClassTable)
	if err != nil {
		return fmt.Errorf("invalid --pcie-class-table: %w", err)
	}
	if err := cfg.sensor.EPSS.Configure(log); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                  newScheme(),
		Cache:                   policyscope.Cache(policyNamespaces), // a snapshot lists the scope's policies only
		Metrics:                 metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress:  cfg.probeAddr,
		LeaderElection:          false,
		GracefulShutdownTimeout: &cfg.shutdownGrace,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	if err := cfg.sensor.VerifyIdentityPolicy(ctx, mgr.GetAPIReader()); err != nil {
		return err
	}
	if refresher := cfg.sensor.EPSS.Refresher(mgr.GetAPIReader(), log); refresher != nil {
		if err := mgr.Add(refresher); err != nil {
			return fmt.Errorf("epss refresher: %w", err)
		}
	}
	metrics, _ := ingest.SourceRegistry.Default()
	if cfg.sensor.PrometheusURL != "" {
		metrics = ingest.NewPromHTTP(cfg.sensor.PrometheusURL, nil)
	}
	local := &sensorsvc.Local{Client: mgr.GetClient(), OwnershipReader: mgr.GetAPIReader(), BoundaryReader: mgr.GetAPIReader(),
		PromURL: cfg.sensor.PrometheusURL, PCIeClasses: pcie, Metrics: metrics}
	sensorConfig := cfg.sensor.Describe()

	transport, err := cfg.tls.ServerOptions()
	if err != nil {
		return err
	}
	server := grpc.NewServer(append(append(phorvexmetrics.GRPCServerOptions(), transport...),
		grpc.MaxRecvMsgSize(wire.MaxMessageBytes),
		grpc.MaxSendMsgSize(wire.MaxMessageBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)...)
	sensorpb.RegisterSensorServiceServer(server, sensorsvc.NewServer(local, sensorConfig.SHA256(), local.TelemetrySource()))
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		healthServer.SetServingStatus(sensorpb.SensorService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
		logger.Info("sensor service ready", "listen", lis.Addr().String(), "configSHA256", sensorConfig.SHA256(),
			"contractVersion", sensorapi.ContractVersion, "telemetrySource", local.TelemetrySource(), "mutualTLS", cfg.tls.Enabled())
		errs := make(chan error, 1)
		go func() { errs <- server.Serve(lis) }()
		select {
		case <-ctx.Done():
		case err := <-errs:
			return err
		}
		healthServer.Shutdown()
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(cfg.shutdownGrace):
			server.Stop()
		}
		return nil
	})); err != nil {
		return err
	}
	return mgr.Start(ctx)
}
