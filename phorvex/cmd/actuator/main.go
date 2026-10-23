// Command actuator serves the Phorvex actuator over gRPC (ADR-0001). The manager
// reaches it with --actuator-endpoint; without that flag the manager acts in
// process.
//
// The actuator is the only service that writes to workloads. It owns the backend
// PHORVEX_ACTUATOR selects, the backend's operation journals, the
// retained-quarantine ledger and the standing route policy. Its ServiceAccount
// holds the actuation RBAC: it checks that RBAC before it serves and answers the
// capability gate's access reviews for it. Run one replica, replaced with the
// Recreate strategy: the native backend keeps its policy bindings in memory, and
// the manager restores them through standing-policy maintenance after a restart.
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
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"phorvex.ai/libs/logging"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/cmd/internal/actuatorconfig"
	"github.com/phorvex/phorvex/cmd/internal/grpctlsconfig"
	"github.com/phorvex/phorvex/cmd/internal/policyscope"
	"github.com/phorvex/phorvex/cmd/internal/trustconfig"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorpb"
	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/startupauthz"
	"github.com/phorvex/phorvex/internal/wire"
)

type config struct {
	listen, metricsAddr, probeAddr string
	tls                            grpctlsconfig.Config
	shutdownGrace                  time.Duration
	operatorNamespace              string
	trust                          trustconfig.Trust
	scope                          policyscope.Scope
	actuator                       actuatorconfig.Flags
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
	cfg := config{log: logging.Options{Service: "phorvex-actuator", Version: buildinfo.Current().GitSHA}}
	flag.StringVar(&cfg.listen, "listen", ":9090", "Address the gRPC actuator service binds to.")
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "Address the metric endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "Address the health probe binds to.")
	flag.DurationVar(&cfg.shutdownGrace, "shutdown-grace", 20*time.Second, "Time in-flight calls get to finish on shutdown.")
	flag.StringVar(&cfg.operatorNamespace, "operator-namespace", os.Getenv("POD_NAMESPACE"), "Namespace holding the protected-operation journals and the quarantine ledger; must match the manager's.")
	cfg.trust.Register(flag.CommandLine)
	cfg.scope.Register(flag.CommandLine)
	cfg.actuator.Register(flag.CommandLine)
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
		logger.Error("actuator service cannot listen", "listen", cfg.listen, "error", err)
		os.Exit(1)
	}
	if err := run(ctrl.SetupSignalHandler(), cfg, restConfig, lis, logger); err != nil {
		logger.Error("actuator service stopped", "error", err)
		os.Exit(1)
	}
}

// run serves the actuator on lis until ctx ends. Every configuration problem is
// refused before the cluster is read or anything is served.
func run(ctx context.Context, cfg config, restConfig *rest.Config, lis net.Listener, logger *slog.Logger) error {
	if err := cfg.actuator.ValidateImage(); err != nil {
		return err
	}
	if err := cfg.actuator.ValidateBound(); err != nil {
		return err
	}
	policyNamespaces, err := cfg.scope.List()
	if err != nil {
		return err
	}
	backend, err := actuator.ResolveBackendFromEnv()
	if err != nil {
		return fmt.Errorf("invalid actuator configuration: %w", err)
	}
	logger.Info("actuator configuration resolved", "actuator", string(backend.Backend), "source", backend.Origin())
	settings, err := cfg.actuator.Load(cfg.operatorNamespace)
	if err != nil {
		return err
	}
	voiceAdmission, err := actuatorconfig.VoiceAdmissionEnabled()
	if err != nil {
		return err
	}
	if err := ingest.ConfigureEndpointLeaseApprovedAuthority(cfg.trust.EndpointLeaseApprovedSource,
		cfg.trust.EndpointLeaseApprovedProxyImage, cfg.trust.EndpointLeaseApprovedEngineImage); err != nil {
		return fmt.Errorf("endpoint lease source configuration invalid: %w", err)
	}
	if err := eventtrust.ConfigureInjector(cfg.trust.InjectorIdentity); err != nil {
		return err
	}
	actuator.ConfigureAdapterDetectorIdentities(cfg.trust.Detectors().List())

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                  newScheme(),
		Cache:                   policyscope.Cache(policyNamespaces), // the backends read the scope's policies only
		Metrics:                 metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress:  cfg.probeAddr,
		LeaderElection:          false,
		GracefulShutdownTimeout: &cfg.shutdownGrace,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("clientset: %w", err)
	}
	report, err := startupauthz.Check(ctx, mgr.GetAPIReader(), cs.AuthorizationV1().SelfSubjectAccessReviews(),
		cfg.actuator.Preflight(settings, backend.Backend, cfg.operatorNamespace, policyNamespaces))
	if err != nil {
		return fmt.Errorf("startup authorization preflight failed: %w", err)
	}
	logger.Info("startup authorization preflight passed",
		"policies", report.Policies, "activePolicies", report.ActivePolicies,
		"dryRunPolicies", report.DryRunPolicies, "namespaces", report.Namespaces,
		"requirements", report.Requirements, "noPolicies", report.NoPolicies)

	act, err := actuator.New(backend.Backend, mgr.GetClient())
	if err != nil {
		return fmt.Errorf("cannot construct the resolved actuator: %w", err)
	}
	settings.Configure(act, mgr.GetAPIReader(), cfg.operatorNamespace, voiceAdmission, cfg.trust)
	capacity, err := actuator.NewQuarantineCapacity(mgr.GetClient(), mgr.GetAPIReader(), cfg.operatorNamespace, cfg.actuator.MaxRetainedQuarantines)
	if err != nil {
		return fmt.Errorf("quarantine capacity guard unavailable: %w", err)
	}
	if err := cfg.actuator.MIG.Wire(restConfig, cs); err != nil {
		return fmt.Errorf("invalid MIG node-exec configuration: %w", err)
	}
	local := &actuatorsvc.Local{Actuator: act, Capacity: capacity, Reader: mgr.GetAPIReader(),
		OperatorNamespace: cfg.operatorNamespace, Access: authz.NewChecker(cs, authz.DefaultTTL)}
	shared := actuatorconfig.Shared(cfg.operatorNamespace, cfg.trust, policyNamespaces)
	service, err := actuatorsvc.NewServer(local, shared.SHA256())
	if err != nil {
		return err
	}

	transport, err := cfg.tls.ServerOptions()
	if err != nil {
		return err
	}
	server := grpc.NewServer(append(append(metrics.GRPCServerOptions(), transport...),
		grpc.MaxRecvMsgSize(wire.MaxMessageBytes),
		grpc.MaxSendMsgSize(wire.MaxMessageBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)...)
	actuatorpb.RegisterActuatorServiceServer(server, service)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		healthServer.SetServingStatus(actuatorpb.ActuatorService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
		logger.Info("actuator service ready", "listen", lis.Addr().String(), "configSHA256", shared.SHA256(),
			"contractVersion", actuatorapi.ContractVersion, "backend", string(backend.Backend), "mutualTLS", cfg.tls.Enabled())
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
