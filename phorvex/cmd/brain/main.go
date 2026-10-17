// Command brain serves the Phorvex decision engine over gRPC (ADR-0001). The
// manager reaches it with --brain-endpoint; without that flag the manager runs
// the same engine in process.
//
// The brain is stateful (cost learning, kill-chain stage clocks, retired owners)
// and must run as exactly one replica. It holds no Kubernetes credentials: every
// capability question it asks is answered by the dispatcher over the Decide
// stream. Math Lab capture, when configured, records here.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"phorvex.ai/libs/logging"

	"github.com/phorvex/phorvex/cmd/internal/decisionconfig"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/brainsvc"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/metrics"
)

type config struct {
	listen, metricsAddr, probeAddr string
	engine                         string
	gpuEnvelopeMax                 float64
	flowClasses                    string
	mathLabPolicies, mathLabDir    string
	mathLabMaxBytes                int64
	mathLabMaxSnapshotBytes        int
	shutdownGrace                  time.Duration
	log                            logging.Options
}

func main() {
	cfg := config{log: logging.Options{Service: "phorvex-brain", Version: buildinfo.Current().GitSHA}}
	flag.StringVar(&cfg.listen, "listen", ":9090", "Address the gRPC brain service binds to.")
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "Address the metric endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "Address the health probe binds to.")
	flag.StringVar(&cfg.engine, "engine", "p1", "Decision engine; must match the manager's --engine.")
	flag.Float64Var(&cfg.gpuEnvelopeMax, "gpu-envelope-max", cost.DefaultGPUEnvelopeMax, "Normalized [0,1] GPU reload/warm-up envelope; must match the manager's --gpu-envelope-max.")
	flag.StringVar(&cfg.flowClasses, "flow-residual-classes", os.Getenv("PHORVEX_FLOW_RESIDUAL_CLASSES"), "Comma-separated workload classes whose flow residual is activated; must match the manager's --flow-residual-classes.")
	flag.StringVar(&cfg.mathLabPolicies, "math-lab-capture-policies", "", "Comma-separated namespace/name PhorvexPolicies whose decision ticks are recorded as replayable Math Lab snapshots. Empty records nothing.")
	flag.StringVar(&cfg.mathLabDir, "math-lab-capture-dir", "", "[math-lab-capture-policies] private directory for the bounded snapshot store.")
	flag.Int64Var(&cfg.mathLabMaxBytes, "math-lab-capture-max-bytes", 1<<30, "[math-lab-capture-policies] byte bound of the snapshot store; the oldest snapshots are evicted first.")
	flag.IntVar(&cfg.mathLabMaxSnapshotBytes, "math-lab-capture-max-snapshot-bytes", mathlab.DefaultMaxSnapshotBytes, "[math-lab-capture-policies] uncompressed bound of one snapshot.")
	flag.DurationVar(&cfg.shutdownGrace, "shutdown-grace", 20*time.Second, "Time in-flight evaluations get to finish on shutdown.")
	logging.RegisterFlags(flag.CommandLine, &cfg.log)
	flag.Parse()

	logger, err := logging.New(os.Stderr, cfg.log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		logger.Error("brain service cannot listen", "listen", cfg.listen, "error", err)
		os.Exit(1)
	}
	if err := run(ctx, cfg, lis, logger); err != nil {
		logger.Error("brain service stopped", "error", err)
		os.Exit(1)
	}
}

// run serves the brain on lis until ctx ends.
func run(ctx context.Context, cfg config, lis net.Listener, logger *slog.Logger) error {
	optimizer, err := decisionconfig.Apply(cfg.engine, cfg.gpuEnvelopeMax, cfg.flowClasses)
	if err != nil {
		return err
	}
	decisionConfig, err := decisionconfig.Describe(optimizer, cfg.gpuEnvelopeMax, cfg.flowClasses)
	if err != nil {
		return err
	}
	recorder, store, err := openMathLab(cfg)
	if err != nil {
		return err
	}
	if store != nil {
		go store.Run(ctx)
		logger.Info("math-lab decision capture enabled", "policies", cfg.mathLabPolicies, "dir", cfg.mathLabDir)
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(brainpb.MaxMessageBytes),
		grpc.MaxSendMsgSize(brainpb.MaxMessageBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	brainpb.RegisterBrainServiceServer(server, brainsvc.NewServer(brainsvc.NewLocal(optimizer, recorder), decisionConfig.SHA256()))
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus(brainpb.BrainService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	httpServers := []*http.Server{
		{Addr: cfg.metricsAddr, Handler: metricsMux(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: cfg.probeAddr, Handler: probeMux(), ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, 1+len(httpServers))
	for _, srv := range httpServers {
		go func(srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}(srv)
	}
	go func() { errs <- server.Serve(lis) }()
	logger.Info("brain service ready", "listen", lis.Addr().String(), "engine", optimizer.Name(),
		"decisionConfigSHA256", decisionConfig.SHA256(), "contractVersion", brainapi.ContractVersion)

	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() { server.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(cfg.shutdownGrace):
		server.Stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range httpServers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return err
}

func openMathLab(cfg config) (*mathlab.Recorder, *mathlab.Store, error) {
	if strings.TrimSpace(cfg.mathLabPolicies) == "" {
		return nil, nil, nil
	}
	store, err := mathlab.OpenStore(cfg.mathLabDir, cfg.mathLabMaxBytes, 4, func(st mathlab.StoreStats) {
		metrics.RecordMathLabStore(st.Files, st.Bytes, st.Evicted, st.Failed)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("math-lab snapshot store: %w", err)
	}
	processConfig := map[string]string{
		"engine": cfg.engine, "gpu-envelope-max": strconv.FormatFloat(cfg.gpuEnvelopeMax, 'g', -1, 64),
		"flow-residual-classes": cfg.flowClasses, "recon-profile": decisionconfig.ReconProfile,
	}
	recorder, err := mathlab.NewRecorder(mathlab.Config{Policies: strings.Split(cfg.mathLabPolicies, ","),
		MaxSnapshotBytes: cfg.mathLabMaxSnapshotBytes, ProcessConfig: processConfig, GPUEnvelopeMax: cfg.gpuEnvelopeMax},
		store, metrics.RecordMathLabCapture)
	if err != nil {
		return nil, nil, fmt.Errorf("math-lab capture: %w", err)
	}
	return recorder, store, nil
}

func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(crmetrics.Registry, promhttp.HandlerOpts{}))
	return mux
}

func probeMux() *http.ServeMux {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	mux.HandleFunc("/healthz", ok)
	mux.HandleFunc("/readyz", ok)
	return mux
}
