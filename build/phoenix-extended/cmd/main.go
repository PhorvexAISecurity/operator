/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package main

import (
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"github.com/r6security/phoenix/internal/controller"
	//+kubebuilder:scaffold:imports

	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(amtdv1beta1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var enableBaselineAdmission bool
	var enableExtendedControllers bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableBaselineAdmission, "enable-baseline-admission-webhook", false,
		"Enable the baseline admission webhook. Requires serving certificates mounted at the controller-runtime webhook certificate path.")
	flag.BoolVar(&enableExtendedControllers, "enable-extended-controllers", false,
		"Enable controllers that require the extended Phoenix CRDs and RBAC permissions.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	managerOptions := ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress:    metricsAddr,
			SecureServing:  true,
			FilterProvider: filters.WithAuthenticationAndAuthorization,
		},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "548c5e7b.r6security.com",
		LeaderElectionReleaseOnCancel: true, // Enable to allow fast leader transitions
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}
	if enableBaselineAdmission {
		managerOptions.WebhookServer = webhook.NewServer(webhook.Options{Port: 9443})
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.AdaptiveMovingTargetDefenseReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AdaptiveMovingTargetDefense")
		os.Exit(1)
	}
	if err = (&controller.PodReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}
	if err = (&controller.SecurityEventReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecurityEvent")
		os.Exit(1)
	}
	if err = (&controller.NIMReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Policy: controller.DefaultNIMPolicy(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NIM")
		os.Exit(1)
	}
	if enableExtendedControllers {
		// ContextMutationPolicy thin status reconciler (D7g): records selected-pod count,
		// resolved-mutation summary and the GatekeeperViolation no-emitter advisory. It
		// does NOT rotate — rotation flows through AMTD Strategy[] -> SecurityEvent ->
		// Rotate, and a Rotate's PolicyRef{Kind:"ContextMutationPolicy"} resolves through
		// the SAME MutationApplier. The CMP type registers in the scheme via
		// amtdv1beta1.AddToScheme (same group/SchemeBuilder), so no extra scheme line is
		// needed here.
		if err = (&controller.ContextMutationPolicyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "ContextMutationPolicy")
			os.Exit(1)
		}
		// WarmInferenceSet warm-pool / LeaderWorkerSet control plane (cap#2, D11/D12).
		// CLASS-B maintenance keeps N warm pods + one leader + the leader-selecting
		// Service; a matched WarmSwap action sets Spec.SwapRequest and this reconciler
		// progresses the restart-safe Ready->flip->drain->retire->rewarm cutover. It does
		// NOT self-initiate a swap (arch §1.3 invariant). The WarmInferenceSet type
		// registers in the scheme via amtdv1beta1.AddToScheme (same group), so no extra
		// scheme line is needed.
		if err = (&controller.WarmInferenceSetReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "WarmInferenceSet")
			os.Exit(1)
		}
		// BaselineDrift reconciler (cap#6, D6/D6g): RECORDS+VERIFIES the pinned digests
		// (Status.LastVerifiedTime/PinnedDigests/BaselineVerified; registry/Rekor/key
		// blip -> VerificationUnavailable + reuse cached last-good) and DETECTS drift on
		// the baseline-governed pods, EMITTING a Type:'drift' SecurityEvent with Evidence.
		// It does NOT act directly — the matcher routes the drift event to a Regenerate or
		// (default) Quarantine action. The WorkloadBaseline type registers in the scheme
		// via amtdv1beta1.AddToScheme (same group), so no extra scheme line is needed.
		if err = (&controller.BaselineDriftReconciler{
			Client:            mgr.GetClient(),
			Scheme:            mgr.GetScheme(),
			OperatorNamespace: os.Getenv("POD_NAMESPACE"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "BaselineDrift")
			os.Exit(1)
		}
	}
	// baselineAdmission webhook (cap#6, :9443, fail-CLOSED): a validating admission
	// handler that DENIES unsigned/unverifiable/un-pinned images when a governing
	// WorkloadBaseline's AdmissionEnforce=true. Registered on the already-running
	// :9443 webhook server. NOTE: a locally-run manager's webhook is hard for the kind
	// apiserver to reach (host/WSL2 networking); the HANDLER is proven by unit/envtest
	// and the PRIMARY live proof is the reconciler-detect + Regenerate-restore path.
	if enableBaselineAdmission {
		if err = controller.RegisterBaselineAdmission(mgr); err != nil {
			setupLog.Error(err, "unable to register webhook", "webhook", "baselineAdmission")
			os.Exit(1)
		}
	} else {
		setupLog.Info("baseline admission webhook disabled; enable only with serving certificates installed")
	}
	if enableExtendedControllers {
		// NodeRotation reconciler (cap#7, D25g/D26): progresses an in-flight node drain
		// (Cordoning->Draining->Rescheduling->Pinning->Completed) created by a matched,
		// D26-gated NodeRotate action. It is RESTART-SAFE (durable phase in annotations)
		// and CLASS-B continuation only — it never self-initiates a node move; no
		// NodeRotation object => nothing happens. It honors MaxConcurrentNodes+Stagger (the
		// no-mass-eviction invariant). The NodeRotation type registers in the scheme via
		// amtdv1beta1.AddToScheme (same group), so no extra scheme line is needed.
		if err = (&controller.NodeRotationReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NodeRotation")
			os.Exit(1)
		}
	} else {
		setupLog.Info("extended controllers disabled; enable only after installing their CRDs and RBAC permissions")
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
