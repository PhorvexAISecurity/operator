// Package kube builds the typed + controller-runtime clients from the configured
// kubeconfig + context, and reports the LIVE context name and apiserver host so
// the safety guard can assert them before any mutation.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// Clients bundles everything the harness needs to talk to one cluster.
type Clients struct {
	Kube        kubernetes.Interface
	Ctrl        ctrlclient.Client
	Rest        *rest.Config
	LiveContext string
	LiveHost    string
}

// Build constructs the clients from the kubeconfig path (empty = default lookup)
// PINNED to the named context. It returns the live context + host for the guard.
//
// PORTABILITY: nothing here is environment-specific; the SAME builder works for
// kind / EKS / CoreWeave / vcluster — only the kubeconfig + context differ.
func Build(kubeconfigPath, contextName string) (*Clients, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	restCfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build rest config for context %q: %w", contextName, err)
	}

	// Resolve the live context name actually selected.
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("read raw kubeconfig: %w", err)
	}
	liveCtx := raw.CurrentContext
	if contextName != "" {
		liveCtx = contextName
	}

	kc, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	cl, err := ctrlclient.New(restCfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("build controller-runtime client: %w", err)
	}

	return &Clients{
		Kube:        kc,
		Ctrl:        cl,
		Rest:        restCfg,
		LiveContext: liveCtx,
		LiveHost:    restCfg.Host,
	}, nil
}
