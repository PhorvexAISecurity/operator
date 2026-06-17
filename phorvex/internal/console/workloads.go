/*
 * Phorvex Console (P-DASHBOARD-LIVE) — LIVE WORKLOAD ENUMERATION.
 *
 * GET /api/workloads?target=<kubeconfig-context>[&ns=<namespace>] lists the REAL workloads
 * running on the selected cluster (Deployments / StatefulSets / DaemonSets + standalone pods),
 * grouped by namespace, DERIVED live from the operator's kubeconfig (never a baked snapshot).
 * Read-only: it only get/list's — it never mutates the cluster. This is the picker the Attack
 * Lab uses to choose WHICH live workload to feature + which namespace to run the scenario in.
 */

package console

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Workload is one real controller (or standalone pod) on the live cluster.
type Workload struct {
	Kind     string            `json:"kind"`     // Deployment | StatefulSet | DaemonSet | Pod
	Name     string            `json:"name"`
	Replicas int               `json:"replicas"`
	Ready    int               `json:"ready"`
	Images   []string          `json:"images"`
	Selector map[string]string `json:"selector"` // matchLabels (Phoenix AMTD targets matchLabels)
}

// WorkloadNS groups the workloads of one namespace.
type WorkloadNS struct {
	Namespace string     `json:"namespace"`
	System    bool       `json:"system"` // kube-* infra namespace (de-emphasized in the picker)
	PodCount  int        `json:"podCount"`
	Workloads []Workload `json:"workloads"`
}

// systemNS marks the cluster-infra namespaces the picker de-emphasizes.
var systemNS = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
}

// clientForContext builds a read-only clientset for a specific kubeconfig context (empty or the
// sentinel "in-cluster" => the pod's mounted ServiceAccount when no kubeconfig resolves). This
// is how the SAME console binary serves live workloads BOTH on a developer box (kubeconfig) and
// as an in-cluster Deployment (ServiceAccount). Read-only; never mutates the kubeconfig.
func clientForContext(ctxName string) (*kubernetes.Clientset, error) {
	rc, err := restConfigFor(ctxName)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(rc)
}

// restConfigFor resolves the REST config for a kubeconfig context, falling back to the pod's
// in-cluster ServiceAccount when no kubeconfig resolves ("" or the "in-cluster" sentinel). It is
// the one place the dual dev-box/in-cluster credential resolution lives.
func restConfigFor(ctxName string) (*rest.Config, error) {
	if ctxName == "in-cluster" {
		ctxName = ""
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	rc, err := cc.ClientConfig()
	if err != nil {
		ic, ierr := rest.InClusterConfig()
		if ierr != nil {
			return nil, err
		}
		rc = ic
	}
	rc.QPS, rc.Burst = 50, 100
	return rc, nil
}

func containerImages(cs []corev1.Container) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Image)
	}
	return out
}

// capabilities reports the LIVE cluster capabilities (GPU / MIG / multi-node) so the UI gates
// only the scenarios whose hardware requirement is genuinely unmet — read live from node
// allocatable resources (the same signal the harness's CapGPU/CapMIG/CapMultiNode detection uses).
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	ctxName := r.URL.Query().Get("target")
	if ctxName != "" && !contextRe.MatchString(ctxName) {
		writeJSON(w, 400, map[string]string{"error": "invalid target context"})
		return
	}
	cs, err := clientForContext(ctxName)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "cannot build cluster client: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "cannot list nodes: " + err.Error()})
		return
	}
	gpu, mig := false, false
	gpuCount := int64(0)
	for i := range nodes.Items {
		for res, q := range nodes.Items[i].Status.Allocatable {
			rs := string(res)
			if rs == "nvidia.com/gpu" && q.Value() > 0 {
				gpu = true
				gpuCount += q.Value()
			}
			if strings.HasPrefix(rs, "nvidia.com/mig-") && q.Value() > 0 {
				mig = true
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"gpu": gpu, "mig": mig, "multiNode": len(nodes.Items) > 1,
		"nodes": len(nodes.Items), "gpuCount": gpuCount,
	})
}

func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	ctxName := r.URL.Query().Get("target")
	if ctxName != "" && !contextRe.MatchString(ctxName) {
		writeJSON(w, 400, map[string]string{"error": "invalid target context"})
		return
	}
	cs, err := clientForContext(ctxName)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "cannot build cluster client: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	byNS := map[string]*WorkloadNS{}
	ensure := func(ns string) *WorkloadNS {
		if x, ok := byNS[ns]; ok {
			return x
		}
		x := &WorkloadNS{Namespace: ns, System: systemNS[ns], Workloads: []Workload{}}
		byNS[ns] = x
		return x
	}

	if deps, e := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); e == nil {
		for _, d := range deps.Items {
			sel := map[string]string{}
			if d.Spec.Selector != nil {
				sel = d.Spec.Selector.MatchLabels
			}
			g := ensure(d.Namespace)
			g.Workloads = append(g.Workloads, Workload{
				Kind: "Deployment", Name: d.Name,
				Replicas: int(d.Status.Replicas), Ready: int(d.Status.ReadyReplicas),
				Images: containerImages(d.Spec.Template.Spec.Containers), Selector: sel,
			})
		}
	} else {
		writeJSON(w, 502, map[string]string{"error": "cannot list workloads: " + e.Error()})
		return
	}
	if sts, e := cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); e == nil {
		for _, d := range sts.Items {
			sel := map[string]string{}
			if d.Spec.Selector != nil {
				sel = d.Spec.Selector.MatchLabels
			}
			g := ensure(d.Namespace)
			g.Workloads = append(g.Workloads, Workload{
				Kind: "StatefulSet", Name: d.Name,
				Replicas: int(d.Status.Replicas), Ready: int(d.Status.ReadyReplicas),
				Images: containerImages(d.Spec.Template.Spec.Containers), Selector: sel,
			})
		}
	}
	if ds, e := cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); e == nil {
		for _, d := range ds.Items {
			sel := map[string]string{}
			if d.Spec.Selector != nil {
				sel = d.Spec.Selector.MatchLabels
			}
			g := ensure(d.Namespace)
			g.Workloads = append(g.Workloads, Workload{
				Kind: "DaemonSet", Name: d.Name,
				Replicas: int(d.Status.DesiredNumberScheduled), Ready: int(d.Status.NumberReady),
				Images: containerImages(d.Spec.Template.Spec.Containers), Selector: sel,
			})
		}
	}
	if pods, e := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); e == nil {
		for _, p := range pods.Items {
			ensure(p.Namespace).PodCount++
		}
	}

	out := make([]WorkloadNS, 0, len(byNS))
	for _, g := range byNS {
		sort.Slice(g.Workloads, func(i, j int) bool { return g.Workloads[i].Name < g.Workloads[j].Name })
		out = append(out, *g)
	}
	// non-system namespaces first, then alphabetical — the attack targets float to the top.
	sort.Slice(out, func(i, j int) bool {
		if out[i].System != out[j].System {
			return !out[i].System
		}
		return out[i].Namespace < out[j].Namespace
	})
	writeJSON(w, 200, map[string]any{"context": ctxName, "namespaces": out})
}
