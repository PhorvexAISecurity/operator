package platform_test

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/epssfeed"
	"github.com/phorvex/phorvex/internal/epssmeta"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/recon"
)

type m104Scanner struct{ digest string }

func (s m104Scanner) Scan(_ context.Context, image string) (map[string]float64, error) {
	if image != s.digest {
		return nil, &m104Unexpected{got: image}
	}
	return map[string]float64{"CVE-2026-0104": 8}, nil
}

type m104Unexpected struct{ got string }

func (e *m104Unexpected) Error() string { return "unexpected scan reference " + e.got }

type m104EPSS struct{}

func (m104EPSS) Lookup(_ context.Context, cves []string) (map[string]float64, error) {
	return map[string]float64{"CVE-2026-0104": .5}, nil
}

func TestM104ActualAPIScopedApplyAndAuthoritativeProjection(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API server")
	}
	defer platform.SeedEPSS(nil)
	local := false
	env := &envtest.Environment{UseExistingCluster: &local}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer env.Stop()
	ctx := context.Background()
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const namespace, cmName, cacheKey, metaKey = "m104-scoped", "epss", "cache.json", "metadata.json"
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	foreignDigest := "registry.example/foreign@sha256:" + strings.Repeat("b", 64)
	foreignEntry := `{"` + foreignDigest + `":{"epss":0.99,"cvss":10,"scanTS":"2026-09-20T00:00:00Z"}}`
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName}, Data: map[string]string{cacheKey: foreignEntry, "foreign": "preserve"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	digest := "registry.example/public@sha256:" + strings.Repeat("a", 64)
	changedDigest := "registry.example/public@sha256:" + strings.Repeat("c", 64)
	pod, err := clientset.CoreV1().Pods(namespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "public"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: digest}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Image: digest, ImageID: "containerd://" + digest, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
	if _, err := clientset.CoreV1().Pods(namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	scope := epssmeta.Scope{Namespaces: []string{namespace}, Digests: []string{digest}}
	result, err := epssfeed.Run(ctx, epssfeed.Options{Client: clientset, Scanner: m104Scanner{digest: digest}, EPSS: m104EPSS{}, Namespace: namespace, ConfigMapName: cmName, ConfigMapKey: cacheKey, MetadataKey: metaKey, InventoryScope: &scope, Apply: true, MetadataTTL: time.Hour, ProducerSource: strings.Repeat("d", 40)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "applied" || result.ConfigMapUID != string(cm.UID) || result.ConfigMapResourceVersion == "" {
		t.Fatalf("actual API receipt = %+v", result)
	}
	applied, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Data["foreign"] != "preserve" {
		t.Fatal("scoped actual API apply changed foreign data")
	}
	dir := t.TempDir()
	cachePath, metaPath := filepath.Join(dir, cacheKey), filepath.Join(dir, metaKey)
	if err := os.WriteFile(cachePath, []byte(applied.Data[cacheKey]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte(applied.Data[metaKey]), 0o600); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &platform.AuthoritativeEPSSRefresher{CachePath: cachePath, MetadataPath: metaPath, Namespace: namespace, ConfigMapName: cmName, CacheKey: cacheKey, MetadataKey: metaKey, Scope: scope, Reader: reader, Timeout: time.Second}
	if _, _, err := refresher.RefreshNow(ctx); err != nil {
		t.Fatal(err)
	}
	lk := platform.EPSSLookupForVerification("containerd://" + digest)
	if !lk.Present || lk.Source.Status != "available" || lk.Source.ConfigMapUID != string(applied.UID) || lk.Source.ConfigMapResourceVersion != applied.ResourceVersion {
		t.Fatalf("authoritative actual API lookup = %+v", lk)
	}
	if foreign := platform.EPSSLookupForVerification(foreignDigest); foreign.Present || foreign.Source.CacheSHA256 != lk.Source.CacheSHA256 {
		t.Fatalf("out-of-scope preserved cache entry entered authoritative projection: %+v", foreign)
	}
	if changed := platform.EPSSLookupForVerification("containerd://" + changedDigest); changed.Present || changed.Basis != platform.EPSSBasisMiss || changed.Source.CacheSHA256 != lk.Source.CacheSHA256 {
		t.Fatalf("out-of-scope digest in an allowed repository received fallback authority: %+v", changed)
	}
	// Exercise the production derive and UCW ranking boundary, not just the lookup
	// seam. The target, unrelated digest and missing identity share the same belief,
	// threat and cost inputs; only the authenticated EPSS physics differs.
	snapshot := &ingest.Snapshot{Pods: []model.Pod{
		{Namespace: namespace, Name: "target", Node: "node-a", ImageID: "containerd://" + digest},
		{Namespace: namespace, Name: "unrelated", Node: "node-a", ImageID: "containerd://" + changedDigest},
		{Namespace: namespace, Name: "missing", Node: "node-a"},
	}}
	adapter, physics := platform.Derive(snapshot)
	if adapter != "generic-k8s" || physics[namespace+"/target"].EPSSMultiplier != 1.4 || physics[namespace+"/unrelated"].EPSSMultiplier != 1 || physics[namespace+"/missing"].EPSSMultiplier != 1 {
		t.Fatalf("production derive adapter=%q target=%+v unrelated=%+v missing=%+v", adapter, physics[namespace+"/target"], physics[namespace+"/unrelated"], physics[namespace+"/missing"])
	}
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("production ucw-recon profile is not registered")
	}
	fctx := recon.FactContext{AssetValue: 1, PHold: .4, StageUrgency: .3, LateralUrgency: .2}
	weights := map[string]float64{}
	for i := range snapshot.Pods {
		pod := snapshot.Pods[i]
		view := &model.WorkloadView{Pod: pod, Physics: physics[pod.Namespace+"/"+pod.Name]}
		facts := profile.AssetFacts(view, fctx)
		for _, fact := range facts.Facts {
			weights[pod.Name] += fact.Weight
		}
	}
	fixedCost := .25
	if !(weights["target"]-fixedCost > weights["unrelated"]-fixedCost) || !(weights["unrelated"] >= weights["missing"]) {
		t.Fatalf("ranking with fixed belief/threat/cost target=%g unrelated=%g missing=%g", weights["target"]-fixedCost, weights["unrelated"]-fixedCost, weights["missing"]-fixedCost)
	}
	if math.Abs((weights["target"]-fixedCost)-(weights["unrelated"]-fixedCost)-(weights["target"]-weights["unrelated"])) > 1e-12 || fctx.PHold != .4 || fctx.StageUrgency != .3 {
		t.Fatal("EPSS projection changed fixed cost, P(hold), or threat inputs")
	}
	// API changes before projection: the prior immutable snapshot remains usable,
	// but the mismatched bytes cannot publish a new identity.
	applied.Data[cacheKey] = `{}`
	if _, err := clientset.CoreV1().ConfigMaps(namespace).Update(ctx, applied, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := refresher.RefreshNow(ctx); err == nil {
		t.Fatal("API/projection mismatch accepted")
	}
	if retained := platform.EPSSLookupForVerification(digest); !retained.Present || retained.Source.ConfigMapResourceVersion != lk.Source.ConfigMapResourceVersion {
		t.Fatalf("mismatch did not retain prior bounded snapshot: %+v", retained)
	}
}
