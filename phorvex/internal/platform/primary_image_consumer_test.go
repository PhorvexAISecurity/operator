package platform

import (
	"context"
	"math"
	"testing"
	"time"

	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// M-173 consumer chain: real Pod objects -> ingest.CollectSnapshot -> genericK8s.Derive. The
// EPSS cache rows are hypothetical and prove KEY SELECTION only (which running digest the
// consumers see), not the severity of any deployed image. Distinct primary/sidecar rows make
// a sidecar substitution visible as the wrong CachedDigest rather than a coincidental hit.
const (
	consumerPrimaryDigest = "docker.io/vllm/vllm-openai@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2"
	consumerNewerDigest   = "docker.io/vllm/vllm-openai@sha256:8f8b6c2d0e1f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
	consumerSidecarDigest = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	consumerUnscannedRef  = "docker.io/library/busybox@sha256:1c9e2f7b3a4d5c6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e"
)

func consumerPod(name, primaryImage string, statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "vllm"},
		Spec: corev1.PodSpec{NodeName: "gpu-1", Containers: []corev1.Container{
			{Name: "vllm", Image: primaryImage},
			{Name: "guardrail", Image: "python:3.11-slim"},
		}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses},
	}
}

func TestDerivePrimaryImageIdentityThroughSnapshot(t *testing.T) {
	SeedEPSSEntries(map[string]seedEntry{
		consumerPrimaryDigest: {EPSS: 0.5, CVSS: 5, ScanTS: "2026-09-01T03:17:00Z"},
		consumerSidecarDigest: {EPSS: 0.9, CVSS: 9, ScanTS: "2026-09-01T03:17:00Z"},
	})
	defer SeedEPSS(nil)

	status := func(name, id string) corev1.ContainerStatus { return corev1.ContainerStatus{Name: name, ImageID: id} }
	pods := []*corev1.Pod{
		consumerPod("aligned", "vllm/vllm-openai:v0.7.3", status("vllm", consumerPrimaryDigest), status("guardrail", consumerSidecarDigest)),
		consumerPod("reordered", "vllm/vllm-openai:v0.7.3", status("guardrail", consumerSidecarDigest), status("vllm", consumerPrimaryDigest)),
		consumerPod("primary-status-missing", "vllm/vllm-openai:v0.7.3", status("guardrail", consumerSidecarDigest)),
		consumerPod("repo-fallback", "vllm/vllm-openai:v0.8.0", status("guardrail", consumerSidecarDigest), status("vllm", consumerNewerDigest)),
		consumerPod("true-miss", "busybox:1.36", status("guardrail", consumerSidecarDigest), status("vllm", consumerUnscannedRef)),
	}
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	b := fake.NewClientBuilder().WithScheme(s)
	for _, p := range pods {
		b = b.WithObjects(p)
	}
	snap, err := ingest.CollectSnapshot(context.Background(), b.Build(), time.Unix(1_789_070_400, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Pods) != len(pods) {
		t.Fatalf("snapshot pods = %d, want %d", len(snap.Pods), len(pods))
	}
	projected := map[string]string{}
	for _, p := range snap.Pods {
		projected[p.Name] = p.ImageID
	}
	physics := (genericK8s{}).Derive(snap)
	witness := func(name string) model.PhysicsWitness {
		w, ok := physics["vllm/"+name]
		if !ok {
			t.Fatalf("no physics witness for vllm/%s", name)
		}
		return w
	}

	// Identity and EPSS keying per pod. "aligned" is the positive control: spec and status order
	// agree, so it is correct with or without name matching.
	cases := []struct {
		name        string
		wantImageID string
		wantPresent bool
		wantBasis   string
		wantCached  string
		wantEPSS    float64
		wantCVSS    float64
	}{
		{"aligned", consumerPrimaryDigest, true, EPSSBasisExact, consumerPrimaryDigest, 0.5, 5},
		{"reordered", consumerPrimaryDigest, true, EPSSBasisExact, consumerPrimaryDigest, 0.5, 5},
		{"primary-status-missing", "", false, "", "", 0, 0},
		{"repo-fallback", consumerNewerDigest, true, EPSSBasisRepoFallback, consumerPrimaryDigest, 0.5, 5},
		{"true-miss", consumerUnscannedRef, false, EPSSBasisMiss, "", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := witness(tc.name)
			t.Logf("projected=%q epss present=%v basis=%q cached=%q epss=%v cvss=%v",
				projected[tc.name], w.EPSSPresent, w.EPSSBasis, w.EPSSCachedDigest, w.EPSSScore, w.CVSS)
			if projected[tc.name] != tc.wantImageID {
				t.Errorf("snapshot ImageID = %q, want %q", projected[tc.name], tc.wantImageID)
			}
			if w.EPSSPresent != tc.wantPresent || w.EPSSBasis != tc.wantBasis || w.EPSSCachedDigest != tc.wantCached {
				t.Errorf("EPSS (present=%v basis=%q cached=%q), want (present=%v basis=%q cached=%q)",
					w.EPSSPresent, w.EPSSBasis, w.EPSSCachedDigest, tc.wantPresent, tc.wantBasis, tc.wantCached)
			}
			if w.EPSSScore != tc.wantEPSS || w.CVSS != tc.wantCVSS {
				t.Errorf("EPSS raw pair = (%v, %v), want (%v, %v)", w.EPSSScore, w.CVSS, tc.wantEPSS, tc.wantCVSS)
			}
		})
	}

	// Fleet image-rarity denominator: four pods carry a primary digest (2x primary, newer,
	// unscanned); the pod whose primary status is missing contributes nothing. A sidecar
	// substitution changes the denominator for EVERY pod, so this is asserted fleet-wide.
	// rarity = 1 + log2(N/count)/log2(N).
	const withImage = 4
	primaryRarity := 1 + math.Log2(withImage/2.0)/math.Log2(withImage)
	singletonRarity := 1 + math.Log2(withImage/1.0)/math.Log2(withImage)
	rarities := []struct {
		name        string
		wantPresent bool
		wantRarity  float64
	}{
		{"aligned", true, primaryRarity},
		{"reordered", true, primaryRarity},
		{"primary-status-missing", false, 1.0},
		{"repo-fallback", true, singletonRarity},
		{"true-miss", true, singletonRarity},
	}
	for _, tc := range rarities {
		t.Run("fleet-rarity/"+tc.name, func(t *testing.T) {
			w := witness(tc.name)
			t.Logf("rarity present=%v value=%v", w.ImageRarityPresent, w.ImageRarity)
			if w.ImageRarityPresent != tc.wantPresent || math.Abs(w.ImageRarity-tc.wantRarity) > 1e-9 {
				t.Errorf("image rarity (present=%v value=%v), want (present=%v value=%v)",
					w.ImageRarityPresent, w.ImageRarity, tc.wantPresent, tc.wantRarity)
			}
		})
	}
}
