package epssfeed

import (
	"context"
	"encoding/json"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"strings"
	"testing"
	"time"
)

type scopeProbeScanner struct{ seen []string }

func (s *scopeProbeScanner) Scan(_ context.Context, image string) (map[string]float64, error) {
	s.seen = append(s.seen, image)
	return map[string]float64{"CVE-TEST": 8}, nil
}

type scopeProbeEPSS struct{}

func (scopeProbeEPSS) Lookup(_ context.Context, _ []string) (map[string]float64, error) {
	return map[string]float64{"CVE-TEST": .5}, nil
}
func TestLeadM104ScopeProducerContract(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		name := "legacy-positive"
		if scoped {
			name = "scoped-preserves-foreign"
		}
		t.Run(name, func(t *testing.T) {
			a := "registry.example/a@sha256:" + strings.Repeat("a", 64)
			b := "registry.example/b@sha256:" + strings.Repeat("b", 64)
			c := "registry.example/foreign@sha256:" + strings.Repeat("c", 64)
			pod := func(ns, name, image string) *corev1.Pod {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: image, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			}
			cl := fake.NewSimpleClientset(pod("scope-a", "a", a), pod("scope-b", "b", b), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "feed", Name: "epss", UID: types.UID("exact-uid"), ResourceVersion: "7"}, Data: map[string]string{"cache": `{"` + c + `":{"epss":0.2,"cvss":4}}`, "unrelated": "preserved"}})
			scanner := &scopeProbeScanner{}
			opts := Options{Client: cl, Scanner: scanner, EPSS: scopeProbeEPSS{}, Namespace: "feed", ConfigMapName: "epss", ConfigMapKey: "cache", Apply: true, Now: func() time.Time { return time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC) }}
			if scoped {
				// Same requested producer input at both source revisions. The old Options
				// does not expose InventoryScope; JSON leaves unsupported fields unset.
				requested, _ := json.Marshal(map[string]any{"InventoryScope": map[string]any{"Namespaces": []string{"scope-a"}, "Digests": []string{a}}, "MetadataKey": "meta", "MetadataTTL": int64(time.Hour), "ProducerSource": strings.Repeat("d", 40)})
				if err := json.Unmarshal(requested, &opts); err != nil {
					t.Fatal(err)
				}
			}
			result, err := Run(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			cm, err := cl.CoreV1().ConfigMaps("feed").Get(context.Background(), "epss", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			cache, err := decodeCache(cm.Data["cache"])
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("scoped=%v observedPods=%d uniqueImages=%d scans=%d cacheEntries=%d foreignPresent=%v", scoped, result.ObservedPods, result.UniqueImages, len(scanner.seen), len(cache), cache[c].CVSS == 4)
			if cm.Data["unrelated"] != "preserved" {
				t.Fatal("unrelated ConfigMap data changed")
			}
			if _, ok := cache[a]; !ok {
				t.Fatal("legitimate target score absent")
			}
			if !scoped {
				if len(scanner.seen) != 2 || result.UniqueImages != 2 {
					t.Fatal("legacy complete inventory changed")
				}
				return
			}
			if len(scanner.seen) != 1 || result.UniqueImages != 1 {
				t.Errorf("scope escaped: expected one exact target; scans=%d unique=%d", len(scanner.seen), result.UniqueImages)
			}
			if _, ok := cache[c]; !ok {
				t.Error("foreign cache entry removed outside configured scope")
			}
			if _, ok := cache[b]; ok {
				t.Error("unrelated namespace was scanned and written")
			}
		})
	}
}
