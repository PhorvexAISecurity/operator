package epssfeed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/phorvex/phorvex/internal/epssmeta"
)

func exactImage(repo, hex string) string { return repo + "@sha256:" + strings.Repeat(hex, 64) }

func TestScopedApplyChangesOnlyExactAuthorityAndReturnsReceipt(t *testing.T) {
	const ns, cmName, cacheKey, metaKey = "phorvex-system", "epss", "epss-cache.json", "epss-metadata.json"
	a, b, foreign := exactImage("registry.example/a", "a"), exactImage("registry.example/b", "b"), exactImage("registry.example/foreign", "c")
	podA := runningPod("a", a)
	podA.Status.ContainerStatuses[0].ImageID = "containerd://" + a
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: ns, UID: types.UID("cm-uid"), ResourceVersion: "7"}, Data: map[string]string{cacheKey: `{"` + b + `":{"epss":0.2,"cvss":4},"` + foreign + `":{"epss":0.9,"cvss":9}}`, "foreign": "preserved"}},
		podA,
	)
	result, err := Run(context.Background(), Options{Client: client, Scanner: fakeScanner{results: map[string]map[string]float64{a: {"CVE-1": 8}}}, EPSS: fakeEPSS{"CVE-1": .5},
		Namespace: ns, ConfigMapName: cmName, ConfigMapKey: cacheKey, MetadataKey: metaKey, Apply: true,
		InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{a, b}}, MetadataTTL: time.Hour,
		ProducerSource: strings.Repeat("d", 40), Now: func() time.Time { return time.Date(2026, 9, 21, 1, 2, 3, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "applied" || result.ConfigMapUID != "cm-uid" || result.ConfigMapResourceVersion == "" || result.ScopeSHA256 == "" || result.CacheSHA256 == "" || result.MetadataSHA256 == "" {
		t.Fatalf("receipt = %+v", result)
	}
	got, _ := client.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
	cache, err := decodeCache(got.Data[cacheKey])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache[a]; !ok {
		t.Fatal("scoped current digest missing")
	}
	if _, ok := cache[b]; ok {
		t.Fatal("scoped stale digest retained")
	}
	if _, ok := cache[foreign]; !ok || got.Data["foreign"] != "preserved" {
		t.Fatal("out-of-scope data changed")
	}
	meta, err := epssmeta.Parse([]byte(got.Data[metaKey]))
	if err != nil {
		t.Fatal(err)
	}
	if !meta.Complete || meta.CacheSHA256 != result.CacheSHA256 || meta.ScopeSHA256 != result.ScopeSHA256 {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestScopedApplyFreshMergesConflictAndProvesLostResponseByReadback(t *testing.T) {
	const ns, cmName, cacheKey, metaKey = "phorvex-system", "epss", "cache", "meta"
	digest := exactImage("registry.example/a", "a")
	for _, tc := range []struct {
		name     string
		conflict bool
	}{{"conflict", true}, {"lost-response", false}} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: ns, UID: types.UID("uid"), ResourceVersion: "7"}, Data: map[string]string{cacheKey: `{}`}}, runningPod("a", digest))
			updates := 0
			client.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updates++
				ua := action.(k8stesting.UpdateAction)
				desired := ua.GetObject().(*corev1.ConfigMap).DeepCopy()
				if tc.conflict && updates == 1 {
					current, _ := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), ns, cmName)
					writer := current.(*corev1.ConfigMap).DeepCopy()
					writer.ResourceVersion = "8"
					writer.Data["writer"] = "preserved"
					_ = client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), writer, ns)
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, cmName, errors.New("rv changed"))
				}
				if !tc.conflict {
					desired.ResourceVersion = "8"
					_ = client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), desired, ns)
					return true, nil, context.DeadlineExceeded
				}
				return false, nil, nil
			})
			result, err := Run(context.Background(), Options{Client: client, Scanner: fakeScanner{results: map[string]map[string]float64{digest: {"CVE-1": 8}}}, EPSS: fakeEPSS{"CVE-1": .4}, Namespace: ns, ConfigMapName: cmName, ConfigMapKey: cacheKey, MetadataKey: metaKey, Apply: true, InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{digest}}, MetadataTTL: time.Hour, ProducerSource: strings.Repeat("d", 40)})
			if err != nil || result.Mode != "applied" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			got, _ := client.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
			if tc.conflict && got.Data["writer"] != "preserved" {
				t.Fatal("fresh conflict merge lost concurrent writer")
			}
			cache, decodeErr := decodeCache(got.Data[cacheKey])
			if decodeErr != nil || cache[digest].EPSS != .4 {
				t.Fatalf("cache=%v err=%v", cache, decodeErr)
			}
			if tc.conflict && updates != 2 || !tc.conflict && updates != 1 {
				t.Fatalf("updates=%d", updates)
			}
		})
	}
}

func TestScopedApplyLostResponseRejectsReplacementConfigMapIdentity(t *testing.T) {
	const ns, cmName, cacheKey, metaKey = "phorvex-system", "epss", "cache", "meta"
	digest := exactImage("registry.example/a", "a")
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: ns, UID: types.UID("uid-old"), ResourceVersion: "7"}, Data: map[string]string{cacheKey: `{}`}},
		runningPod("a", digest),
	)
	client.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		desired := action.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		desired.UID, desired.ResourceVersion = types.UID("uid-replacement"), "8"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), desired, ns); err != nil {
			t.Fatal(err)
		}
		return true, nil, context.DeadlineExceeded
	})
	result, err := Run(context.Background(), Options{Client: client, Scanner: fakeScanner{results: map[string]map[string]float64{digest: {"CVE-1": 8}}}, EPSS: fakeEPSS{"CVE-1": .4}, Namespace: ns, ConfigMapName: cmName, ConfigMapKey: cacheKey, MetadataKey: metaKey, Apply: true, InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{digest}}, MetadataTTL: time.Hour, ProducerSource: strings.Repeat("d", 40)})
	if err == nil || result.Mode != "apply-unknown" {
		t.Fatalf("replacement readback result=%+v err=%v", result, err)
	}
}

func TestDecodeCacheRejectsAmbiguousAndOversizedDocuments(t *testing.T) {
	if _, err := decodeCache(`{"a":{"epss":0.1,"cvss":1},"a":{"epss":0.2,"cvss":2}}`); err == nil {
		t.Fatal("duplicate cache key accepted")
	}
	if _, err := decodeCache(strings.Repeat(" ", epssmeta.MaxCacheBytes+1)); err == nil {
		t.Fatal("oversized cache accepted")
	}
}

func TestScopedApplyRejectsBoundedInputWhoseMergeExceedsOutputLimit(t *testing.T) {
	const ns, cmName, cacheKey, metaKey = "phorvex-system", "epss", "cache", "meta"
	digest := exactImage("registry.example/a", "a")
	prior := make(map[string]Score, epssmeta.MaxCacheEntries)
	for i := 0; i < epssmeta.MaxCacheEntries; i++ {
		prior[fmt.Sprintf("foreign-%04d", i)] = Score{EPSS: .1, CVSS: 1}
	}
	priorBytes, err := Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: ns, UID: types.UID("uid"), ResourceVersion: "7"}, Data: map[string]string{cacheKey: string(priorBytes)}},
		runningPod("a", digest),
	)
	result, err := Run(context.Background(), Options{Client: client, Scanner: fakeScanner{results: map[string]map[string]float64{digest: {"CVE-1": 8}}}, EPSS: fakeEPSS{"CVE-1": .4}, Namespace: ns, ConfigMapName: cmName, ConfigMapKey: cacheKey, MetadataKey: metaKey, Apply: true, InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{digest}}, MetadataTTL: time.Hour, ProducerSource: strings.Repeat("d", 40)})
	if err == nil || result.Mode != "rejected-output" {
		t.Fatalf("near-limit merge result=%+v err=%v", result, err)
	}
	updates := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" && action.GetResource().Resource == "configmaps" {
			updates++
		}
	}
	got, getErr := client.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
	if getErr != nil || updates != 0 || got.Data[cacheKey] != string(priorBytes) || got.Data[metaKey] != "" {
		t.Fatalf("rejected output mutated object: updates=%d getErr=%v", updates, getErr)
	}
}

func TestConfiguredScopeRejectsTagsAndPartialModeBeforeMutation(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "epss", Namespace: "ns"}, Data: map[string]string{"cache": `{}`}})
	for _, opts := range []Options{
		{InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{"registry/image:tag"}}},
		{InventoryScope: &epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{exactImage("registry/image", "a")}}, AllowPartial: true},
	} {
		opts.Client, opts.Scanner, opts.EPSS, opts.Namespace, opts.ConfigMapName, opts.ConfigMapKey, opts.MetadataKey, opts.MetadataTTL, opts.ProducerSource = client, fakeScanner{}, fakeEPSS{}, "ns", "epss", "cache", "meta", time.Hour, strings.Repeat("d", 40)
		if _, err := Run(context.Background(), opts); err == nil {
			t.Fatalf("invalid scope accepted: %+v", opts)
		}
	}
}
