package cataloguev1

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/metricvalidity"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func crmTestRuntime(t *testing.T) CRMCapabilityRuntime {
	t.Helper()
	dir := t.TempDir()
	manifest := crmManifest{Schema: "phorvex.crm-fixture.v1", CRMImage: "example.invalid/crm@sha256:" + strings.Repeat("a", 64), MongoImage: "example.invalid/mongo@sha256:" + strings.Repeat("b", 64), BaseImageDigest: crmBaseImage, SourceSHA256: crmSourceSHA, DependencyLockSHA256: crmLockSHA, WheelhouseManifestSHA256: strings.Repeat("c", 64), Dependencies: map[string]string{"fastapi": "0.115.14", "pydantic": "2.13.4", "pymongo": "4.17.0", "uvicorn": "0.30.6"}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "harness")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	kubePath := filepath.Join(dir, "kubeconfig")
	kubeRaw := []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n    server: https://127.0.0.1:6443\ncontexts:\n- name: crm-fixture\n  context:\n    cluster: fixture\n    user: fixture\ncurrent-context: crm-fixture\nusers:\n- name: fixture\n  user:\n    token: fixture-token\n")
	if err := os.WriteFile(kubePath, kubeRaw, 0600); err != nil {
		t.Fatal(err)
	}
	return CRMCapabilityRuntime{Enabled: true, Namespace: "crm-fixture", NamespaceUID: "11111111-1111-4111-8111-111111111111", ServiceAccountName: "fixture-sa", ManifestFile: manifestPath, ManifestSHA256: digestBytes(raw), HarnessBinary: binaryPath, HarnessSHA256: digestBytes([]byte("#!/bin/sh\nexit 0\n")), HarnessDir: dir, KubeconfigPath: kubePath, KubeconfigSHA256: digestBytes(kubeRaw), KubeContext: "crm-fixture"}
}

func TestCRMReconcileRefusesMissingProcessIdentityAndWrongJournal(t *testing.T) {
	r := crmTestRuntime(t)
	job := Job{RunID: "v1run-1", Profile: CRMRefund, OutputDir: t.TempDir(), OwnerDigest: strings.Repeat("a", 64), CreatedAt: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	trial := crmTrialID(job)
	outDir := filepath.Join(job.OutputDir, "crm-harness")
	config, err := crmHarnessConfig(job, r, trial, outDir)
	if err != nil {
		t.Fatal(err)
	}
	identity := map[string]string{"scenario": string(job.Profile), "trialID": trial, "namespaceUID": r.NamespaceUID, "manifestSHA256": r.ManifestSHA256, "harnessSHA256": r.HarnessSHA256, "configSHA256": digestBytes(config)}
	ctx := JobContext{Job: job, Runtime: Runtime{CRM: r}}
	h := NewCRMCapabilityHandler(CRMRefund)
	cleanup := h.Reconcile(context.Background(), ctx, Journal{Records: []JournalRecord{{Intent: &Intent{Step: "crm-fixture-dispatch", Mutation: true, Identity: identity}}}})
	if cleanup.Verified || !cleanup.UnsafeToRetry || cleanup.Status != "PROCESS-UNRESOLVED" {
		t.Fatalf("missing process identity treated as safe: %+v", cleanup)
	}
	identity["trialID"] = "foreign"
	cleanup = h.Reconcile(context.Background(), ctx, Journal{Records: []JournalRecord{{Intent: &Intent{Step: "crm-fixture-dispatch", Mutation: true, Identity: identity}}}})
	if cleanup.Verified || !cleanup.UnsafeToRetry || cleanup.Status != "INTENT-IDENTITY-INVALID" {
		t.Fatalf("foreign journal intent accepted: %+v", cleanup)
	}
}

func TestCRMExactCleanupRequiresCreateUIDLedgerAndPreservesForeignObject(t *testing.T) {
	r := crmTestRuntime(t)
	const trial = "1234567890abcdef"
	name := "c2-crm-refund-" + trial
	makeClient := func() *fake.Clientset {
		client := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: r.Namespace, UID: types.UID(r.NamespaceUID), Labels: map[string]string{"phorvex.ai/crm-capability-fixture": "true"}}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.Namespace, UID: types.UID("pod-uid")}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-code", Namespace: r.Namespace, UID: types.UID("cm-uid")}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-owned", Namespace: r.Namespace, UID: types.UID("foreign"), Labels: map[string]string{"r6th.io/owned": "true"}}},
		)
		client.PrependReactor("create", "selfsubjectreviews", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.SelfSubjectReview{Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:" + r.Namespace + ":" + r.ServiceAccountName}}}, nil
		})
		return client
	}
	ledger := func(dir, podUID string) {
		t.Helper()
		f, err := os.Create(filepath.Join(dir, "crm-created.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range []crmCreated{{Schema: "phorvex.crm-created.v1", Event: "created", Run: trial, Namespace: r.Namespace, NamespaceUID: r.NamespaceUID, Resource: "pods", Name: name, UID: podUID}, {Schema: "phorvex.crm-created.v1", Event: "created", Run: trial, Namespace: r.Namespace, NamespaceUID: r.NamespaceUID, Resource: "configmaps", Name: name + "-code", UID: "cm-uid"}} {
			raw, _ := json.Marshal(rec)
			if _, err := f.Write(append(raw, '\n')); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	missing := makeClient()
	cleanup, err := crmCleanupExactWithClient(context.Background(), r, t.TempDir(), "refund", trial, missing)
	if err == nil || cleanup.Verified || !cleanup.UnsafeToRetry {
		t.Fatalf("missing UID ledger accepted: %+v %v", cleanup, err)
	}
	if _, err := missing.CoreV1().Pods(r.Namespace).Get(context.Background(), name, metav1.GetOptions{}); err != nil {
		t.Fatalf("missing ledger deleted Pod: %v", err)
	}
	wrongDir := t.TempDir()
	ledger(wrongDir, "different-pod-uid")
	wrong := makeClient()
	cleanup, err = crmCleanupExactWithClient(context.Background(), r, wrongDir, "refund", trial, wrong)
	if err == nil || cleanup.Verified || !cleanup.UnsafeToRetry {
		t.Fatalf("wrong create-response UID accepted: %+v %v", cleanup, err)
	}
	if _, err := wrong.CoreV1().Pods(r.Namespace).Get(context.Background(), name, metav1.GetOptions{}); err != nil {
		t.Fatalf("wrong ledger deleted Pod: %v", err)
	}
	goodDir := t.TempDir()
	ledger(goodDir, "pod-uid")
	good := makeClient()
	cleanup, err = crmCleanupExactWithClient(context.Background(), r, goodDir, "refund", trial, good)
	if err != nil || !cleanup.Verified || cleanup.UnsafeToRetry || cleanup.Details["podUID"] != "pod-uid" {
		t.Fatalf("exact UID cleanup failed: %+v %v", cleanup, err)
	}
	if _, err := good.CoreV1().ConfigMaps(r.Namespace).Get(context.Background(), "foreign-owned", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign object deleted: %v", err)
	}
	if _, err := good.CoreV1().Namespaces().Get(context.Background(), r.Namespace, metav1.GetOptions{}); err != nil {
		t.Fatalf("namespace deleted: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(goodDir, "crm-created.jsonl"))
	if err != nil || strings.Count(string(raw), `"event":"retired"`) != 2 {
		t.Fatalf("UID retirement missing: %v %s", err, raw)
	}
}

func TestCRMLocalAuthorityPinsFilesAndRejectsEscapedOrWritablePaths(t *testing.T) {
	r := crmTestRuntime(t)
	if err := ValidateCRMLocalAuthority(r); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "manifest.json")
	raw, err := os.ReadFile(r.ManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, raw, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(r.ManifestFile), "escape.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	r.ManifestFile = link
	if err := ValidateCRMLocalAuthority(r); err == nil {
		t.Fatal("escaped manifest symlink accepted")
	}
	r.ManifestFile = filepath.Join(filepath.Dir(link), "manifest.json")
	if err := os.Chmod(r.KubeconfigPath, 0666); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCRMLocalAuthority(r); err == nil {
		t.Fatal("writable scoped kubeconfig accepted")
	}
	if err := os.Chmod(r.KubeconfigPath, 0600); err != nil {
		t.Fatal(err)
	}
	r.HarnessSHA256 = strings.Repeat("0", 64)
	if err := ValidateCRMLocalAuthority(r); err == nil {
		t.Fatal("wrong executable hash accepted")
	}
	r.HarnessSHA256 = digestBytes([]byte("#!/bin/sh\nexit 0\n"))
	r.Namespace = "crm"
	if err := ValidateCRMLocalAuthority(r); err == nil {
		t.Fatal("installed CRM namespace accepted as fixture")
	}
}

func crmTestMetric(t *testing.T, r CRMCapabilityRuntime, profile ProfileID, cross int, status int) []byte {
	t.Helper()
	manifest, err := crmReadManifest(r)
	if err != nil {
		t.Fatal(err)
	}
	kind := "refund"
	if profile == CRMReset {
		kind = "reset"
	}
	o := crmObservation{Schema: "phorvex.crm-observation.v1", Case: kind, Run: "1234567890abcdef", LegitimateRead: true, OwnExactCount: 1, CrossExactCount: cross, CrossHTTPStatus: status, OwnCreatedID: "own-id", SeedHashesUnchanged: true, SeedHashes: map[string]string{"account_a": strings.Repeat("a", 64), "account_b": strings.Repeat("b", 64), "order_a": strings.Repeat("c", 64), "order_b": strings.Repeat("d", 64)}, AccountIDs: []string{"a-id", "b-id"}, OrderIDs: []string{"a-order", "b-order"}, CrossObserved: cross == 1, PodUID: "pod-uid", ConfigMapUID: "cm-uid"}
	if cross == 1 {
		o.CrossCreatedID = "cross-id"
	}
	state, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	validity := &metricvalidity.Validity{Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary, Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete, AttackExecuted: true, OracleObserved: true, Scored: false, UnscoredReason: crmUnscoredReason, Cleanup: metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "scenario.Teardown"}}, Complete: true, Verified: true}}
	evidence := map[string]string{"sourceSHA256": crmSourceSHA, "probeSHA256": crmProbeSHA, "manifestSHA256": r.ManifestSHA256, "dependencyLockSHA256": crmLockSHA, "runID": "1234567890abcdef", "podUID": "pod-uid", "configMapUID": "cm-uid", "crmImageID": "containerd://sha256:" + strings.Repeat("a", 64), "mongoImageID": "containerd://sha256:" + strings.Repeat("b", 64), "claimScope": "functional-authorization-capability-only", "crmImage": manifest.CRMImage, "mongoImage": manifest.MongoImage, "wheelhouseManifestSHA256": manifest.WheelhouseManifestSHA256}
	limits := crmRefundLimits
	if profile == CRMReset {
		limits = crmResetLimits
	}
	metric := map[string]any{"scenario": string(profile), "defender": "d-nomtd", "trial": 0, "oracleAchieved": cross == 1, "skipped": true, "skipReason": "UNSCORED(benign-control): " + validity.UnscoredReason, "scenarioRealism": "executable-mechanism", "scenarioBenignControl": true, "scenarioClaimLimits": limits, "defensiveActions": 0, "observedState": string(state), "benchmarkEvidence": evidence, "validity": validity}
	raw, err := json.Marshal(metric)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCRMMetricAcceptsBWriteAbsenceAndDenialAfterWrite(t *testing.T) {
	r := crmTestRuntime(t)
	for _, tc := range []struct {
		name          string
		profile       ProfileID
		cross, status int
		bad           string
	}{{"refund-write", CRMRefund, 1, 200, ""}, {"refund-absence", CRMRefund, 0, 403, ""}, {"refund-denial-after-write", CRMRefund, 1, 403, ""}, {"reset-write", CRMReset, 1, 200, ""}, {"contradictory", CRMRefund, 1, 200, "crossObserved"}, {"wrong-case", CRMReset, 1, 200, "case"}, {"wrong-image-id", CRMRefund, 1, 200, "imageID"}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := crmTestMetric(t, r, tc.profile, tc.cross, tc.status)
			if tc.bad != "" {
				var m map[string]any
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				if tc.bad == "imageID" {
					m["benchmarkEvidence"].(map[string]any)["crmImageID"] = "containerd://sha256:" + strings.Repeat("e", 64)
				} else {
					var o map[string]any
					if err := json.Unmarshal([]byte(m["observedState"].(string)), &o); err != nil {
						t.Fatal(err)
					}
					if tc.bad == "crossObserved" {
						o["crossObserved"] = false
					} else {
						o["case"] = "refund"
					}
					state, _ := json.Marshal(o)
					m["observedState"] = string(state)
				}
				raw, _ = json.Marshal(m)
			}
			path := filepath.Join(t.TempDir(), "metrics.jsonl")
			if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			limits := crmRefundLimits
			if tc.profile == CRMReset {
				limits = crmResetLimits
			}
			_, _, o, err := loadCRMMetric(path, tc.profile, limits, "1234567890abcdef", r)
			if tc.bad != "" && err == nil {
				t.Fatal("contradictory B observation accepted")
			}
			if tc.bad == "" && (err != nil || o.CrossExactCount != tc.cross) {
				t.Fatalf("valid B state refused: %+v %v", o, err)
			}
		})
	}
}
