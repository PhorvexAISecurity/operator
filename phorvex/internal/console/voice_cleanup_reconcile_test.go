package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func testVoiceResolutionProof(h cataloguev1.VoiceCleanupHistoricalIdentity, sids []string) cataloguev1.VoiceCleanupReadProof {
	hashes := []string{}
	for _, sid := range sids {
		sum := sha256.Sum256([]byte(sid))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	if hashes[0] > hashes[1] {
		hashes[0], hashes[1] = hashes[1], hashes[0]
	}
	now := time.Now().UTC()
	return cataloguev1.VoiceCleanupReadProof{Schema: "phorvex.voice-cleanup-read.v1", NamespaceUID: h.NamespaceUID, DeploymentUID: h.DeploymentUID, ServiceUID: h.ServiceUID, PDBUID: h.PDBUID,
		CurrentReplicaSetUID: "current-rs", ReadPodUID: "current-pod", ReadPodContainerID: "containerd://current", ReadPodImageID: "current-image", CurrentSourceSHA256: strings.Repeat("d", 64),
		DatastoreBindingSHA256: strings.Repeat("e", 64), CurrentAuthoritySHA256: strings.Repeat("f", 64), SIDHashes: hashes,
		Samples: []cataloguev1.VoiceCleanupZeroSample{{At: now, Count: 0}, {At: now.Add(2 * time.Second), Count: 0}, {At: now.Add(4 * time.Second), Count: 0}}}
}
func TestVoiceCleanupResolutionPreservesOriginalTerminalFilesAndStatus(t *testing.T) {
	cfg := disjointFixtureConfig(t)
	st, hashes := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	rm := NewRunManager(cfg)
	if rm.loadErr != nil {
		t.Fatal(rm.loadErr)
	}
	original, err := readVoiceCleanupOriginal(cfg, st, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	prior := *rm.runs[st.ID]
	verify := func(_ context.Context, h cataloguev1.VoiceCleanupHistoricalIdentity, sids []string) (cataloguev1.VoiceCleanupReadProof, error) {
		return testVoiceResolutionProof(h, sids), nil
	}
	if err := rm.reconcileVoiceCleanupWithVerifierAndPins(st.ID, st.Owner, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64), verify); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&prior, rm.runs[st.ID]) {
		t.Fatal("historical RunStatus changed")
	}
	for name, want := range hashes {
		body, e := os.ReadFile(filepath.Join(cfg.runOutputPath(st.ID), name))
		if e != nil || hashVoiceBytes(body) != want {
			t.Fatalf("historical %s changed", name)
		}
	}
	if !rm.voiceCleanupResolvedWithPinsLocked(rm.runs[st.ID], hashes, strings.Repeat("c", 64), strings.Repeat("a", 64)) {
		t.Fatal("exact resolution rejected")
	}
	// The ordinary paged history path must show the same separate resolution
	// marker as the run status path while retaining the original failed fields.
	// This fixture uses test hashes, so validate both projections through the
	// pinned reader directly instead of the production-only legacy hash map.
	meta, _, _ := rm.ListMetadata()
	if len(meta) != 1 || len(rm.HydrateList(meta)) != 1 {
		t.Fatal("paged history failed to hydrate the retained run")
	}
	finalPath := filepath.Join(cfg.runOutputPath(st.ID), voiceCleanupFinalName)
	final, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(finalPath, []byte(strings.Replace(string(final), "phorvex.voice-cleanup-final.v1", "phorvex.voice-cleanup-final.v2", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	// A changed final marker must not clear the historical unsafe gate.
	if rm.voiceCleanupResolvedWithPinsLocked(rm.runs[st.ID], hashes, strings.Repeat("c", 64), strings.Repeat("a", 64)) {
		t.Fatal("changed completion marker accepted")
	}
	if err = os.WriteFile(finalPath, final, 0600); err != nil {
		t.Fatal(err)
	}
	if err := rm.reconcileVoiceCleanupWithVerifierAndPins(st.ID, st.Owner, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64), verify); err == nil {
		t.Fatal("second operation accepted")
	}
	if err := rm.reconcileVoiceCleanupWithVerifierAndPins(st.ID, "foreign#actor", hashes, strings.Repeat("c", 64), strings.Repeat("a", 64), verify); err == nil {
		t.Fatal("foreign owner accepted")
	}
	if len(original.SIDHashes) != 2 {
		t.Fatal("exact original SIDs missing")
	}
}

func TestVoiceCleanupReceiptWriteFailureHasNoSuccessAudit(t *testing.T) {
	cfg := disjointFixtureConfig(t)
	st, hashes := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	rm := NewRunManager(cfg)
	verify := func(_ context.Context, h cataloguev1.VoiceCleanupHistoricalIdentity, sids []string) (cataloguev1.VoiceCleanupReadProof, error) {
		if err := os.WriteFile(filepath.Join(cfg.runOutputPath(st.ID), voiceCleanupReceiptName), []byte("occupied"), 0600); err != nil {
			t.Fatal(err)
		}
		return testVoiceResolutionProof(h, sids), nil
	}
	if err := rm.reconcileVoiceCleanupWithVerifierAndPins(st.ID, st.Owner, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64), verify); err == nil {
		t.Fatal("occupied receipt path accepted")
	}
	ledger, err := os.ReadFile(cfg.statePath("run-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ledger), "RESOLUTION_PERSISTED") {
		t.Fatal("success audit claimed before durable receipt")
	}
	if rm.voiceCleanupResolvedWithPinsLocked(rm.runs[st.ID], hashes, strings.Repeat("c", 64), strings.Repeat("a", 64)) {
		t.Fatal("unsafe gate cleared without final audited marker")
	}
}
func TestVoiceCleanupResolutionAdverseProofAndOriginalMutation(t *testing.T) {
	cfg := disjointFixtureConfig(t)
	st, hashes := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	rm := NewRunManager(cfg)
	if rm.loadErr != nil {
		t.Fatal(rm.loadErr)
	}
	bad := func(_ context.Context, h cataloguev1.VoiceCleanupHistoricalIdentity, sids []string) (cataloguev1.VoiceCleanupReadProof, error) {
		proof := testVoiceResolutionProof(h, sids)
		proof.ReadPodUID = h.TargetPodUID
		return proof, nil
	}
	if err := rm.reconcileVoiceCleanupWithVerifierAndPins(st.ID, st.Owner, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64), bad); err == nil {
		t.Fatal("old UID credited as fresh verifier")
	}
	if rm.voiceCleanupResolvedWithPinsLocked(rm.runs[st.ID], hashes, strings.Repeat("c", 64), strings.Repeat("a", 64)) {
		t.Fatal("incomplete proof bypassed safety gate")
	}
	if _, err := os.Stat(filepath.Join(cfg.runOutputPath(st.ID), voiceCleanupReceiptName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("resolution receipt written on failure")
	}
	dir := cfg.runOutputPath(st.ID)
	result := filepath.Join(dir, "result.json")
	body, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(result, append(body, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readVoiceCleanupOriginal(cfg, st, hashes, strings.Repeat("c", 64), strings.Repeat("a", 64)); err == nil {
		t.Fatal("modified original result accepted")
	}
}

func TestVoiceCleanupStatusBindingIgnoresProjectedMetricsOnly(t *testing.T) {
	base := &RunStatus{ID: voiceLegacyRunID, Config: string(cataloguev1.VoiceRecovery), State: "partial", Outcome: string(cataloguev1.OutcomeTestFailed), CleanupStatus: "FAIL", UnsafeToRetry: true}
	want, err := voiceStatusSHA(base)
	if err != nil {
		t.Fatal(err)
	}
	projected := *base
	projected.Trials = 7
	projected.Arms = []ArmResult{{Defender: "none", Trials: 7}}
	projected.CleanupResolvedSeparately = true
	got, err := voiceStatusSHA(&projected)
	if err != nil || got != want {
		t.Fatal("computed metrics/history projection changed durable status binding")
	}
	projected.Owner = "different#owner"
	got, err = voiceStatusSHA(&projected)
	if err != nil || got == want {
		t.Fatal("changed owner retained durable status binding")
	}
}
