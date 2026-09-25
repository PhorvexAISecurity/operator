package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const voiceLegacyRunID = "v1run-5"
const voiceLegacyReplicaSetSpecSHA256 = "c5e2c152707a5c53b4d902643dd30ab342e2f0c1dc4c8c744f774dcd8499e887"
const voiceLegacyAuthoritySHA256 = "6a0244da0d12356a795d2351f303de0b797f4f48cde1381e188f199a64b85502"

// These exact original bytes were captured before any cleanup reconciliation.
// No mutation or generated result may replace one of these historical artifacts.
var voiceLegacyArtifactHashes = map[string]string{
	"job.json":      "8b93b9c04214231557fca856ad929f3f8b0025f625175378829b61fc12ad0e1f",
	"runtime.json":  "45d101c7e5703f356304431719cb756295c4bde320fba0c8a2f00e0b7d12a306",
	"result.json":   "9b4f4d3cd94f24a0e580fa7a0e4406c05e195fddfb42b9aa4523bce0b890326a",
	"metrics.jsonl": "aadedaaa22c4544c37c1d138d02001bde4914f64d09bec493ae0646f41fc94ae",
	"journal.jsonl": "0a30a7f500eb647284d14162d840d1140824e34b23cc4c816706613d69597198",
}

const voiceCleanupReceiptName = "cleanup-reconciliation.v1.json"
const voiceCleanupIntentName = "cleanup-reconciliation-intent.v1.json"
const voiceCleanupFinalName = "cleanup-reconciliation-final.v1.json"

type voiceCleanupOriginal struct {
	Hashes       map[string]string                          `json:"originalSHA256"`
	StatusSHA256 string                                     `json:"originalStatusSHA256"`
	Historical   cataloguev1.VoiceCleanupHistoricalIdentity `json:"historical"`
	SIDHashes    []string                                   `json:"sidHashes"`
	SIDs         []string                                   `json:"-"`
}

type voiceCleanupResolution struct {
	Schema                  string                            `json:"schema"`
	RunID                   string                            `json:"runID"`
	Profile                 string                            `json:"profile"`
	Tenant                  string                            `json:"tenant"`
	Target                  string                            `json:"target"`
	OwnerSHA256             string                            `json:"ownerSHA256"`
	AttemptID               string                            `json:"attemptID"`
	At                      time.Time                         `json:"at"`
	Original                voiceCleanupOriginal              `json:"original"`
	Read                    cataloguev1.VoiceCleanupReadProof `json:"read"`
	HistoricalOutcome       string                            `json:"historicalOutcome"`
	HistoricalCleanup       string                            `json:"historicalCleanup"`
	HistoricalUnsafeToRetry bool                              `json:"historicalUnsafeToRetry"`
	Mutations               int                               `json:"mutations"`
}

type voiceCleanupAudit struct {
	Kind        string `json:"kind"`
	Phase       string `json:"phase"`
	RunID       string `json:"runID"`
	AttemptID   string `json:"attemptID"`
	ActorSHA256 string `json:"actorSHA256"`
	Status      string `json:"status"`
	At          string `json:"at"`
}

func hashVoiceBytes(raw []byte) string    { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func hashVoiceString(value string) string { return hashVoiceBytes([]byte(value)) }
func voiceStatusSHA(status *RunStatus) (string, error) {
	// Status() and List() refresh Arms/Trials from metrics on the in-memory row.
	// Bind every other terminal field. Exact metrics bytes are pinned separately.
	stable := *status
	stable.Arms = nil
	stable.Trials = 0
	stable.QueuePos = 0
	stable.CleanupResolvedSeparately = false
	raw, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	return hashVoiceBytes(raw), nil
}

func readVoiceCleanupOriginal(cfg Config, prior *RunStatus, expected map[string]string, expectedReplicaSetSHA, expectedAuthoritySHA string) (voiceCleanupOriginal, error) {
	var proof voiceCleanupOriginal
	if prior == nil || prior.ID != voiceLegacyRunID || prior.Config != string(cataloguev1.VoiceRecovery) || prior.ExecutionKind != "fixed-suite" || prior.State != "partial" || prior.Outcome != string(cataloguev1.OutcomeTestFailed) || prior.CleanupStatus != "FAIL" || !prior.UnsafeToRetry || prior.ScopeTenant != "voice" || prior.ScopeTarget != defaultTargetID || prior.Owner == "" || prior.Finished == "" {
		return proof, errors.New("terminal Voice run identity differs")
	}
	dir := cfg.runOutputPath(prior.ID)
	if err := validatePriorVoiceFilesAt(prior, dir, dir, cfg.StateDir); err != nil {
		return proof, err
	}
	limits := map[string]int64{"job.json": 64 << 10, "runtime.json": 64 << 10, "result.json": 64 << 10, "metrics.jsonl": (1 << 20) + 1, "journal.jsonl": 256 * (64 << 10)}
	if len(expected) != len(limits) {
		return proof, errors.New("original Voice hash set differs")
	}
	originals := map[string][]byte{}
	proof.Hashes = map[string]string{}
	for name, limit := range limits {
		body, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, name), limit)
		if err != nil {
			return voiceCleanupOriginal{}, err
		}
		digest := hashVoiceBytes(body)
		if expected[name] != digest {
			return voiceCleanupOriginal{}, errors.New("original Voice bytes differ")
		}
		proof.Hashes[name] = digest
		originals[name] = body
	}
	var result cataloguev1.Result
	if err := json.Unmarshal(originals["result.json"], &result); err != nil {
		return voiceCleanupOriginal{}, err
	}
	var historical cataloguev1.VoiceCleanupHistoricalIdentity
	historical.TargetPodUID = result.Evidence["targetPodUID"]
	historical.ReplacementPodUID = result.Evidence["replacementPodUID"]
	if !voiceUID.MatchString(historical.TargetPodUID) || !voiceUID.MatchString(historical.ReplacementPodUID) || historical.TargetPodUID == historical.ReplacementPodUID || result.Evidence["authoritySHA256"] != expectedAuthoritySHA {
		return voiceCleanupOriginal{}, errors.New("original Voice effect evidence differs")
	}
	var sids []string
	evictionAccepted := false
	authoritySeen := false
	for _, line := range bytes.Split(bytes.TrimSpace(originals["journal.jsonl"]), []byte{'\n'}) {
		var record cataloguev1.JournalRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return voiceCleanupOriginal{}, err
		}
		if record.Intent != nil && record.Intent.Step == "voice.session" {
			sids = append(sids, record.Intent.Identity["callSID"])
		}
		if record.Event != nil && record.Event.Step == "voice.eviction" && record.Event.Status == "accepted" {
			evictionAccepted = true
		}
		if record.Event != nil && record.Event.Step == "voice.authority" {
			if authoritySeen || record.Event.Identity["authoritySHA256"] != expectedAuthoritySHA {
				return voiceCleanupOriginal{}, errors.New("Voice authority event differs")
			}
			authoritySeen = true
			historical.NamespaceUID = record.Event.Identity["namespaceUID"]
			historical.DeploymentUID = record.Event.Identity["deploymentUID"]
			historical.ReplicaSetUID = record.Event.Identity["replicaSetUID"]
			historical.ServiceUID = record.Event.Identity["serviceUID"]
			historical.PDBUID = record.Event.Identity["pdbUID"]
		}
	}
	if !authoritySeen || !evictionAccepted || len(sids) != 2 || sids[0] == sids[1] || !voiceSID.MatchString(sids[0]) || !voiceSID.MatchString(sids[1]) || !strings.HasPrefix(sids[0], "CA") || !strings.HasPrefix(sids[1], "CA") || !voiceUID.MatchString(historical.ReplicaSetUID) {
		return voiceCleanupOriginal{}, errors.New("original Voice journal effects differ")
	}
	historical.ReplicaSetSpecSHA256 = expectedReplicaSetSHA
	proof.Historical = historical
	proof.SIDs = sids
	proof.SIDHashes = []string{hashVoiceString(sids[0]), hashVoiceString(sids[1])}
	if proof.SIDHashes[0] > proof.SIDHashes[1] {
		proof.SIDHashes[0], proof.SIDHashes[1] = proof.SIDHashes[1], proof.SIDHashes[0]
	}
	statusSHA, err := voiceStatusSHA(prior)
	if err != nil {
		return voiceCleanupOriginal{}, err
	}
	proof.StatusSHA256 = statusSHA
	// The validator and hashes must still hold after the independent original parse.
	if err := validatePriorVoiceFilesAt(prior, dir, dir, cfg.StateDir); err != nil {
		return voiceCleanupOriginal{}, err
	}
	for name, limit := range limits {
		body, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, name), limit)
		if err != nil || hashVoiceBytes(body) != proof.Hashes[name] {
			return voiceCleanupOriginal{}, errors.New("original Voice artifact changed during read")
		}
	}
	return proof, nil
}

func writeVoiceExclusive(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > 64<<10 {
		return errors.New("Voice reconciliation record exceeds bound")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (rm *RunManager) appendVoiceCleanupAudit(id, attemptID, actor, phase, status string) error {
	raw, err := json.Marshal(voiceCleanupAudit{Kind: "phorvex.console.voice.cleanup-reconcile.v1", Phase: phase, RunID: id, AttemptID: attemptID, ActorSHA256: hashVoiceString(actor), Status: status, At: rm.cfg.now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), raw)
}
func (rm *RunManager) ReconcileVoiceCleanup(id, actor string) error {
	return rm.reconcileVoiceCleanupWithVerifier(id, actor, func(ctx context.Context, h cataloguev1.VoiceCleanupHistoricalIdentity, sids []string) (cataloguev1.VoiceCleanupReadProof, error) {
		runtimeConfig := rm.cfg.catalogueV1RuntimeConfig()
		var rc *rest.Config
		var err error
		if runtimeConfig.KubeconfigPath == "" {
			rc, err = rest.InClusterConfig()
		} else {
			rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: runtimeConfig.KubeconfigPath}
			rc, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: runtimeConfig.KubeContext}).ClientConfig()
		}
		if err != nil {
			return cataloguev1.VoiceCleanupReadProof{}, err
		}
		kube, err := kubernetes.NewForConfig(rc)
		if err != nil {
			return cataloguev1.VoiceCleanupReadProof{}, err
		}
		driver, err := cataloguev1.NewVoiceCleanupReadDriver(cataloguev1.Runtime{RESTConfig: rc, Kube: kube, Voice: runtimeConfig.Voice})
		if err != nil {
			return cataloguev1.VoiceCleanupReadProof{}, err
		}
		cfg := cataloguev1.VoiceConfig{Namespace: "voice", DeploymentName: "voice-bot", ServiceName: "voice-bot", PDBName: "voice-bot", ContainerName: "bot", BotSourcePath: "/app/bot.py"}
		return cataloguev1.VerifyVoiceCleanupReadOnly(ctx, driver, cfg, h, sids, nil)
	})
}
func (rm *RunManager) reconcileVoiceCleanupWithVerifier(id, actor string, verify func(context.Context, cataloguev1.VoiceCleanupHistoricalIdentity, []string) (cataloguev1.VoiceCleanupReadProof, error)) error {
	return rm.reconcileVoiceCleanupWithVerifierAndPins(id, actor, voiceLegacyArtifactHashes, voiceLegacyReplicaSetSpecSHA256, voiceLegacyAuthoritySHA256, verify)
}

func (rm *RunManager) reconcileVoiceCleanupWithVerifierAndPins(id, actor string, expectedHashes map[string]string, replicaSetSHA, authoritySHA string, verify func(context.Context, cataloguev1.VoiceCleanupHistoricalIdentity, []string) (cataloguev1.VoiceCleanupReadProof, error)) error {
	rm.mu.Lock()
	st := rm.runs[id]
	if id != voiceLegacyRunID || st == nil || actor == "" || st.Owner != actor || rm.loadErr != nil || rm.procs[id] != nil || rm.stopping[id] || rm.active != 0 || !cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(id)) {
		rm.mu.Unlock()
		return errors.New("Voice cleanup reconciliation run, owner, or concurrency differs")
	}
	prior := *st
	original, err := readVoiceCleanupOriginal(rm.cfg, &prior, expectedHashes, replicaSetSHA, authoritySHA)
	if err != nil {
		rm.mu.Unlock()
		return err
	}
	dir := rm.cfg.runOutputPath(id)
	if _, err = os.Stat(filepath.Join(dir, voiceCleanupReceiptName)); err == nil {
		rm.mu.Unlock()
		return errors.New("Voice cleanup resolution already exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		rm.mu.Unlock()
		return err
	}
	seed := make([]byte, 16)
	if _, err = rand.Read(seed); err != nil {
		rm.mu.Unlock()
		return err
	}
	attemptID := hex.EncodeToString(seed)
	intent := map[string]any{"schema": "phorvex.voice-cleanup-reconcile-intent.v1", "runID": id, "attemptID": attemptID, "originalSHA256": original.Hashes, "statusSHA256": original.StatusSHA256, "actorSHA256": hashVoiceString(actor), "at": rm.cfg.now().UTC().Format(time.RFC3339Nano)}
	if err = writeVoiceExclusive(filepath.Join(dir, voiceCleanupIntentName), intent); err != nil {
		rm.mu.Unlock()
		return fmt.Errorf("durable Voice reconciliation already attempted or unavailable: %w", err)
	}
	if err = rm.appendVoiceCleanupAudit(id, attemptID, actor, "intent", "READ_ONLY"); err != nil {
		rm.mu.Unlock()
		return err
	}
	rm.active++
	rm.mu.Unlock()
	defer func() { rm.mu.Lock(); rm.active--; rm.dequeueNextLocked(); rm.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	readProof, readErr := verify(ctx, original.Historical, original.SIDs)
	rm.mu.Lock()
	defer rm.mu.Unlock()
	current := rm.runs[id]
	if readErr != nil || ctx.Err() != nil || current == nil || !reflect.DeepEqual(current, &prior) || rm.procs[id] != nil || rm.stopping[id] {
		_ = rm.appendVoiceCleanupAudit(id, attemptID, actor, "terminal", "UNRESOLVED")
		return errors.New("Voice cleanup read verification unresolved; original run remains unsafe")
	}
	after, err := readVoiceCleanupOriginal(rm.cfg, current, expectedHashes, replicaSetSHA, authoritySHA)
	if err != nil || !reflect.DeepEqual(after.Hashes, original.Hashes) || after.StatusSHA256 != original.StatusSHA256 || !validVoiceCleanupReadProof(readProof, original) {
		_ = rm.appendVoiceCleanupAudit(id, attemptID, actor, "terminal", "UNRESOLVED")
		return errors.New("Voice cleanup source or read proof differs; original run remains unsafe")
	}
	resolution := voiceCleanupResolution{Schema: "phorvex.voice-cleanup-resolution.v1", RunID: id, Profile: prior.Config, Tenant: prior.ScopeTenant, Target: prior.ScopeTarget, OwnerSHA256: hashVoiceString(actor), AttemptID: attemptID, At: rm.cfg.now().UTC(), Original: original, Read: readProof, HistoricalOutcome: prior.Outcome, HistoricalCleanup: prior.CleanupStatus, HistoricalUnsafeToRetry: prior.UnsafeToRetry, Mutations: 0}
	if err = writeVoiceExclusive(filepath.Join(dir, voiceCleanupReceiptName), resolution); err != nil {
		return err
	}
	receiptRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, voiceCleanupReceiptName), 64<<10)
	if err != nil {
		return err
	}
	if err = rm.appendVoiceCleanupAudit(id, attemptID, actor, "terminal", "RESOLUTION_PERSISTED"); err != nil {
		return err
	}
	if err = writeVoiceExclusive(filepath.Join(dir, voiceCleanupFinalName), map[string]string{
		"schema": "phorvex.voice-cleanup-final.v1", "runID": id, "attemptID": attemptID,
		"actorSHA256": hashVoiceString(actor), "receiptSHA256": hashVoiceBytes(receiptRaw),
	}); err != nil {
		return err
	}
	return nil
}
func validVoiceCleanupReadProof(proof cataloguev1.VoiceCleanupReadProof, original voiceCleanupOriginal) bool {
	h := original.Historical
	if proof.Schema != "phorvex.voice-cleanup-read.v1" || proof.NamespaceUID != h.NamespaceUID || proof.DeploymentUID != h.DeploymentUID || proof.ServiceUID != h.ServiceUID || proof.PDBUID != h.PDBUID || proof.ReadPodUID == h.TargetPodUID || proof.ReadPodUID == h.ReplacementPodUID ||
		proof.CurrentReplicaSetUID == "" || proof.ReadPodUID == "" || proof.ReadPodContainerID == "" || proof.ReadPodImageID == "" || !voiceHex.MatchString(proof.CurrentSourceSHA256) || !voiceHex.MatchString(proof.CurrentAuthoritySHA256) || !voiceHex.MatchString(proof.DatastoreBindingSHA256) || proof.KubernetesWrites != 0 || proof.MongoWrites != 0 || proof.WorkloadCalls != 0 || len(proof.Samples) != 3 || !reflect.DeepEqual(proof.SIDHashes, original.SIDHashes) {
		return false
	}
	for i, sample := range proof.Samples {
		if sample.Count != 0 || sample.At.IsZero() || i > 0 && sample.At.Sub(proof.Samples[i-1].At) < 2*time.Second {
			return false
		}
	}
	return true
}
func (rm *RunManager) voiceCleanupResolvedLocked(prior *RunStatus) bool {
	return rm.voiceCleanupResolvedWithPinsLocked(prior, voiceLegacyArtifactHashes, voiceLegacyReplicaSetSpecSHA256, voiceLegacyAuthoritySHA256)
}
func (rm *RunManager) voiceCleanupResolvedWithPinsLocked(prior *RunStatus, expectedHashes map[string]string, replicaSetSHA, authoritySHA string) bool {
	if prior == nil || prior.ID != voiceLegacyRunID {
		return false
	}
	original, err := readVoiceCleanupOriginal(rm.cfg, prior, expectedHashes, replicaSetSHA, authoritySHA)
	if err != nil {
		return false
	}
	dir := rm.cfg.runOutputPath(prior.ID)
	intentRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, voiceCleanupIntentName), 64<<10)
	if err != nil {
		return false
	}
	receiptRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, voiceCleanupReceiptName), 64<<10)
	if err != nil {
		return false
	}
	finalRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(dir, voiceCleanupFinalName), 64<<10)
	if err != nil {
		return false
	}
	var intent map[string]any
	var receipt voiceCleanupResolution
	var final map[string]string
	if json.Unmarshal(intentRaw, &intent) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || json.Unmarshal(finalRaw, &final) != nil || receipt.Schema != "phorvex.voice-cleanup-resolution.v1" || receipt.RunID != prior.ID || receipt.Profile != prior.Config || receipt.Tenant != prior.ScopeTenant || receipt.Target != prior.ScopeTarget || receipt.OwnerSHA256 != hashVoiceString(prior.Owner) || receipt.AttemptID == "" || intent["attemptID"] != receipt.AttemptID || intent["runID"] != prior.ID || intent["actorSHA256"] != receipt.OwnerSHA256 || intent["statusSHA256"] != original.StatusSHA256 || final["schema"] != "phorvex.voice-cleanup-final.v1" || final["runID"] != prior.ID || final["attemptID"] != receipt.AttemptID || final["actorSHA256"] != receipt.OwnerSHA256 || final["receiptSHA256"] != hashVoiceBytes(receiptRaw) || receipt.HistoricalOutcome != string(cataloguev1.OutcomeTestFailed) || receipt.HistoricalCleanup != "FAIL" || !receipt.HistoricalUnsafeToRetry || receipt.Mutations != 0 || !reflect.DeepEqual(receipt.Original.Hashes, original.Hashes) || receipt.Original.StatusSHA256 != original.StatusSHA256 || !reflect.DeepEqual(receipt.Original.Historical, original.Historical) || !reflect.DeepEqual(receipt.Original.SIDHashes, original.SIDHashes) || !validVoiceCleanupReadProof(receipt.Read, original) {
		return false
	}
	intentHashes, ok := intent["originalSHA256"].(map[string]any)
	if !ok || len(intentHashes) != len(original.Hashes) {
		return false
	}
	for name, digest := range original.Hashes {
		if intentHashes[name] != digest {
			return false
		}
	}
	return true
}
