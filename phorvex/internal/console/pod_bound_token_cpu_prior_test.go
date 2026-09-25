package console

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/cataloguev1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const cpuPriorReviewedContext = "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"

func cpuPriorDestination() runDestination {
	return runDestination{Targets: []string{hostTargetID, cpuPriorReviewedContext}, Tenants: []string{podBoundTokenCPUNamespace}, ScopeTarget: cpuPriorReviewedContext, ScopeTenant: podBoundTokenCPUNamespace, SuiteSHA256: strings.Repeat("a", 64)}
}

func cpuMongoOriginalFixture(t *testing.T) (*RunManager, *RunStatus, string) {
	t.Helper()
	cfg := Config{StateDir: t.TempDir()}
	prior := &RunStatus{ID: "run-20", Config: mongoExposureConfig, State: "partial", Namespace: mongoExposureNamespace,
		CleanupStatus: "UNVERIFIED", UnsafeToRetry: true, ScopeTenant: mongoExposureNamespace, ScopeTarget: cpuPriorReviewedContext,
		Finished: "2026-09-25 18:21:14 UTC", Owner: "reviewed-owner",
		Error: "Mongo measurement, audit join or exact cleanup unverified; original result remains partial"}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{prior.ID: prior}, procs: map[string]*exec.Cmd{}, stopping: map[string]bool{}}
	out := cfg.runOutputPath(prior.ID)
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	if original := os.Getenv("MONGO_RUN20_ORIGINALS"); original != "" {
		for _, name := range []string{"mongo-exposure-claim.json", "mongo-exposure-audit-start.json", "mongo-exposure.json", "mongo-exposure-terminal.json", "mongo-exposure-audit-terminal.json", "mongo-exposure-phases.jsonl"} {
			raw, err := os.ReadFile(filepath.Join(original, name))
			if err != nil {
				t.Fatal(err)
			}
			mongoTestWrite(t, filepath.Join(out, name), raw)
		}
		return rm, prior, out
	}
	started := time.Date(2026, 9, 25, 18, 20, 58, 0, time.UTC)
	finished := started.Add(16 * time.Second)
	nonce := strings.Repeat("b", 32)
	claim := map[string]string{"schema": "mongo-exposure-claim-v1", "runId": prior.ID, "nonce": nonce, "at": started.Format(time.RFC3339Nano)}
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-claim.json"), claim)
	start := mongoAuditStart{Schema: "mongo-exposure-audit-start-v1", RunID: prior.ID, SourceIdentity: "authenticated-manager", ConfigSHA256: strings.Repeat("c", 64), Segment: audittransport.Segment{ID: "live", Generation: "one", Anchor: strings.Repeat("d", 32), Size: 100}, Offset: 100, ObservedAt: started.Add(-time.Second).Format(time.RFC3339Nano)}
	startRaw := mongoTestJSON(t, filepath.Join(out, "mongo-exposure-audit-start.json"), start)
	a := mongoArtifactEvidence{Schema: "mongo-exposure-artifact-v1", RunID: prior.ID, Nonce: nonce, Namespace: mongoExposureNamespace,
		Database: "cc_" + nonce, Collection: "owned_" + nonce, CollectionUUID: strings.Repeat("e", 32), ClientPodName: "cat-mongo-read-" + nonce[:12],
		ClientPodUID: "7b7862c1-6155-4fc9-b015-0110f231fd0f", ClientRead: "UNKNOWN", LegitimateBefore: "EXACT_READ", LegitimateAfter: "UNKNOWN", ObservedFinding: "UNKNOWN", Validity: "INCONCLUSIVE", Cleanup: "UNCONFIRMED", SecurityOutcome: "NOT_EVALUATED", StartedAt: started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano)}
	a.Source.NamespaceUID = "11111111-1111-4111-8111-111111111111"
	a.Source.PodUID, a.Source.PolicyUID = "mongo-source-uid", "mongo-policy-uid"
	artifactRaw := mongoTestJSON(t, filepath.Join(out, "mongo-exposure.json"), a)
	terminal := map[string]any{"schema": "mongo-exposure-terminal-v1", "runId": prior.ID, "nonce": nonce,
		"namespaceUID": a.Source.NamespaceUID, "artifactSHA256": mongoHash(artifactRaw), "collectionAbsent": true,
		"clientPodAbsent": true, "namespacePreserved": true, "cleanup": "UNCONFIRMED", "observedAt": finished.Add(time.Millisecond).Format(time.RFC3339Nano)}
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-terminal.json"), terminal)
	auditEnd := mongoAuditTerminal{Schema: "mongo-exposure-audit-terminal-v1", RunID: prior.ID, StartSHA256: mongoHash(startRaw), ArtifactSHA256: mongoHash(artifactRaw), SourceIdentity: start.SourceIdentity, BrainTrace: "GAP", IssueCode: "AUDIT_GAP"}
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-audit-terminal.json"), auditEnd)
	collection := a.Database + "." + a.Collection
	rows := []struct{ phase, resource, name, identity string }{
		{"CREATE_INTENT", "collection", collection, ""}, {"CREATE_ACK", "collection", collection, ""},
		{"UUID_CONFIRMED", "collection", collection, a.CollectionUUID}, {"INSERT_INTENT", "document", nonce, ""},
		{"INSERT_ACK", "document", nonce, nonce}, {"CREATE_INTENT", "pod", a.ClientPodName, ""},
		{"CREATED", "pod", a.ClientPodName, a.ClientPodUID}, {"DELETE_INTENT", "pod", a.ClientPodName, a.ClientPodUID},
		{"ABSENT", "pod", a.ClientPodName, a.ClientPodUID}, {"DROP_INTENT", "collection", collection, a.CollectionUUID},
		{"DROP_ACK", "collection", collection, a.CollectionUUID}, {"ABSENT", "collection", collection, a.CollectionUUID},
	}
	var phases bytes.Buffer
	for i, row := range rows {
		phase := mongoPhaseEvidence{Schema: "mongo-exposure-phase-v1", RunID: prior.ID, Nonce: nonce, Phase: row.phase, Resource: row.resource, Name: row.name, Identity: row.identity, At: started.Add(time.Duration(i+1) * time.Second).Format(time.RFC3339Nano)}
		encoded, err := json.Marshal(phase)
		if err != nil {
			t.Fatal(err)
		}
		phases.Write(encoded)
		phases.WriteByte('\n')
	}
	mongoTestWrite(t, filepath.Join(out, "mongo-exposure-phases.jsonl"), phases.Bytes())
	return rm, prior, out
}

func TestPodBoundCPUPriorAdmitsOnlyOriginalShapedMongoCleanup(t *testing.T) {
	rm, prior, out := cpuMongoOriginalFixture(t)
	if err := rm.podBoundTokenCPUPriorAdmissionLocked(cpuPriorDestination()); err != nil {
		t.Fatalf("verified Mongo cleanup refused: %v", err)
	}
	if !prior.UnsafeToRetry || prior.CleanupStatus != "UNVERIFIED" || prior.State != "partial" {
		t.Fatal("historical Mongo result changed")
	}
	wrongDestination := cpuPriorDestination()
	wrongDestination.ScopeTarget = "arn:aws:eks:us-east-2:753556437180:cluster/other-cluster"
	wrongDestination.Targets[1] = wrongDestination.ScopeTarget
	if err := rm.podBoundTokenCPUPriorAdmissionLocked(wrongDestination); err == nil {
		t.Fatal("Mongo original from another cluster admitted")
	}
	defaultDestination := cpuPriorDestination()
	defaultDestination.ScopeTarget = defaultTargetID
	defaultDestination.Targets[1] = defaultTargetID
	if err := rm.podBoundTokenCPUPriorAdmissionLocked(defaultDestination); err == nil {
		t.Fatal("default target substituted for reviewed cluster")
	}
	baseline := map[string][]byte{}
	for _, name := range []string{"mongo-exposure-claim.json", "mongo-exposure-audit-start.json", "mongo-exposure.json", "mongo-exposure-terminal.json", "mongo-exposure-audit-terminal.json", "mongo-exposure-phases.jsonl"} {
		baseline[name], _ = os.ReadFile(filepath.Join(out, name))
	}
	var original mongoArtifactEvidence
	if err := json.Unmarshal(baseline["mongo-exposure.json"], &original); err != nil {
		t.Fatal(err)
	}
	wrongUID := "7b7862c1-6155-4fc9-b015-0110f231fd0e"
	if wrongUID == original.ClientPodUID {
		wrongUID = "7b7862c1-6155-4fc9-b015-0110f231fd0d"
	}
	wrongUUID := strings.Repeat("f", 32)
	if wrongUUID == original.CollectionUUID {
		wrongUUID = strings.Repeat("a", 32)
	}
	for name, mutate := range map[string]func(){
		"missing original": func() { os.Remove(filepath.Join(out, "mongo-exposure-terminal.json")) },
		"drop ack": func() {
			p := filepath.Join(out, "mongo-exposure-phases.jsonl")
			os.WriteFile(p, bytes.Replace(baseline["mongo-exposure-phases.jsonl"], []byte(`"phase":"DROP_ACK"`), []byte(`"phase":"DROP_UNKNOWN"`), 1), 0600)
		},
		"client UID": func() {
			p := filepath.Join(out, "mongo-exposure-phases.jsonl")
			os.WriteFile(p, bytes.Replace(baseline["mongo-exposure-phases.jsonl"], []byte(original.ClientPodUID), []byte(wrongUID), 1), 0600)
		},
		"collection UUID": func() {
			p := filepath.Join(out, "mongo-exposure-phases.jsonl")
			os.WriteFile(p, bytes.Replace(baseline["mongo-exposure-phases.jsonl"], []byte(original.CollectionUUID), []byte(wrongUUID), 1), 0600)
		},
		"tampered artifact hash": func() {
			p := filepath.Join(out, "mongo-exposure.json")
			os.WriteFile(p, append(baseline["mongo-exposure.json"], ' '), 0600)
		},
		"scope tenant":   func() { prior.ScopeTenant = "voice" },
		"scope target":   func() { prior.ScopeTarget = "another-reviewed-cluster" },
		"active process": func() { rm.procs[prior.ID] = &exec.Cmd{} },
		"third unsafe":   func() { rm.runs["other"] = &RunStatus{ID: "other", Config: "unrelated", UnsafeToRetry: true} },
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			if err := rm.podBoundTokenCPUPriorAdmissionLocked(cpuPriorDestination()); err == nil {
				t.Fatal("unproved predecessor admitted")
			}
			for n, raw := range baseline {
				mongoTestWrite(t, filepath.Join(out, n), raw)
			}
			prior.ScopeTenant = mongoExposureNamespace
			prior.ScopeTarget = cpuPriorReviewedContext
			rm.procs[prior.ID] = nil
			delete(rm.runs, "other")
		})
	}
}

func TestPodBoundCPUPriorAdmitsReviewedVoiceAndMongoOnly(t *testing.T) {
	cfg := disjointFixtureConfig(t)
	voice, _ := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	_, mongo, mongoOut := cpuMongoOriginalFixture(t)
	mongoDest := cfg.runOutputPath(mongo.ID)
	if err := os.MkdirAll(mongoDest, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mongo-exposure-claim.json", "mongo-exposure-audit-start.json", "mongo-exposure.json", "mongo-exposure-terminal.json", "mongo-exposure-audit-terminal.json", "mongo-exposure-phases.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(mongoOut, name))
		if err != nil {
			t.Fatal(err)
		}
		mongoTestWrite(t, filepath.Join(mongoDest, name), raw)
	}
	rm := NewRunManager(cfg)
	rm.runs[mongo.ID] = mongo
	if err := rm.podBoundTokenCPUPriorAdmissionLocked(cpuPriorDestination()); err != nil {
		t.Fatalf("two separately proven, disjoint predecessors refused: %v", err)
	}
	if !rm.runs[voice.ID].UnsafeToRetry || !rm.runs[mongo.ID].UnsafeToRetry {
		t.Fatal("historical unsafe status was changed")
	}
	rm.procs[voice.ID] = &exec.Cmd{}
	if err := rm.podBoundTokenCPUPriorAdmissionLocked(cpuPriorDestination()); err == nil {
		t.Fatal("active Voice predecessor admitted")
	}
}

func TestPodBoundCPUMongoLiveAbsenceRejectsReplacement(t *testing.T) {
	proof := mongoEarlyCleanupProof{Present: true, NamespaceUID: "11111111-1111-4111-8111-111111111111", ClientPodName: "cat-mongo-read-bbbbbbbbbbbb", ClientPodUID: "7b7862c1-6155-4fc9-b015-0110f231fd0f"}
	kc := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mongoExposureNamespace, UID: "11111111-1111-4111-8111-111111111111"}})
	if err := podBoundCPUMongoLiveAbsence(context.Background(), kc, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := kc.CoreV1().Pods(mongoExposureNamespace).Create(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: proof.ClientPodName, Namespace: mongoExposureNamespace, UID: "replacement-uid"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podBoundCPUMongoLiveAbsence(context.Background(), kc, proof); err == nil {
		t.Fatal("replacement client Pod accepted")
	}
	if err := kc.CoreV1().Pods(mongoExposureNamespace).Delete(context.Background(), proof.ClientPodName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ns, _ := kc.CoreV1().Namespaces().Get(context.Background(), mongoExposureNamespace, metav1.GetOptions{})
	ns.UID = "changed"
	kc.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	if err := podBoundCPUMongoLiveAbsence(context.Background(), kc, proof); err == nil {
		t.Fatal("changed namespace UID accepted")
	}
}
