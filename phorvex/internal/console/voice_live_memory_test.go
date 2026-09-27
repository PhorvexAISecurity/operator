package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestVoiceMemoryFireRejectsUnreviewedInputBeforeEffect(t *testing.T) {
	s := NewServer(Config{StateDir: t.TempDir()})
	for _, body := range []string{
		`{}`,
		`{"scenario":"ai2-agent-memory-contamination","caller":"+15551230001"}`,
		`{"scenario":"ai2-agent-memory-contamination"}{}`,
		`{"scenario":"ai2-agent-excessive-agency"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/voice/live/fire", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.voiceMemoryLiveFire(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q status=%d, want 400", body, w.Code)
		}
	}
}

func TestVoiceMemoryCompatibilityRequiresSourceRollout(t *testing.T) {
	rows := compatibleLive(appStack{Namespace: "voice", Workload: true, Armed: true})
	for _, row := range rows {
		if row.ID == voiceMemoryScenario && (row.Armed || !row.Compatible) {
			t.Fatalf("Voice scenario must be compatible but unarmed before the hook: %+v", row)
		}
	}
	rows = compatibleLive(appStack{Namespace: "voice", Workload: true, Armed: true, VoiceMemoryHook: true})
	for _, row := range rows {
		if row.ID == voiceMemoryScenario && (!row.Armed || !row.Compatible) {
			t.Fatalf("Voice scenario should be selectable only after hook declaration: %+v", row)
		}
	}
}

func TestVoiceMemoryReceiptRequiresExactCallerPodAndBenignNote(t *testing.T) {
	reply := voiceProbeReply{WSOpened: true}
	reply.Receipt.Version = 1
	reply.Receipt.CallSIDHash = voiceMemoryDigest("CAexample01234567")
	reply.Receipt.CallerSHA256 = voiceMemoryDigest("+15551230001")
	reply.Receipt.NoteSHA256 = []string{voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest(voiceMemoryBenignNote)}
	reply.Receipt.SourceSHA256 = voiceMemorySourceSHA256
	reply.Receipt.PodUID = "pod-uid"
	reply.Receipt.ObservedAtUnixMs = 1
	if !voiceMemoryReceiptMatches(reply, "CAexample01234567", "+15551230001", "pod-uid", voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest(voiceMemoryBenignNote), true) {
		t.Fatal("valid digest-only actual context receipt rejected")
	}
	if voiceMemoryReceiptMatches(reply, "CAother01234567", "+15551230001", "pod-uid", voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest(voiceMemoryBenignNote), true) {
		t.Fatal("different call SID accepted")
	}
	if voiceMemoryReceiptMatches(reply, "CAexample01234567", "+15551230002", "pod-uid", voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest(voiceMemoryBenignNote), true) {
		t.Fatal("different caller accepted")
	}
	if voiceMemoryReceiptMatches(reply, "CAexample01234567", "+15551230001", "other-pod", voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest(voiceMemoryBenignNote), true) {
		t.Fatal("different Pod accepted")
	}
	if voiceMemoryReceiptMatches(reply, "CAexample01234567", "+15551230001", "pod-uid", voiceMemoryDigest(voiceMemoryAttackNote), voiceMemoryDigest("different benign"), true) {
		t.Fatal("benign-control drift accepted")
	}
}

func TestVoiceMemoryServingPodRequiresPinAndReady(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-uid"),
		Annotations: map[string]string{"phorvex.ai/voice-memory-source-sha256": voiceMemorySourceSHA256,
			"phorvex.ai/voice-memory-policy-configmap": "voice-memory-policy"},
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet"}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "bot"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if !voiceMemoryServingPod(pod, &appsv1.Deployment{}) {
		t.Fatal("pinned ready Pod refused")
	}
	pod.Annotations["phorvex.ai/voice-memory-source-sha256"] = strings.Repeat("0", 64)
	if voiceMemoryServingPod(pod, &appsv1.Deployment{}) {
		t.Fatal("wrong source accepted")
	}
}

func TestVoiceMemoryEventRequiresAdmissionStampedCreator(t *testing.T) {
	creator := "system:serviceaccount:phorvex:console"
	var manifest map[string]any
	s := NewServer(Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) != 5 || args[0] != "create" || args[1] != "-f" {
			t.Fatal("unexpected event transport")
		}
		raw, err := os.ReadFile(args[2])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), voiceMemoryAttackNote) {
			t.Fatal("raw note entered event")
		}
		if err = json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		meta := manifest["metadata"].(map[string]any)
		if _, hasNamespace := meta["namespace"]; hasNamespace {
			t.Fatal("cluster-scoped SecurityEvent manifest must omit namespace")
		}
		spec := manifest["spec"].(map[string]any)
		return string(mustJSON(t, map[string]any{"metadata": map[string]any{
			"name": meta["name"], "uid": "event-uid",
			"creationTimestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"annotations": map[string]any{"phorvex.ai/creator-identity": creator,
				"phorvex.ai/console-target-pod-uid":      "pod-uid",
				"phorvex.ai/voice-memory-observation-v1": meta["annotations"].(map[string]any)["phorvex.ai/voice-memory-observation-v1"]}},
			"spec": spec})), nil
	}})
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-a", UID: types.UID("pod-uid")}}
	snap := voiceMemorySnapshot{DeploymentUID: "11111111-1111-4111-8111-111111111111",
		PolicyUID: "22222222-2222-4222-8222-222222222222", PolicyGeneration: 1, EventCreator: creator}
	event, err := s.createVoiceMemoryEvent(t.TempDir(), "voice-memory-case", pod, snap, "+15551230001", voiceMemoryDigest(voiceMemoryAttackNote), time.Now().Add(-time.Second))
	if err != nil || event.EventUID != "event-uid" || !event.Observed {
		t.Fatalf("stamped event rejected: %v %+v", err, event)
	}
	annotation := manifest["metadata"].(map[string]any)["annotations"].(map[string]any)["phorvex.ai/voice-memory-observation-v1"].(string)
	if !strings.Contains(annotation, `"evidenceSource":"TEST_INJECTED"`) {
		t.Fatal("signal origin absent")
	}
	creator = "system:serviceaccount:voice:unreviewed"
	if _, err := s.createVoiceMemoryEvent(t.TempDir(), "voice-memory-case", pod, snap, "+15551230001", voiceMemoryDigest(voiceMemoryAttackNote), time.Now().Add(-time.Second)); err == nil {
		t.Fatal("different authenticated creator accepted")
	}
}

func TestVoiceMemoryEventInventoryUsesClusterScope(t *testing.T) {
	s := NewServer(Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || strings.Join(args, " ") != "get securityevents -o json" {
			t.Fatalf("cluster-scoped event inventory expected, got %s %q", bin, args)
		}
		return string(mustJSON(t, map[string]any{"items": []any{map[string]any{
			"metadata": map[string]any{"creationTimestamp": time.Now().UTC().Format(time.RFC3339Nano)},
			"spec":     map[string]any{"targets": []string{"voice/voice-bot-a"}, "rule": map[string]any{"type": model.AttackVectorVoiceMemory}},
		}}})), nil
	}})
	recent, err := s.voiceMemoryRecentEvent("voice-bot-a")
	if err != nil || !recent {
		t.Fatalf("recent cluster-scoped Voice event not found: recent=%t err=%v", recent, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
