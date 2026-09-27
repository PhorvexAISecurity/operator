package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

func guardrailAvailabilityPinnedProfile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../build/test-harness/config.guardrail-availability-recovery.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	digest := strings.Repeat("a", 64)
	image := "example.test/reviewed@sha256:" + digest
	for key, value := range map[string]string{
		"__SET_LOGICAL_CLUSTER_TARGET__": "reviewed-cluster", "__SET_REVIEWED_KUBE_SYSTEM_UID__": uid, "__SET_REVIEWED_VLLM_POD_NAME__": "vllm-pod", "__SET_REVIEWED_VLLM_POD_UID__": uid, "__SET_REVIEWED_VLLM_IMAGE_ID__": image, "__SET_REVIEWED_VLLM_SERVICE_UID__": uid, "__SET_REVIEWED_GUARDRAIL_SOURCE_CONFIGMAP_UID__": uid, "__SET_REVIEWED_GUARDRAIL_SOURCE_SHA256__": digest, "__SET_REVIEWED_GUARDRAIL_JOURNAL_NAME__": "guardrail-journal", "__SET_REVIEWED_GUARDRAIL_JOURNAL_UID__": uid, "__SET_REVIEWED_MANAGER_POD_NAME__": "manager-pod", "__SET_REVIEWED_MANAGER_POD_UID__": uid, "__SET_REVIEWED_MANAGER_IMAGE_ID__": image, "__SET_REVIEWED_CONSOLE_DEPLOYMENT_NAME__": "console-deployment", "__SET_REVIEWED_CONSOLE_DEPLOYMENT_UID__": uid, "__SET_REVIEWED_CONSOLE_IMAGE_ID__": image, "__SET_REVIEWED_POLICY_UID__": uid, "__SET_REVIEWED_POLICY_GENERATION__": "1", "__SET_REVIEWED_MODEL_ID__": "Qwen/Qwen2.5-7B-Instruct-AWQ", "__SET_REVIEWED_CONSOLE_EVENT_CREATOR__": "system:serviceaccount:phorvex-system:console-sa", "__SET_REVIEWED_AUDIT_SOURCE_URL__": "https://audit.phorvex-system.svc:8445", "__SET_REVIEWED_AUDIT_SERVER_DNS__": "audit.phorvex-system.svc",
	} {
		s = strings.ReplaceAll(s, key, value)
	}
	return []byte(s)
}

func TestGuardrailAvailabilityCappedWriter(t *testing.T) {
	w := availabilityCappedWriter{max: 4}
	if n, err := w.Write([]byte("abcdefgh")); err != nil || n != 8 || string(w.Bytes()) != "abcd" || !w.overflow {
		t.Fatalf("capped writer retained excess output: n=%d err=%v len=%d overflow=%v", n, err, w.Len(), w.overflow)
	}
	if n, err := w.Write([]byte("later")); err != nil || n != 5 || w.Len() != 4 {
		t.Fatal("capped writer grew after overflow")
	}
}

func TestGuardrailAvailabilityPrePOSTAdmissionJoins(t *testing.T) {
	before := availabilitySnapshot{TargetPodUID: "target-uid", TargetContainerID: "containerd://target", TargetImageID: "reviewed-image", SourceUID: "source-uid", SourceSHA256: strings.Repeat("a", 64), JournalUID: "journal-uid", JournalResourceVersion: "24", Receipt: json.RawMessage(`{"generation":24}`), ActiveVariant: "pgv1", PodVariant: "pgv1", GuardrailEpoch: "epoch-1", ModelIdentity: json.RawMessage(`{"id":"reviewed-model"}`)}
	if err := availabilityAdmissionMatches(before, before, before); err != nil {
		t.Fatalf("unchanged baseline refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*availabilitySnapshot)
	}{
		{"variant", func(s *availabilitySnapshot) { s.ActiveVariant = "pgv2" }},
		{"protected journal", func(s *availabilitySnapshot) {
			s.JournalResourceVersion = "25"
			s.Receipt = json.RawMessage(`{"generation":25}`)
		}},
		{"source", func(s *availabilitySnapshot) { s.SourceSHA256 = strings.Repeat("b", 64) }},
		{"model", func(s *availabilitySnapshot) { s.ModelIdentity = json.RawMessage(`{"id":"changed-model"}`) }},
		{"target container", func(s *availabilitySnapshot) { s.TargetContainerID = "containerd://replacement" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := before
			tc.change(&changed)
			if availabilityAdmissionMatches(before, changed, before) == nil || availabilityAdmissionMatches(before, before, changed) == nil {
				t.Fatal("prepost or immediate-prepost drift admitted")
			}
		})
	}
	population := func(name, uid, id, image string, extra bool, continuation string) map[string]any {
		pod := map[string]any{"metadata": map[string]any{"name": name, "uid": uid}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "guardrail", "containerID": id, "imageID": image, "ready": true, "restartCount": float64(0)}}}}
		items := []any{pod}
		if extra {
			items = append(items, pod)
		}
		return map[string]any{"metadata": map[string]any{"continue": continuation}, "items": items}
	}
	if err := availabilityOneTargetPopulation(population("target-pod", before.TargetPodUID, before.TargetContainerID, before.TargetImageID, false, ""), before, "target-pod"); err != nil {
		t.Fatalf("sole exact target refused: %v", err)
	}
	for _, p := range []map[string]any{
		population("target-pod", before.TargetPodUID, before.TargetContainerID, before.TargetImageID, true, ""),
		population("target-pod", before.TargetPodUID, before.TargetContainerID, before.TargetImageID, false, "next-page"),
		population("target-pod", "other-uid", before.TargetContainerID, before.TargetImageID, false, ""),
		population("other-pod", before.TargetPodUID, before.TargetContainerID, before.TargetImageID, false, ""),
		population("target-pod", before.TargetPodUID, "containerd://replacement", before.TargetImageID, false, ""),
	} {
		if err := availabilityOneTargetPopulation(p, before, "target-pod"); err == nil {
			t.Fatal("non-exact or incomplete target population admitted")
		}
	}
}

func TestGuardrailAvailabilityOriginalKubeLabelBoundary(t *testing.T) {
	e := availabilityEvidence{files: map[string][]byte{
		"kube-001-prepost-target.json":           []byte(`{"metadata":{"uid":"before"}}`),
		"kube-002-immediate-prepost-target.json": []byte(`{"metadata":{"uid":"immediate"}}`),
	}}
	var before, immediate map[string]any
	if err := e.findKube("prepost-target", &before); err != nil || availabilityUID(before) != "before" {
		t.Fatalf("exact prepost original lost to nested label: %v", err)
	}
	if err := e.findKube("immediate-prepost-target", &immediate); err != nil || availabilityUID(immediate) != "immediate" {
		t.Fatalf("exact immediate original absent: %v", err)
	}
	e.files["kube-003-prepost-target.json"] = []byte(`{"metadata":{"uid":"duplicate"}}`)
	if err := e.findKube("prepost-target", &before); err == nil {
		t.Fatal("duplicate exact prepost original admitted")
	}
}

func TestGuardrailAvailabilityConsoleRolloutIdentity(t *testing.T) {
	p, err := parseGuardrailAvailabilityProfile(guardrailAvailabilityPinnedProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	owner := func(kind, name, uid string) []any {
		return []any{map[string]any{"kind": kind, "name": name, "uid": uid, "controller": true}}
	}
	mk := func(name, uid, image string) (map[string]any, map[string]any, map[string]any) {
		console := map[string]any{"metadata": map[string]any{"name": name, "uid": uid, "ownerReferences": owner("ReplicaSet", "console-rs", "rs-uid")}, "spec": map[string]any{"serviceAccountName": "console-sa"}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "console", "containerID": "containerd://" + uid, "imageID": image, "ready": true, "restartCount": float64(0)}}}}
		rs := map[string]any{"metadata": map[string]any{"name": "console-rs", "uid": "rs-uid", "ownerReferences": owner("Deployment", p.Fixture.ConsoleDeploymentName, p.Fixture.ConsoleDeploymentUID)}}
		dep := map[string]any{"metadata": map[string]any{"name": p.Fixture.ConsoleDeploymentName, "uid": p.Fixture.ConsoleDeploymentUID}}
		return console, rs, dep
	}
	oldPod, oldRS, oldDep := mk("console-old", "old-uid", p.Fixture.ConsoleImageID)
	newPod, newRS, newDep := mk("console-new", "new-uid", p.Fixture.ConsoleImageID)
	if err := availabilityCheckConsoleIdentity(p, "console-old", "old-uid", oldPod, oldRS, oldDep); err != nil {
		t.Fatal(err)
	}
	if err := availabilityCheckConsoleIdentity(p, "console-new", "new-uid", newPod, newRS, newDep); err != nil {
		t.Fatalf("new rollout with unchanged reviewed Deployment profile refused: %v", err)
	}
	if err := availabilityCheckConsoleIdentity(p, "console-old", "old-uid", newPod, newRS, newDep); err == nil {
		t.Fatal("in-run Pod replacement accepted")
	}
	wrongImage, rs, dep := mk("console-new", "new-uid", "example.test/wrong@sha256:"+strings.Repeat("b", 64))
	if err := availabilityCheckConsoleIdentity(p, "console-new", "new-uid", wrongImage, rs, dep); err == nil {
		t.Fatal("unreviewed image accepted")
	}
	newRS["metadata"].(map[string]any)["ownerReferences"] = owner("Deployment", p.Fixture.ConsoleDeploymentName, "other-deployment-uid")
	if err := availabilityCheckConsoleIdentity(p, "console-new", "new-uid", newPod, newRS, newDep); err == nil {
		t.Fatal("wrong Deployment owner accepted")
	}
}

func TestGuardrailAvailabilityProfileSelfRolloutAndScope(t *testing.T) {
	raw := guardrailAvailabilityPinnedProfile(t)
	p, err := parseGuardrailAvailabilityProfile(raw)
	if err != nil || p.Fixture.ConsoleDeploymentUID == "" {
		t.Fatalf("stable Deployment profile refused: %v", err)
	}
	if strings.Contains(string(raw), "consolePodUID:") || strings.Contains(string(raw), "\"__SET_") {
		t.Fatal("profile still contains self Pod pin or placeholder")
	}
	for _, field := range []string{"consoleDeploymentName: \"console-deployment\"", "consoleDeploymentUID: \"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"", "eventCreator: \"system:serviceaccount:phorvex-system:console-sa\""} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("expected reviewed field %s absent", field)
		}
	}
	for _, changed := range [][]byte{[]byte(strings.Replace(string(raw), "console-deployment", "", 1)), []byte(strings.Replace(string(raw), "consoleDeploymentUID: \"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"", "consolePodUID: \"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"", 1)), []byte(strings.Replace(string(raw), "console-sa", "wrong/sa", 1))} {
		if _, err := parseGuardrailAvailabilityProfile(changed); err == nil {
			t.Fatal("unsafe self identity profile admitted")
		}
	}
	owner := runOwnership{Target: "reviewed-cluster", Tenant: "vllm", FixtureTenant: "phorvex-system", Config: guardrailAvailabilityConfig}
	for _, tc := range []struct {
		targets, tenants []string
		want             bool
	}{{[]string{hostTargetID, "reviewed-cluster"}, []string{"vllm", "phorvex-system"}, true}, {[]string{"reviewed-cluster"}, []string{"vllm", "phorvex-system"}, false}, {[]string{hostTargetID}, []string{"vllm", "phorvex-system"}, false}, {[]string{hostTargetID, "reviewed-cluster"}, []string{"vllm"}, false}, {[]string{hostTargetID, "reviewed-cluster"}, []string{"phorvex-system"}, false}} {
		if got := runVisibleTo(&Principal{Targets: tc.targets, Tenants: tc.tenants}, owner); got != tc.want {
			t.Fatalf("scope result %v want %v", got, tc.want)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, allowedConfigs[guardrailAvailabilityConfig].File)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	rm := NewRunManager(Config{Root: dir, HarnessDir: dir, GuardrailAvailabilityProfileSHA256: digest})
	if _, err := rm.SuiteDestination(guardrailAvailabilityConfig); err == nil {
		t.Fatal("default-off suite admitted")
	}
	for _, name := range []string{guardrailAvailabilityConfig, "ai-vllm-guardrail-availability-recovery"} {
		if _, err := rm.StartScenario([]string{name}, false, false, "reviewed-cluster", "vllm", "", ""); err == nil {
			t.Fatal("named recovery entered generic scenario")
		}
	}
}

func TestGuardrailAvailabilityOriginalReplyClasses(t *testing.T) {
	marker := "CNR_1234abcd"
	for _, tc := range []struct {
		name      string
		status    int
		raw, want string
	}{
		{"typed block", 403, `{"error":{"type":"guardrail_blocked"}}`, "GUARDRAIL_BLOCKED"},
		{"marker in typed error", 403, `{"error":{"type":"guardrail_blocked","message":"CNR_1234abcd"}}`, "UNKNOWN_CONTRADICTORY_403"},
		{"escaped marker in typed error", 403, `{"error":{"type":"guardrail_blocked","message":"CNR_\u0031\u0032\u0033\u0034abcd"}}`, "UNKNOWN_CONTRADICTORY_403"},
		{"typed error plus completion", 403, `{"error":{"type":"guardrail_blocked"},"choices":[{"message":{"role":"assistant","content":"OK"}}]}`, "UNKNOWN_CONTRADICTORY_403"},
		{"say ok", 200, `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`, "OK"},
		{"missing completion", 200, `{"choices":[{"message":{}}]}`, "UNKNOWN_COMPLETION_SHAPE"},
		{"null completion", 200, `{"choices":[{"message":{"role":"assistant","content":null}}]}`, "UNKNOWN_COMPLETION_SHAPE"},
		{"duplicate body", 403, `{"error":{"type":"guardrail_blocked"},"error":{"type":"guardrail_blocked"}}`, "UNKNOWN_MALFORMED_REPLY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := availabilityClass("say_ok", tc.status, []byte(tc.raw), marker); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func availabilityAuditLine(i int, selected bool, event bool) []byte {
	row := map[string]any{"kind": "phorvex.decision", "namespace": "vllm", "pod": "target-pod", "time": time.Date(2026, 9, 25, 0, 0, i, 0, time.UTC).Format(time.RFC3339Nano), "action": "noop", "selected": false, "actuated": false, "decisionTrace": map[string]any{"assetUID": "target-uid", "policyUID": "policy-uid", "assetNamespace": "vllm", "assetName": "target-pod", "decisionID": fmt.Sprintf("d%02d", i), "tickID": fmt.Sprintf("t%02d", i), "dispatchOutcome": "not-attempted"}}
	if selected {
		row["action"] = "guardrail-rotate"
		row["selected"] = true
		row["actuated"] = true
		row["dispatchOutcome"] = "emitted"
		row["decisionTrace"].(map[string]any)["dispatchOutcome"] = "emitted"
		row["eventEvidence"] = 0.95
	}
	if event {
		row["events"] = []map[string]any{{"name": "event-1", "eventUID": "event-uid", "creatorIdentity": "system:serviceaccount:phorvex-system:console-sa", "targetPodUID": "target-uid", "targetsPod": true, "trustVerdict": "trusted", "present": true, "weight": 0.95}}
	}
	b, _ := json.Marshal(row)
	return append(b, '\n')
}

func TestGuardrailAvailabilitySeventeenAuditRowsAndUnboundCounterexamples(t *testing.T) {
	before := availabilitySnapshot{TargetPodUID: "target-uid", PolicyUID: "policy-uid"}
	event := &availabilityEvent{UID: "event-uid", Name: "event-1", CreatorIdentity: "system:serviceaccount:phorvex-system:console-sa"}
	var trace []byte
	for i := 0; i < 17; i++ {
		trace = append(trace, availabilityAuditLine(i, i == 9, i >= 9)...)
	}
	rows, unbound, err := availabilityProjectAudit(trace, before, "target-pod", event)
	if err != nil || unbound != 0 || len(rows) != 17 {
		t.Fatalf("positive rows=%d unbound=%d err=%v", len(rows), unbound, err)
	}
	selected := 0
	for _, row := range rows {
		if row.Selected {
			selected++
			if row.Action != "guardrail-rotate" || row.DispatchOutcome != "emitted" || row.EventCoverage != "EXACT_TRUSTED_EVENT_OBSERVED" {
				t.Fatalf("selected row differs: %+v", row)
			}
		} else if row.Action != "noop" || row.DispatchOutcome != "not-attempted" || row.Actuated {
			t.Fatalf("passive row differs: %+v", row)
		}
	}
	if selected != 1 {
		t.Fatalf("selected=%d", selected)
	}
	var bad map[string]any
	if err := json.Unmarshal(availabilityAuditLine(18, true, true), &bad); err != nil {
		t.Fatal(err)
	}
	bad["namespace"] = "other"
	raw, _ := json.Marshal(bad)
	_, unbound, err = availabilityProjectAudit(append(trace, append(raw, '\n')...), before, "target-pod", event)
	if err != nil || unbound != 1 {
		t.Fatalf("contradictory exact UID should be unbound: %d %v", unbound, err)
	}
	bad["namespace"] = "vllm"
	bad["selected"] = nil
	raw, _ = json.Marshal(bad)
	_, unbound, err = availabilityProjectAudit(append(trace, append(raw, '\n')...), before, "target-pod", event)
	if err != nil || unbound != 1 {
		t.Fatalf("null selection should be unbound: %d %v", unbound, err)
	}
}

func TestGuardrailAvailabilityRotatedAuditAlias(t *testing.T) {
	start := availabilityAuditStart{Segment: audittransport.Segment{ID: "live", Generation: "gen-a", Size: 100, Anchor: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, CheckpointSize: 100, AlignedOffset: 100}
	m := audittransport.Manifest{Segments: []audittransport.Segment{{ID: "live", Generation: "gen-c", Size: 5, Anchor: "cccccccccccccccccccccccccccccccc"}, {ID: "backup-1", Generation: "gen-b", Size: 50, Anchor: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, {ID: "backup-2", Generation: "gen-a", Size: 150, Anchor: start.Segment.Anchor}}}
	spans, err := availabilitySpans(start, m)
	if err != nil || len(spans) != 3 || spans[0][0].(audittransport.Segment).ID != "backup-2" {
		t.Fatalf("rotated alias not preserved: %+v %v", spans, err)
	}
	mutated := m
	mutated.Segments = append([]audittransport.Segment(nil), m.Segments...)
	mutated.Segments[2].Anchor = "dddddddddddddddddddddddddddddddd"
	if _, err := availabilitySpans(start, mutated); err == nil {
		t.Fatal("changed original generation anchor accepted")
	}
}

func TestGuardrailAvailabilityObserveModeCannotEarnBlockedCredit(t *testing.T) {
	put := func(files map[string][]byte, name string, v any) { raw, _ := json.Marshal(v); files[name] = raw }
	e := availabilityEvidence{files: map[string][]byte{}}
	e.p.Fixture.GuardrailJournalName = "journal"
	s := availabilitySnapshot{TargetPodUID: "target-uid", TargetContainerID: "containerd://target", TargetImageID: "image@sha256:" + strings.Repeat("a", 64), SourceUID: "source-uid", JournalUID: "journal-uid", JournalResourceVersion: "44", SourceSHA256: availabilityHash([]byte("source")), Receipt: json.RawMessage(`{"generation":1}`), ActiveVariant: "pgv1", PodVariant: "pgv1", GuardrailEpoch: "epoch"}
	name := "before-canary-pre"
	put(e.files, name+"-snapshot.json", s)
	put(e.files, "kube-001-"+name+"-target.json", map[string]any{"metadata": map[string]any{"uid": "target-uid", "annotations": map[string]any{"phorvex.ai/guardrail-variant": "pgv1"}, "labels": map[string]any{"phorvex.ai/guardrail-epoch": "epoch"}}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "guardrail", "containerID": s.TargetContainerID, "imageID": s.TargetImageID, "ready": true, "restartCount": float64(0)}}}})
	put(e.files, "kube-002-"+name+"-source.json", map[string]any{"metadata": map[string]any{"uid": "source-uid"}, "data": map[string]any{"guardrail_proxy.py": "source"}})
	put(e.files, "kube-003-"+name+"-journal.json", map[string]any{"kind": "ConfigMap", "metadata": map[string]any{"name": "journal", "namespace": "phorvex-system", "uid": "journal-uid", "resourceVersion": "44"}, "data": map[string]any{"receipt": `{"generation":1}`}})
	put(e.files, name+"-runtime.json", map[string]any{"_mountedSourceSHA256": s.SourceSHA256, "8000/v1/guardrail/state": map[string]any{"status": 200, "body": map[string]any{"mode": "observe", "ready": true, "active": "pgv1", "loaded": []string{"pgv1", "pgv2"}, "thresholds": map[string]float64{"pgv1": 0.5, "pgv2": 0.5}}}})
	if _, err := e.snapshot(name); err == nil || !strings.Contains(err.Error(), "guardrail state") {
		t.Fatalf("observe mode accepted as enforcing: %v", err)
	}
}

func TestGuardrailAvailabilityProtectedOperationRejectsWrongFields(t *testing.T) {
	p := guardrailAvailabilityProfile{}
	p.Fixture.PolicyName = "vllm-defense"
	p.Fixture.PolicyUID = "policy-uid"
	p.Fixture.PodName = "target-pod"
	p.Fixture.PodUID = "target-uid"
	before := availabilitySnapshot{PolicyUID: "policy-uid", TargetPodUID: "target-uid", ActiveVariant: "pgv1", PodVariant: "pgv1"}
	before.Receipt = json.RawMessage(`{"generation":7,"operationID":"old"}`)
	tick := "tick-1"
	op := availabilityOperationID(tick, p.Fixture.PolicyUID, "vllm", p.Fixture.PodUID)
	receipt := map[string]any{"version": 9, "kind": "guardrail-rotate", "effectDomain": "guardrail-variant-v1", "phase": "terminal-full", "generation": 8, "priorVariant": "pgv1", "nextVariant": "pgv2", "operationID": op, "tickID": tick, "policyNamespace": "vllm", "policyName": p.Fixture.PolicyName, "policyUID": p.Fixture.PolicyUID, "targetName": p.Fixture.PodName, "targetUID": p.Fixture.PodUID, "expectedGuardrail": map[string]any{"present": true, "value": availabilityEpoch(op)}}
	encode := func() availabilitySnapshot {
		raw, _ := json.Marshal(receipt)
		return availabilitySnapshot{Receipt: raw, ActiveVariant: "pgv2", PodVariant: "pgv2", GuardrailEpoch: availabilityEpoch(op)}
	}
	if err := availabilityCheckTransition(before, encode(), p); err != nil {
		t.Fatalf("exact transition rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		value any
	}{{"phase", "dispatching"}, {"policyUID", "other-policy"}, {"targetUID", "other-target"}, {"kind", "kv-reset"}, {"effectDomain", "other"}, {"policyName", "other-policy"}} {
		old := receipt[tc.name]
		receipt[tc.name] = tc.value
		if err := availabilityCheckTransition(before, encode(), p); err == nil {
			t.Errorf("mutated %s accepted", tc.name)
		}
		receipt[tc.name] = old
	}
}

func TestGuardrailAvailabilityChildAbsoluteChatDeadline(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	for _, slow := range []bool{false, true} {
		t.Run(fmt.Sprint("slow=", slow), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw := []byte(`{"error":{"type":"guardrail_blocked"}}`)
				w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
				w.WriteHeader(403)
				if !slow {
					_, _ = w.Write(raw)
					return
				}
				for _, b := range raw {
					_, _ = w.Write([]byte{b})
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					time.Sleep(80 * time.Millisecond)
				}
			})}
			go func() { _ = server.Serve(listener) }()
			defer server.Close()
			port := listener.Addr().(*net.TCPAddr).Port
			code := strings.ReplaceAll(availabilityChatCode, ",8000,", fmt.Sprintf(",%d,", port))
			code = strings.Replace(code, "signal.alarm(35)", "signal.alarm(1)", 1)
			cmd := exec.Command("python3", "-B", "-c", code)
			cmd.Stdin = bytes.NewReader([]byte(`{}`))
			started := time.Now()
			out, err := cmd.CombinedOutput()
			if slow {
				if err == nil || time.Since(started) > 2*time.Second {
					t.Fatalf("slow trickle survived child alarm: elapsed=%v err=%v output=%q", time.Since(started), err, out)
				}
			} else {
				if err != nil {
					t.Fatalf("fast fixed reply failed: %v %q", err, out)
				}
				var wire availabilityHTTP
				if availabilityDecode(bytes.TrimSpace(out), &wire) != nil || wire.Status != 403 {
					t.Fatalf("fast HTTP envelope malformed: %q", out)
				}
			}
		})
	}
}
