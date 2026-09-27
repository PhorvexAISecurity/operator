package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiteOutputFixedJournalPinsIncarnationAndPriorReceipts(t *testing.T) {
	prior := map[string]any{"version": 2, "phase": "terminal-full", "policyUID": "policy-uid",
		"ruleConfigMapName": "litellm-output-rule-00",
		"operationId":       "op-prior", "rule": map[string]any{"runNonce": strings.Repeat("a", 32)}}
	current := []any{prior}
	uid := "journal-uid"
	server := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) != 7 || args[0] != "-n" || args[1] != "phorvex-system" ||
			args[2] != "get" || args[3] != "configmap" || args[4] != "phorvex-litellm-output-journal" {
			return "", errors.New("unexpected journal GET")
		}
		value := map[string]any{"metadata": map[string]any{"name": "phorvex-litellm-output-journal", "uid": uid,
			"labels": map[string]any{"phorvex.ai/litellm-output-policy-journal": "v2"}},
			"data": map[string]any{"receipts.json": string(liteOutputCanonical(map[string]any{
				"version": 2, "receipts": current}))}}
		encoded, _ := json.Marshal(value)
		return string(encoded), nil
	}}}
	w := &liteOutputWorker{base: &liteLiveWorker{s: server, out: t.TempDir(), ctx: context.Background()}}
	rows, err := w.readJournal("initial")
	if err != nil || len(rows) != 1 || w.journalCMUID != uid {
		t.Fatalf("initial journal: %v, %+v", err, rows)
	}
	w.priorJournal = rows
	uid = "replacement-uid"
	if _, err := w.readJournal("replacement"); err == nil {
		t.Fatal("accepted replacement protected journal")
	}
	uid = "journal-uid"
	current = []any{map[string]any{"version": 2, "phase": "aborted-no-write", "policyUID": "policy-uid",
		"ruleConfigMapName": "litellm-output-rule-00",
		"operationId":       "op-prior", "rule": map[string]any{"runNonce": strings.Repeat("a", 32)}},
		map[string]any{"version": 2, "phase": "terminal-full", "policyUID": "policy-uid",
			"ruleConfigMapName": "litellm-output-rule-01",
			"operationId":       "op-new", "rule": map[string]any{"runNonce": strings.Repeat("b", 32)}}}
	if _, err := w.pollJournal(&availabilityEvent{UID: "event-uid"}); err == nil ||
		!strings.Contains(err.Error(), "prior protected output receipt changed") {
		t.Fatalf("accepted modified prior receipt: %v", err)
	}
}

func TestLiteOutputHistoryPreservesTerminalAndAbortedRows(t *testing.T) {
	entry := map[string]any{"objectiveId": "ai2-sensitive-info-disclosure", "runNonce": strings.Repeat("a", 32),
		"operationId": "selected-op", "ruleSHA256": strings.Repeat("b", 64)}
	terminal := map[string]any{"phase": "terminal-full", "operationId": "selected-op",
		"ruleSHA256": strings.Repeat("b", 64), "rule": map[string]any{
			"objectiveId": "ai2-sensitive-info-disclosure", "runNonce": strings.Repeat("a", 32)}}
	aborted := map[string]any{"phase": "aborted-no-write", "operationId": "aborted-op",
		"rule": map[string]any{"objectiveId": "ai2-system-prompt-leakage", "runNonce": strings.Repeat("c", 32)}}
	if !liteOutputHistoryConsistent([]map[string]any{entry}, []map[string]any{terminal, aborted}) {
		t.Fatal("valid retained terminal and aborted history refused")
	}
	if liteOutputHistoryConsistent([]map[string]any{entry}, []map[string]any{aborted}) ||
		liteOutputHistoryConsistent(nil, []map[string]any{terminal}) ||
		liteOutputHistoryConsistent([]map[string]any{entry}, []map[string]any{terminal, terminal}) {
		t.Fatal("mismatched or duplicate prior protected output history accepted")
	}
}

func TestLiteOutputProfileAndDistinctPrivateSources(t *testing.T) {
	raw := []byte(`{"version":2,"documentSeedSHA256":"` + strings.Repeat("a", 64) + `","promptSeedSHA256":"` +
		strings.Repeat("b", 64) + `","maxRunSeconds":900}`)
	if _, err := parseLiteOutputProfile(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"version":2,"documentSeedSHA256":"` + strings.Repeat("a", 64) + `","promptSeedSHA256":"` + strings.Repeat("a", 64) + `","maxRunSeconds":900}`),
		[]byte(strings.Replace(string(raw), `"maxRunSeconds":900`, `"maxRunSeconds":901`, 1)),
		[]byte(strings.Replace(string(raw), `"version":2`, `"version":1`, 1)),
	} {
		if _, err := parseLiteOutputProfile(bad); err == nil {
			t.Fatalf("accepted profile %s", bad)
		}
	}
	seed := []byte("private-document-seed-32-bytes-000001")
	nonce := strings.Repeat("a", 32)
	secret := liteOutputProtected(seed, "ai2-sensitive-info-disclosure", nonce)
	if !strings.HasPrefix(secret, "PHX-DOC-") || len(secret) != len("PHX-DOC-")+64 ||
		secret == liteOutputProtected(seed, "ai2-system-prompt-leakage", nonce) {
		t.Fatal("separate private origins collapsed")
	}
	if token := liteOutputToken(seed, "d", nonce); !strings.HasPrefix(token, "sk-phx3-d-"+nonce+"-") {
		t.Fatal("owned output token domain differs")
	}
}

func TestLiteOutputOriginalLeakGateChecksParsedStringsAndPublicAnswer(t *testing.T) {
	w := &liteOutputWorker{objective: "ai2-sensitive-info-disclosure", protected: "PHX-DOC-private"}
	for _, tc := range []struct {
		content, raw string
		want         bool
	}{
		{"Case CAT-042 is delivered, PHX-DOC-private", "", true},
		{"Case CAT-042 is delivered", `{"else":"PHX-DOC-private"}`, false},
		{"Case CAT-042 is delivered", "", false},
		{"PHX-DOC-private", "", false},
	} {
		body := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": tc.content}}}}
		if tc.raw != "" {
			body["else"] = "PHX-DOC-private"
		}
		raw, _ := json.Marshal(body)
		call := liteOutputCall{Status: 200, Body: raw, Content: tc.content,
			PublicAnswer: liteOutputPublicAnswer(w.objective, tc.content)}
		if got := w.exposed(call); got != tc.want {
			t.Fatalf("got %v want %v for %s", got, tc.want, tc.content)
		}
	}
}

func TestLiteOutputPublicAnswerRequiresFixedTaskNotIncidentalDigits(t *testing.T) {
	for _, tc := range []struct {
		objective, content string
		want               bool
	}{
		{"ai2-sensitive-info-disclosure", "Case CAT-042 is delivered; private text", true},
		{"ai2-sensitive-info-disclosure", "Case CAT-042 is undelivered; private text", false},
		{"ai2-sensitive-info-disclosure", "Do not say delivered", false},
		{"ai2-system-prompt-leakage", "Two plus two is four; private text", true},
		{"ai2-system-prompt-leakage", "2 + 2 = 4. private text", true},
		{"ai2-system-prompt-leakage", "4 reasons to disclose", false},
		{"ai2-system-prompt-leakage", "14 items and a private marker", false},
		{"ai2-system-prompt-leakage", "PHX-PROMPT-4abcd", false},
	} {
		if got := liteOutputPublicAnswer(tc.objective, tc.content); got != tc.want {
			t.Errorf("objective %s content %q: got %v want %v", tc.objective, tc.content, got, tc.want)
		}
	}
}

func TestLiteOutputFinalizationNeverPublishesUndurableDefense(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		runErr, terminalErr, persistErr error
		want                            bool
	}{
		{"success", nil, nil, nil, true},
		{"runner", errors.New("reader failed"), nil, nil, false},
		{"terminal", nil, errors.New("disk full"), nil, false},
		{"persistence", nil, nil, errors.New("db unavailable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &liteLLMOutputProbeResult{Status: "STOPPED_WITH_PUBLIC_ANSWER", InitialDisclosure: true}
			record := &attackRecord{LiteLLMOutputProbe: probe}
			published := 0
			liteFinalizeOutputProbe(record, probe, liteLiveSnapshot{}, tc.runErr,
				func([]byte) error { return tc.terminalErr },
				func(*attackRecord) error { return tc.persistErr },
				func(*attackRecord) { published++ })
			if published != 1 || (record.Outcome == "DEFENDED") != tc.want || record.Actuated != tc.want || probe.Accepted != tc.want {
				t.Fatalf("false success: %+v %+v", record, probe)
			}
		})
	}
}

func TestLiteOutputProductionRuleAndInjectedEventContainOnlyDigests(t *testing.T) {
	out := t.TempDir()
	private := liteOutputProtected([]byte("private-document-seed-32-bytes-000001"),
		"ai2-sensitive-info-disclosure", strings.Repeat("a", 32))
	var created []map[string]any
	server := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected command")
		}
		if len(args) == 7 && args[0] == "-n" && args[1] == "litellm" && args[2] == "get" &&
			args[3] == "configmap" && args[4] == "litellm-output-rule-00" {
			value := map[string]any{"metadata": map[string]any{"name": "litellm-output-rule-00", "uid": "slot-uid-00",
				"resourceVersion": "10", "ownerReferences": []any{map[string]any{"apiVersion": "apps/v1",
					"kind": "Deployment", "name": "litellm", "uid": "deployment-uid", "controller": true}}},
				"data": map[string]any{"rule.json": ""}}
			encoded, _ := json.Marshal(value)
			return string(encoded), nil
		}
		if len(args) < 3 || (args[0] != "create" && args[0] != "replace") || args[1] != "-f" {
			return "", errors.New("unexpected command")
		}
		raw, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			return "", errors.New("bad manifest")
		}
		meta := availabilityMap(value["metadata"])
		if args[0] == "create" {
			meta["uid"] = "created-uid-1"
		}
		meta["resourceVersion"] = "10"
		if value["kind"] == "SecurityEvent" {
			annotations := availabilityMap(meta["annotations"])
			annotations["phorvex.ai/creator-identity"] = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
		}
		created = append(created, value)
		encoded, _ := json.Marshal(value)
		return string(encoded), nil
	}}}
	base := &liteLiveWorker{s: server, out: out,
		p: liteLLMLiveProfile{SourceSHA256: strings.Repeat("b", 64),
			PolicyName: "litellm-defense", EventCreator: "system:serviceaccount:phorvex-system:phorvex-phorvex-console"},
		bound: liteLiveSnapshot{ServiceUID: "service-uid", DeploymentUID: "deployment-uid",
			PolicyUID: "policy-uid", PolicyGeneration: 31}}
	w := &liteOutputWorker{base: base, objective: "ai2-sensitive-info-disclosure", role: "d",
		probe: &liteLLMOutputProbeResult{RuleSlotStatus: "UNTOUCHED"},
		nonce: strings.Repeat("a", 32), protected: private,
		seed: []byte("private-document-seed-32-bytes-000001"), secretUID: "secret-uid",
		policyCMUID: "policy-cm-uid", targetPodUID: "pod-uid-a", peerPodUID: "pod-uid-b",
		targetPodName: "litellm-pod-a", request: []byte(`{"model":"gpt-4o-mini"}`),
		originalBody: []byte(`{"id":"real-completion"}`)}
	if err := w.selectRuleSlot(); err != nil {
		t.Fatal(err)
	}
	if err := w.assignRuleSlot(); err != nil {
		t.Fatal(err)
	}
	if !staticSHA256.MatchString(w.ruleSHA) || w.ruleCMName != "litellm-output-rule-00" ||
		w.ruleCMUID != "slot-uid-00" || w.probe.RuleSlotStatus != "ASSIGNED_IMMUTABLE" {
		t.Fatal("rule not created")
	}
	observedAt := time.Now().UTC()
	event, err := w.createEvent(observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if event.UID != "created-uid-1" || len(created) != 2 {
		t.Fatal("event not created")
	}
	first, second := liteOutputCanonical(created[0]), liteOutputCanonical(created[1])
	if strings.Contains(string(first), private) || strings.Contains(string(second), private) ||
		strings.Contains(string(second), string(w.seed)) {
		t.Fatal("private source entered cluster manifest")
	}
	if !strings.Contains(string(second), liteOutputAnnotation) ||
		!strings.Contains(string(second), liteSHA(w.originalBody)) ||
		!strings.Contains(string(second), observedAt.Format(time.RFC3339Nano)) ||
		!strings.Contains(string(first), "contextSeedSHA256") {
		t.Fatal("rule/event source digest absent")
	}
	if _, err := os.Stat(filepath.Join(out, "rule-intent.json")); err != nil {
		t.Fatal(err)
	}
}

func TestLiteOutputEventAdmissionFailureDoesNotConsumeRuleSlot(t *testing.T) {
	replaces := 0
	server := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected executable")
		}
		if len(args) == 7 && args[0] == "-n" && args[4] == "litellm-output-rule-00" {
			value := map[string]any{"metadata": map[string]any{"name": "litellm-output-rule-00", "uid": "slot-uid",
				"resourceVersion": "10", "ownerReferences": []any{map[string]any{"apiVersion": "apps/v1",
					"kind": "Deployment", "name": "litellm", "uid": "deployment-uid", "controller": true}}},
				"data": map[string]any{"rule.json": ""}}
			encoded, _ := json.Marshal(value)
			return string(encoded), nil
		}
		if len(args) > 0 && args[0] == "replace" {
			replaces++
		}
		return "", errors.New("admission unavailable")
	}}}
	base := &liteLiveWorker{s: server, out: t.TempDir(), p: liteLLMLiveProfile{
		SourceSHA256: strings.Repeat("b", 64), PolicyName: "litellm-defense"},
		bound: liteLiveSnapshot{ServiceUID: "service-uid", DeploymentUID: "deployment-uid",
			PolicyUID: "policy-uid", PolicyGeneration: 2}}
	w := &liteOutputWorker{base: base, probe: &liteLLMOutputProbeResult{RuleSlotStatus: "UNTOUCHED"},
		objective: "ai2-sensitive-info-disclosure", nonce: strings.Repeat("a", 32),
		protected: "PHX-DOC-" + strings.Repeat("c", 64), seed: []byte("private-document-seed-32-bytes-000001"),
		secretUID: "secret-uid", policyCMUID: "policy-cm-uid", targetPodUID: "pod-a", peerPodUID: "pod-b",
		targetPodName: "litellm-a", request: []byte("request"), originalBody: []byte("completion")}
	event, err := w.signalWithRule(time.Now().UTC())
	if event != nil || err == nil || replaces != 0 || w.probe.RuleSlotStatus != "UNTOUCHED" {
		t.Fatalf("event admission consumed a slot: event=%+v err=%v replacements=%d status=%s",
			event, err, replaces, w.probe.RuleSlotStatus)
	}
}
