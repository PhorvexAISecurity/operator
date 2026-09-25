package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var availabilityAttackID = regexp.MustCompile(`^atk-[a-z0-9]{1,32}$`)

func (w *availabilityWorker) consoleHTTP(method, path string, body []byte, token string) (availabilityConsoleHTTP, []byte, error) {
	var out availabilityConsoleHTTP
	if method == http.MethodPost {
		if w.t.ConsolePOSTsAttempted != 0 || path != "/api/vllm/attack" || !bytes.Equal(body, []byte(availabilityConsoleBody)) {
			return out, nil, errors.New("console mutation outside fixed scope")
		}
		w.t.ConsolePOSTsAttempted++
	} else if method == http.MethodGet {
		if w.t.ConsoleGETsAttempted >= 3 || !strings.HasPrefix(path, "/api/attack-results?id=atk-") {
			return out, nil, errors.New("console result route outside bound")
		}
		w.t.ConsoleGETsAttempted++
	} else {
		return out, nil, errors.New("console method outside fixed scope")
	}
	left, e := w.remaining(20 * time.Second)
	if e != nil {
		return out, nil, e
	}
	ctx, stop := context.WithTimeout(w.ctx, min(left, 15*time.Second))
	defer stop()
	req, e := http.NewRequestWithContext(ctx, method, w.p.Fixture.ConsoleURL+path, bytes.NewReader(body))
	if e != nil {
		return out, nil, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	client := &http.Client{Timeout: min(left, 15*time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	name := fmt.Sprintf("console-%d-%d.json", w.t.ConsolePOSTsAttempted, w.t.ConsoleGETsAttempted)
	resp, e := client.Do(req)
	if e != nil {
		_ = w.saveJSON(strings.TrimSuffix(name, ".json")+"-partial.json", map[string]any{"method": method, "path": path, "status": nil, "bodyBase64": "", "bodySHA256": availabilityHash(nil), "bodyBytes": 0, "complete": false, "errorClass": "TRANSPORT"})
		return out, nil, errors.New("one-shot console request unresolved")
	}
	defer resp.Body.Close()
	var received bytes.Buffer
	part := make([]byte, 8192)
	for {
		n, re := resp.Body.Read(part)
		if n > 0 {
			if received.Len()+n > 1<<20 {
				re = errors.New("reply bound")
			} else {
				_, _ = received.Write(part[:n])
			}
		}
		if re != nil {
			if re == io.EOF {
				break
			}
			partial := received.Bytes()
			_ = w.saveJSON(strings.TrimSuffix(name, ".json")+"-partial.json", map[string]any{"method": method, "path": path, "status": resp.StatusCode, "bodyBase64": encodeAvailabilityBase64(partial), "bodySHA256": availabilityHash(partial), "bodyBytes": len(partial), "complete": false, "errorClass": "BODY_READ"})
			return out, nil, errors.New("bounded console original reply unresolved")
		}
	}
	raw := received.Bytes()
	out = availabilityConsoleHTTP{method, path, resp.StatusCode, encodeAvailabilityBase64(raw), availabilityHash(raw), len(raw)}
	if e = w.saveJSON(name, out); e != nil {
		return out, nil, e
	}
	return out, raw, nil
}

func encodeAvailabilityBase64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func (w *availabilityWorker) token() (string, error) {
	raw, e := os.ReadFile(w.p.Fixture.ScopedTokenFile)
	if e != nil || len(raw) > 8192 {
		return "", errors.New("reviewed scoped console credential unavailable")
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("reviewed scoped console credential malformed")
	}
	return token, nil
}

func availabilityBaselineStatus(v GuardrailAvailabilityControls) string {
	if v.Canary != "GUARDRAIL_BLOCKED" {
		if v.Canary == "DISCLOSED" || v.Canary == "WITHHELD" {
			return "STOP_CANARY_NOT_BLOCKED"
		}
		return "UNKNOWN"
	}
	if v.SayOK != "GUARDRAIL_BLOCKED" {
		if v.SayOK == "OK" || v.SayOK == "OTHER_200" {
			return "STOP_SAY_OK_NOT_BLOCKED"
		}
		return "UNKNOWN"
	}
	if v.Arithmetic != "FOUR" {
		if v.Arithmetic == "OTHER_200" || v.Arithmetic == "GUARDRAIL_BLOCKED" {
			return "STOP_ARITHMETIC_NOT_FOUR"
		}
		return "UNKNOWN"
	}
	return "READY_FOR_ONE_INJECTED_RECOVERY"
}

func (w *availabilityWorker) eventFromConsole(token string, attackID string, preexisting map[string]bool) (*availabilityEvent, error) {
	if !availabilityAttackID.MatchString(attackID) {
		return nil, errors.New("console attack identifier malformed")
	}
	path := "/api/attack-results?id=" + attackID + "&includeObservations=true&limit=1"
	wire, raw, e := w.consoleHTTP(http.MethodGet, path, nil, token)
	if e != nil {
		return nil, e
	}
	if wire.Status != 200 {
		return nil, errors.New("console result did not confirm event")
	}
	var listing map[string]any
	if e = availabilityDecode(raw, &listing); e != nil {
		return nil, e
	}
	rows, _ := listing["attacks"].([]any)
	var found map[string]any
	count := 0
	for _, v := range rows {
		m := availabilityMap(v)
		if m["id"] == attackID {
			found = m
			count++
		}
	}
	if count != 1 || found["evidenceKind"] != "vllm-in-place-effect" || found["attackId"] != "guardrail-rotate" || found["targetUid"] != w.p.Fixture.PodUID {
		return nil, errors.New("console event provenance absent")
	}
	stimulus := availabilityMap(found["stimulusEvidence"])
	name, uid := availabilityString(stimulus, "eventName"), availabilityString(stimulus, "eventUid")
	if stimulus["observed"] != true || name == "" || uid == "" || len(name) > 253 {
		return nil, errors.New("console event identity absent")
	}
	obj, e := w.kube("event", "get", "securityevents.amtd.r6security.com", name, "-o", "json")
	if e != nil {
		return nil, e
	}
	meta, spec := availabilityMeta(obj), availabilityMap(obj["spec"])
	rule := availabilityMap(spec["rule"])
	labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
	targets, _ := spec["targets"].([]any)
	if len(targets) != 1 || targets[0] != "vllm/"+w.p.Fixture.PodName || availabilityString(meta, "uid") != uid || preexisting[uid] || availabilityString(notes, "phorvex.ai/creator-identity") != w.p.Fixture.EventCreator || availabilityString(labels, "phorvex.ai/console-vllm") != "true" || availabilityString(labels, "phorvex.ai/attack-correlation") != availabilityString(stimulus, "correlation") || rule["type"] != "phorvex.attack.guardrail" || rule["source"] != "redteam" {
		return nil, errors.New("exact created event provenance differs")
	}
	event := &availabilityEvent{uid, name, availabilityString(meta, "resourceVersion"), w.p.Fixture.EventCreator, availabilityString(stimulus, "correlation"), w.p.Fixture.PodUID, "phorvex.attack.guardrail", "redteam"}
	if event.ResourceVersion == "" {
		return nil, errors.New("created event resource version absent")
	}
	return event, nil
}

func (w *availabilityWorker) cleanupEvent() error {
	if w.event == nil {
		return errors.New("exact event identity unavailable for cleanup")
	}
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	rc, e := rest.InClusterConfig()
	if e != nil {
		return errors.New("exact event cleanup cluster authority unavailable")
	}
	client, e := dynamic.NewForConfig(rc)
	if e != nil {
		return errors.New("exact event cleanup client unavailable")
	}
	cluster, e := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || string(cluster.GetUID()) != w.p.Fixture.ClusterUID {
		return errors.New("cleanup API cluster differs from reviewed observation cluster")
	}
	clusterRaw, _ := json.Marshal(cluster.Object)
	if e = w.save("cleanup-cluster.json", clusterRaw); e != nil {
		return e
	}
	resource := client.Resource(securityEventGVR)
	obj, e := resource.Get(ctx, w.event.Name, metav1.GetOptions{})
	if e != nil {
		return errors.New("event predelete read unavailable")
	}
	raw, e := json.Marshal(obj.Object)
	if e != nil {
		return e
	}
	if e = w.save("event-predelete.json", raw); e != nil {
		return e
	}
	meta, spec := availabilityMeta(obj.Object), availabilityMap(obj.Object["spec"])
	labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
	rule := availabilityMap(spec["rule"])
	targets, _ := spec["targets"].([]any)
	if availabilityString(meta, "uid") != w.event.UID || availabilityString(meta, "name") != w.event.Name || availabilityString(meta, "resourceVersion") != w.event.ResourceVersion || availabilityString(notes, "phorvex.ai/creator-identity") != w.event.CreatorIdentity || availabilityString(labels, "phorvex.ai/attack-correlation") != w.event.Correlation || availabilityString(labels, "phorvex.ai/console-vllm") != "true" || len(targets) != 1 || targets[0] != "vllm/"+w.p.Fixture.PodName || rule["type"] != w.event.RuleType || rule["source"] != w.event.Source {
		return errors.New("event ownership changed before exact delete")
	}
	if e = w.saveJSON("delete-intent.json", w.event); e != nil {
		return e
	}
	w.t.ExactEventDeletesAttempted++
	uid := obj.GetUID()
	rv := obj.GetResourceVersion()
	e = resource.Delete(ctx, w.event.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if e != nil {
		return errors.New("exact UID and resource-version delete unresolved")
	}
	if e = w.saveJSON("delete-ack.json", map[string]any{"uid": string(uid), "resourceVersion": rv, "acknowledged": true}); e != nil {
		return e
	}
	_, e = resource.Get(ctx, w.event.Name, metav1.GetOptions{})
	if !apierrors.IsNotFound(e) {
		return errors.New("exact event absence not verified")
	}
	if e = w.saveJSON("event-absence.json", map[string]any{"name": w.event.Name, "uid": w.event.UID, "notFound": true}); e != nil {
		return e
	}
	w.t.CleanupVerified = true
	return nil
}

func (w *availabilityWorker) execute() (err error) {
	if w.rm.cfg.AuditSourceIdentity != w.p.Fixture.AuditURL+"|"+w.p.Fixture.AuditServerName {
		return errors.New("reviewed authenticated audit origin changed")
	}
	if _, e := w.remaining(330 * time.Second); e != nil {
		return e
	}
	markerRaw := make([]byte, 4)
	if _, err = rand.Read(markerRaw); err != nil {
		return err
	}
	w.marker = "CNR_" + hex.EncodeToString(markerRaw)
	w.request = map[string][]byte{}
	for _, which := range []string{"canary", "say_ok", "arithmetic"} {
		w.request[which] = availabilityRequest(w.p.Fixture.ModelID, w.marker, which)
	}
	if e := w.save("private-marker.bin", []byte(w.marker)); e != nil {
		return e
	}
	if e := w.saveJSON("private-intent.json", map[string]any{"runID": w.t.RunID, "markerSHA256": availabilityHash([]byte(w.marker)), "maximumGuardedChats": 6, "maximumConsolePOSTs": 1, "requestSHA256": map[string]string{"canary": availabilityHash(w.request["canary"]), "say_ok": availabilityHash(w.request["say_ok"]), "arithmetic": availabilityHash(w.request["arithmetic"])}}); e != nil {
		return e
	}
	start, e := w.auditStart()
	if e != nil {
		return e
	}
	auditAttempted := false
	defer func() {
		if w.t.ConsolePOSTsAttempted > 0 && !auditAttempted {
			auditAttempted = true
			closeStarted := time.Now()
			a, _ := w.auditClose(start, w.event)
			a.CloseStartedLate = closeStarted.Sub(w.postAt) > 120*time.Second
			_ = w.saveJSON("audit-terminal.json", a)
		}
		if w.event != nil {
			if ce := w.cleanupEvent(); ce != nil {
				w.t.Status = "UNKNOWN"
				if err == nil {
					err = ce
				}
			}
		}
		if w.t.ConsolePOSTsAttempted == 0 {
			w.t.CleanupVerified = true
		}
	}()
	w.before, e = w.snapshot("before")
	if e != nil {
		return e
	}
	if w.before.ActiveVariant != "pgv1" || w.before.PodVariant != "pgv1" {
		w.t.Status = "STOP_BASELINE_VARIANT"
		return nil
	}
	if e = availabilityCheckProtected(w.before, w.p); e != nil {
		return e
	}
	baseline, e := w.measure("before", w.before)
	if e != nil {
		return e
	}
	gate := availabilityBaselineStatus(baseline)
	if gate != "READY_FOR_ONE_INJECTED_RECOVERY" {
		w.t.Status = gate
		return nil
	}
	prepost, e := w.snapshot("prepost")
	if e != nil {
		return e
	}
	if !availabilitySameSource(w.before, prepost, false) {
		return errors.New("pre-POST baseline source or operation drift")
	}
	population, e := w.kube("prepost-target-population", "-n", "vllm", "get", "pods", "-l", "app=vllm", "-o", "json")
	if e != nil {
		return e
	}
	items, _ := population["items"].([]any)
	if len(items) != 1 || availabilityUID(availabilityMap(items[0])) != w.before.TargetPodUID {
		return errors.New("console target population changed before POST")
	}
	inventory, e := w.kube("prepost-event-inventory", "get", "securityevents.amtd.r6security.com", "-l", "phorvex.ai/console-vllm=true", "-o", "json")
	if e != nil {
		return e
	}
	if availabilityString(availabilityMeta(inventory), "continue") != "" {
		return errors.New("preexisting event inventory incomplete")
	}
	rows, _ := inventory["items"].([]any)
	if len(rows) > 512 {
		return errors.New("preexisting event inventory over bound")
	}
	known := map[string]bool{}
	for _, v := range rows {
		known[availabilityUID(availabilityMap(v))] = true
	}
	if _, e = w.remaining(330 * time.Second); e != nil {
		return e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	if e = w.saveJSON("post-intent.json", map[string]any{"runID": w.t.RunID, "requestSHA256": availabilityHash([]byte(availabilityConsoleBody)), "nonce": hex.EncodeToString(nonce), "auditStartSHA256": availabilityHash(mustAvailabilityJSON(start)), "baselineGate": gate, "maximumPOSTs": 1}); e != nil {
		return e
	}
	token, e := w.token()
	if e != nil {
		return e
	}
	if _, e = w.compactSnapshot("immediate-prepost", w.before); e != nil {
		return e
	}
	if _, e = w.remaining(330 * time.Second); e != nil {
		return e
	}
	w.postAt = time.Now()
	wire, body, e := w.consoleHTTP(http.MethodPost, "/api/vllm/attack", []byte(availabilityConsoleBody), token)
	if e != nil {
		return e
	}
	var ack map[string]any
	if e = availabilityDecode(body, &ack); e != nil {
		return e
	}
	if wire.Status != 200 || ack["ok"] != true || ack["action"] != "guardrail-rotate" {
		return errors.New("one-shot console event not positively acknowledged")
	}
	w.event, e = w.eventFromConsole(token, availabilityString(ack, "attackId"), known)
	if e != nil {
		return e
	}
	if e = w.saveJSON("created-event.json", w.event); e != nil {
		return e
	}
	// Poll only the pinned journal for the first distinct generation. The
	// subsequent complete snapshot and reader establish the actual operation.
	baseGen, _, _, _, _, _, e := availabilityReceiptFields(w.before.Receipt)
	if e != nil {
		return e
	}
	for i := 0; i < 6; i++ {
		j, je := w.kube(fmt.Sprintf("journal-poll-%d", i), "-n", "phorvex-system", "get", "configmap", w.p.Fixture.GuardrailJournalName, "-o", "json")
		if je != nil {
			return je
		}
		var r json.RawMessage
		if availabilityDecode([]byte(availabilityString(availabilityMap(j["data"]), "receipt")), &r) == nil {
			n, _, _, _, _, _, _ := availabilityReceiptFields(r)
			if n != baseGen {
				break
			}
		}
		select {
		case <-w.ctx.Done():
			return errors.New("observation cancelled")
		case <-time.After(5 * time.Second):
		}
	}
	operation, e := w.snapshot("operation")
	if e != nil {
		return e
	}
	if !availabilitySameSource(w.before, operation, true) {
		return errors.New("operation source identity drift")
	}
	// A selected action with no protected readback is an observed negative,
	// provided the subsequent calls and full audit still complete. The
	// independent reader decides whether it is a confirmed effect.
	_, e = w.measure("after", operation)
	if e != nil {
		return e
	}
	w.after, e = w.snapshot("final")
	if e != nil {
		return e
	}
	if !availabilitySameSource(operation, w.after, false) {
		return errors.New("final source or operation drift")
	}
	closeStartedAt := time.Now()
	auditAttempted = true
	audit, ae := w.auditClose(start, w.event)
	audit.CloseStartedLate = closeStartedAt.Sub(w.postAt) > 120*time.Second
	if audit.CloseStartedLate {
		audit.Status = "AUDIT_COVERAGE_GAP"
		audit.CoverageComplete = false
	}
	if se := w.saveJSON("audit-terminal.json", audit); se != nil {
		return se
	}
	if ae != nil {
		return ae
	}
	if !audit.CoverageComplete {
		return errors.New("authenticated audit interval incomplete")
	}
	w.t.Status = "OBSERVED_PENDING_INDEPENDENT_READER"
	return nil
}

func mustAvailabilityJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func availabilityCheckProtected(s availabilitySnapshot, p guardrailAvailabilityProfile) error {
	f := p.Fixture
	var r map[string]any
	if e := availabilityDecode(s.Receipt, &r); e != nil {
		return e
	}
	n, phase, prior, next, op, tick, e := availabilityReceiptFields(s.Receipt)
	if e != nil {
		return e
	}
	if r["version"] != float64(9) || r["kind"] != "guardrail-rotate" || r["effectDomain"] != "guardrail-variant-v1" || phase != "terminal-full" || r["policyNamespace"] != "vllm" || r["policyName"] != f.PolicyName || r["policyUID"] != f.PolicyUID || r["targetName"] != f.PodName || r["targetUID"] != f.PodUID || prior == next || next != "pgv1" || s.ActiveVariant != "pgv1" || s.PodVariant != "pgv1" || tick == "" || op != availabilityOperationID(tick, f.PolicyUID, "vllm", f.PodUID) || availabilityMap(r["expectedGuardrail"])["present"] != true || availabilityMap(r["expectedGuardrail"])["value"] != availabilityEpoch(op) || s.GuardrailEpoch != availabilityEpoch(op) || n < 1 {
		return errors.New("natural baseline protected variant receipt differs")
	}
	return nil
}
func availabilityCheckTransition(before, after availabilitySnapshot, p guardrailAvailabilityProfile) error {
	bn, _, _, _, bop, _, e := availabilityReceiptFields(before.Receipt)
	if e != nil {
		return e
	}
	an, phase, prior, next, op, tick, e := availabilityReceiptFields(after.Receipt)
	if e != nil {
		return e
	}
	var r map[string]any
	if e = availabilityDecode(after.Receipt, &r); e != nil {
		return e
	}
	if an != bn+1 || r["version"] != float64(9) || r["kind"] != "guardrail-rotate" || r["effectDomain"] != "guardrail-variant-v1" || phase != "terminal-full" || r["policyNamespace"] != "vllm" || r["policyName"] != p.Fixture.PolicyName || r["targetName"] != p.Fixture.PodName || prior != "pgv1" || next != "pgv2" || op == bop || op != availabilityOperationID(tick, p.Fixture.PolicyUID, "vllm", p.Fixture.PodUID) || after.ActiveVariant != "pgv2" || after.PodVariant != "pgv2" || after.GuardrailEpoch != availabilityEpoch(op) || availabilityMap(r["expectedGuardrail"])["present"] != true || availabilityMap(r["expectedGuardrail"])["value"] != availabilityEpoch(op) || r["policyUID"] != p.Fixture.PolicyUID || r["targetUID"] != p.Fixture.PodUID {
		return errors.New("protected pgv1 to pgv2 operation not confirmed")
	}
	return nil
}
