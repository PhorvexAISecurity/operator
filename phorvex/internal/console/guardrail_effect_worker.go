package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const guardrailEffectEventDescription = "synthetic guardrail signal after a measured fixed confidential-output baseline"

// The existing console action owns this worker. It does not call the action
// route again and cannot create an event until all three original guarded
// baseline replies and their source brackets have been sealed.
func (s *Server) startMeasuredGuardrailEffect(p guardrailAvailabilityProfile, profileRaw []byte, base defenseBaseline, pod string) string {
	started := s.cfg.now()
	id := "atk-" + strconv.FormatInt(started.UnixNano(), 36) + strconv.FormatUint(vllmEventSequence.Add(1), 36)
	r := &attackRecord{
		ID: id, FiredAt: started.UTC().Format(time.RFC3339Nano), Service: vllmAttackNS,
		Namespace: vllmAttackNS, Pod: pod, Deploy: base.deploy, OwnerKind: base.ownerKind, OwnerUID: base.ownerUID,
		Attack: "Guardrail guarded-outcome observation", AttackID: "guardrail-rotate", MITRE: "filter-effect-only",
		Expected: "guardrail-rotate", EvidenceKind: "vllm-in-place-effect", TargetUID: base.uid,
		OutcomeClass: "guarded-baseline-pending", Status: "running", UptimeBefore: base.uptime,
		ObservationStart:     started.UTC().Format(time.RFC3339Nano),
		ObservationEnd:       started.Add(600 * time.Second).UTC().Format(time.RFC3339Nano),
		GuardrailEffectProbe: newGuardrailEffectProbeResult(s.cfg.GuardrailEffectProfileSHA256),
		started:              started, accepted: started,
	}
	publishAttack(r)
	go s.runMeasuredGuardrailEffect(r, p, profileRaw)
	return id
}

func (s *Server) runMeasuredGuardrailEffect(r *attackRecord, p guardrailAvailabilityProfile, profileRaw []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	out := s.cfg.statePath(filepath.Join("guardrail-effect", r.ID))
	w := &availabilityWorker{
		rm: &RunManager{cfg: s.cfg}, ctx: ctx, out: out, p: p,
		deadline: time.Now().Add(600 * time.Second), selfName: os.Getenv("PHORVEX_CONSOLE_POD_NAME"),
		selfUID: os.Getenv("PHORVEX_CONSOLE_POD_UID"),
		t: availabilityTerminal{Schema: "guardrail-effect-terminal-v1", RunID: r.ID,
			ProfileSHA256: s.cfg.GuardrailEffectProfileSHA256, Status: "UNKNOWN",
			StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ConsolePOSTsAttempted: 1},
	}
	var err error
	if out == "" || w.selfName == "" || len(validation.IsDNS1123Subdomain(w.selfName)) != 0 || !staticUID.MatchString(w.selfUID) {
		err = errors.New("guardrail effect private storage or own Pod identity unavailable")
	} else if err = os.MkdirAll(out, 0700); err == nil {
		if err = w.save("profile-original.yaml", profileRaw); err == nil {
			err = w.saveJSON("self-identity.json", map[string]string{"name": w.selfName, "uid": w.selfUID})
		}
		if err == nil {
			err = w.initRetainedCaller()
		}
		if err == nil {
			err = s.executeMeasuredGuardrailEffect(w, r)
		}
	}
	if err != nil {
		w.t.Issue = guardrailEffectSafeIssue(err)
	}
	w.t.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if out != "" {
		if e := w.saveJSON("guardrail-effect-terminal.json", w.t); e != nil && err == nil {
			err = e
		}
	}
	result, readErr := readGuardrailEffectProbeResult(out, r.ID, s.cfg.GuardrailEffectProfileSHA256)
	if readErr != nil || result == nil {
		result = newGuardrailEffectProbeResult(s.cfg.GuardrailEffectProfileSHA256)
		result.Issues = append(result.Issues, "independent original-receipt projection unavailable")
	}
	if err != nil {
		result.Accepted = false
		result.Status = "UNKNOWN"
		result.Issues = append(result.Issues, guardrailEffectSafeIssue(err))
	}
	r.GuardrailEffectProbe = result
	r.OutcomeClass = "guardrail-effect-" + result.Status
	if result.Accepted && result.EventUID != "" && result.DecisionID != "" && result.OperationID != "" {
		r.EffectEvidence = &attackEffectEvidence{Kind: "guardrail-protected-selected-operation", Observed: true,
			ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID,
			Before: result.PriorVariant, After: result.NextVariant,
			Correlation: "exact-injected-event-selected-decision-protected-operation:" + result.OperationID,
			Limitation:  "Original guarded replies and legitimate controls determine the narrow outcome; this injected event does not prove natural detection or general security efficacy"}
	}
	r.Outcome, r.Containment, r.DefendedPod = "", "", ""
	r.Actuated, r.DwellOngoing, r.TimeToDefendSec, r.DwellSec = false, false, 0, 0
	r.Status = "done"
	if !result.Accepted {
		r.Status = "partial"
	}
	publishAttack(r)
	if e := s.persistAttack(r); e != nil {
		r.Status = "partial"
		r.PersistenceError = "guardrail effect evidence persistence unavailable; unsafe to retry"
		s.recordStateError(fmt.Errorf("persist measured guardrail effect: %w", e))
		publishAttack(r)
	}
}

func (s *Server) executeMeasuredGuardrailEffect(w *availabilityWorker, record *attackRecord) (err error) {
	markerRaw := make([]byte, 4)
	if _, err = rand.Read(markerRaw); err != nil {
		return err
	}
	w.marker = "CNR_" + hex.EncodeToString(markerRaw)
	w.request = map[string][]byte{}
	for _, which := range []string{"canary", "say_ok", "arithmetic"} {
		w.request[which] = availabilityRequest(w.p.Fixture.ModelID, w.marker, which)
	}
	if err = w.save("private-marker.bin", []byte(w.marker)); err != nil {
		return err
	}
	if err = w.saveJSON("private-intent.json", map[string]any{"runID": w.t.RunID,
		"markerSHA256": availabilityHash([]byte(w.marker)), "maximumGuardedChats": 6,
		"maximumSecurityEvents": 1, "consoleLaunchPOSTs": 1,
		"requestSHA256": map[string]string{"canary": availabilityHash(w.request["canary"]),
			"say_ok": availabilityHash(w.request["say_ok"]), "arithmetic": availabilityHash(w.request["arithmetic"])}}); err != nil {
		return err
	}
	var start availabilityAuditStart
	auditAttempted := false
	var candidate *attackStimulusEvidence
	defer func() {
		// Every path after a possibly accepted create, including a failed
		// private receipt write, first tries bounded exact-name reconciliation.
		// Never infer cleanup from a lost acknowledgement or a foreign object.
		if reconcileErr := w.reconcilePendingGuardrailEvent(candidate, w.reconcileAmbiguousGuardrailEvent); reconcileErr != nil {
			if err == nil {
				err = reconcileErr
			}
		}
		if w.t.SecurityEventsAttempted == 1 && !auditAttempted {
			auditAttempted = true
			started := time.Now()
			a, _ := w.auditClose(start, w.event)
			a.CloseStartedLate = started.Sub(w.postAt) > 120*time.Second
			_ = w.saveJSON("audit-terminal.json", a)
		}
		if w.event != nil {
			if e := w.cleanupEvent(); e != nil {
				w.t.Status = "UNKNOWN"
				if err == nil {
					err = e
				}
			}
		} else if w.t.SecurityEventsAttempted == 0 {
			w.t.CleanupVerified = true
		}
	}()
	w.before, err = w.snapshot("before")
	if err != nil {
		return err
	}
	if err = guardrailEffectProtected(w.before, w.p); err != nil {
		return err
	}
	baseline, err := w.measure("before", w.before)
	if err != nil {
		return err
	}
	gate := guardrailEffectBaselineGate(baseline)
	if gate != "THREAT_LANDED_BEFORE_INJECTED_RESPONSE" {
		w.t.Status = gate
		return nil
	}
	prepost, err := w.snapshot("prepost")
	if err != nil || !availabilitySameSource(w.before, prepost, false) {
		return errors.New("guardrail effect pre-event source or journal drift")
	}
	population, err := w.kube("prepost-target-population", "-n", "vllm", "get", "pods", "-l", "app=vllm", "-o", "json")
	if err != nil || availabilityOneTargetPopulation(population, w.before, w.p.Fixture.PodName) != nil {
		return errors.New("guardrail effect target population changed")
	}
	if _, err = w.remaining(330 * time.Second); err != nil {
		return err
	}
	// The authenticated interval covers the candidate event and response, not
	// the already sealed, nonmutating three-call baseline. This keeps the fixed
	// audit byte budget available for the causal interval.
	start, err = w.auditStart()
	if err != nil {
		return err
	}
	// A same-name pre-existing event would make a later UID/creator join
	// ambiguous. Retain the complete bounded original list before dispatch.
	inventory, err := w.kube("prepost-event-inventory", "get", "securityevents.amtd.r6security.com", "-o", "json", "--chunk-size=512")
	if err != nil || availabilityString(availabilityMeta(inventory), "continue") != "" {
		return errors.New("guardrail effect pre-event inventory incomplete")
	}
	items, ok := inventory["items"].([]any)
	if !ok || len(items) > 512 {
		return errors.New("guardrail effect pre-event inventory malformed")
	}
	if err = w.saveJSON("event-intent.json", map[string]any{"runID": w.t.RunID,
		"auditStartSHA256": availabilityHash(mustAvailabilityJSON(start)),
		"baselineGate":     gate, "maximumSecurityEvents": 1,
		"targetPodUID": w.before.TargetPodUID}); err != nil {
		return err
	}
	immediate, err := w.compactSnapshot("immediate-pre-event", w.before)
	if err != nil || availabilityAdmissionMatches(w.before, prepost, immediate) != nil {
		return errors.New("guardrail effect immediate pre-event admission drift")
	}
	if _, err = w.remaining(240 * time.Second); err != nil {
		return err
	}
	w.postAt = time.Now()
	w.t.SecurityEventsAttempted++
	stimulus, err := s.createCorrelatedVLLMEvent(w.p.Fixture.PodName, w.p.Fixture.PodUID,
		"GuardrailBypass", guardrailEffectEventDescription, "0.95")
	candidate = stimulus
	if stimulus != nil {
		record.StimulusEvidence = stimulus
		publishAttack(record)
		if e := w.saveMeasuredEventCandidate(stimulus); e != nil {
			return e
		}
	}
	if err != nil || stimulus == nil || !stimulus.Observed {
		return errors.New("one-shot injected SecurityEvent outcome unresolved")
	}
	w.event, err = w.readMeasuredGuardrailEvent(stimulus)
	if err != nil {
		return err
	}
	for _, raw := range items {
		if availabilityUID(availabilityMap(raw)) == w.event.UID ||
			availabilityString(availabilityMeta(availabilityMap(raw)), "name") == w.event.Name {
			return errors.New("guardrail effect event existed before one-shot creation")
		}
	}
	if err = w.saveJSON("created-event.json", w.event); err != nil {
		return err
	}
	baseGen := int64(0)
	if !w.before.JournalAbsent {
		baseGen, _, _, _, _, _, err = availabilityReceiptFields(w.before.Receipt)
		if err != nil {
			return err
		}
	}
	for i := 0; i < 6; i++ {
		j, e := w.journal(fmt.Sprintf("journal-poll-%d", i), w.p.Fixture.JournalInitiallyAbsent || w.p.Fixture.CaptureCurrentJournal)
		if e != nil {
			return e
		}
		var receipt map[string]any
		if !availabilityIsJournalAbsence(j, w.p.Context, w.p.Fixture.GuardrailJournalName) &&
			availabilityDecode([]byte(availabilityString(availabilityMap(j["data"]), "receipt")), &receipt) == nil && receipt["generation"] != float64(baseGen) {
			break
		}
		select {
		case <-w.ctx.Done():
			return errors.New("guardrail effect observation cancelled")
		case <-time.After(5 * time.Second):
		}
	}
	operation, err := w.snapshot("operation")
	if err != nil || !availabilitySameSource(w.before, operation, true) {
		return errors.New("guardrail effect operation source drift")
	}
	if _, err = w.measure("after", operation); err != nil {
		return err
	}
	w.after, err = w.snapshot("final")
	if err != nil || !availabilitySameSource(operation, w.after, false) {
		return errors.New("guardrail effect final operation drift")
	}
	closeStarted := time.Now()
	auditAttempted = true
	a, auditErr := w.auditClose(start, w.event)
	a.CloseStartedLate = closeStarted.Sub(w.postAt) > 120*time.Second
	if a.CloseStartedLate {
		a.CoverageComplete, a.Status = false, "AUDIT_COVERAGE_GAP"
	}
	if e := w.saveJSON("audit-terminal.json", a); e != nil {
		return e
	}
	if auditErr != nil || !a.CoverageComplete {
		return errors.New("guardrail effect authenticated audit interval incomplete")
	}
	w.t.Status = "OBSERVED_PENDING_INDEPENDENT_READER"
	return nil
}

func (w *availabilityWorker) saveMeasuredEventCandidate(stimulus *attackStimulusEvidence) error {
	if len(stimulus.createManifest) > 0 {
		if err := w.save("event-create-manifest.yaml", stimulus.createManifest); err != nil {
			return err
		}
	}
	if len(stimulus.createReply) > 0 {
		if err := w.save("event-create-reply.json", stimulus.createReply); err != nil {
			return err
		}
	}
	return w.saveJSON("event-producer.json", stimulus)
}

func (w *availabilityWorker) reconcilePendingGuardrailEvent(candidate *attackStimulusEvidence, readback func(*attackStimulusEvidence) error) error {
	if w.t.SecurityEventsAttempted != 1 || w.event != nil || candidate == nil {
		return nil
	}
	return readback(candidate)
}

// A lost create reply is not a license to create again or to guess-delete a
// same-name object. Three exact GETs within fifteen seconds can recover only
// an object whose UID, creator, target, rule and correlation all match the
// retained candidate. Even recovered ownership leaves the run UNKNOWN.
func (w *availabilityWorker) reconcileAmbiguousGuardrailEvent(candidate *attackStimulusEvidence) error {
	if candidate == nil || candidate.EventName == "" || candidate.Correlation == "" ||
		candidate.TargetUID != w.p.Fixture.PodUID || candidate.EventRule != "phorvex.attack.guardrail" {
		return errors.New("ambiguous event candidate identity unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rc, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("ambiguous event cluster authority unavailable")
	}
	client, err := dynamic.NewForConfig(rc)
	if err != nil {
		return errors.New("ambiguous event readback client unavailable")
	}
	return w.reconcileAmbiguousGuardrailEventWithClient(ctx, client, candidate)
}

func (w *availabilityWorker) reconcileAmbiguousGuardrailEventWithClient(ctx context.Context, client dynamic.Interface, candidate *attackStimulusEvidence) error {
	cluster, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || string(cluster.GetUID()) != w.p.Fixture.ClusterUID {
		return errors.New("ambiguous event cluster identity differs")
	}
	raw, err := json.Marshal(cluster.Object)
	if err != nil || w.save("event-reconcile-cluster.json", raw) != nil {
		return errors.New("ambiguous event cluster receipt unavailable")
	}
	resource := client.Resource(securityEventGVR)
	for attempt := 1; attempt <= 3; attempt++ {
		obj, getErr := resource.Get(ctx, candidate.EventName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			_ = w.saveJSON(fmt.Sprintf("event-reconcile-notfound-%d.json", attempt), map[string]any{"name": candidate.EventName, "correlation": candidate.Correlation, "notFound": true})
			if attempt < 3 {
				select {
				case <-ctx.Done():
					return errors.New("ambiguous event readback deadline exhausted")
				case <-time.After(2 * time.Second):
				}
			}
			continue
		}
		if getErr != nil {
			return errors.New("ambiguous event exact readback failed")
		}
		raw, err = json.Marshal(obj.Object)
		if err != nil || w.save("event-reconcile-original.json", raw) != nil {
			return errors.New("ambiguous event original readback unavailable")
		}
		meta, spec := availabilityMeta(obj.Object), availabilityMap(obj.Object["spec"])
		labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
		targets, _ := spec["targets"].([]any)
		if availabilityString(meta, "name") != candidate.EventName || availabilityString(meta, "uid") == "" ||
			availabilityString(meta, "resourceVersion") == "" ||
			(candidate.EventUID != "" && availabilityString(meta, "uid") != candidate.EventUID) ||
			(candidate.EventCreatedAt != "" && availabilityString(meta, "creationTimestamp") != candidate.EventCreatedAt) ||
			availabilityString(labels, "phorvex.ai/attack-correlation") != candidate.Correlation ||
			availabilityString(labels, "phorvex.ai/console-vllm") != "true" ||
			availabilityString(notes, "phorvex.ai/creator-identity") != w.p.Fixture.EventCreator ||
			len(targets) != 1 || targets[0] != "vllm/"+w.p.Fixture.PodName ||
			availabilityMap(spec["rule"])["type"] != candidate.EventRule ||
			availabilityMap(spec["rule"])["source"] != "redteam" {
			return errors.New("ambiguous event readback is not exact owned candidate")
		}
		w.event = &availabilityEvent{availabilityString(meta, "uid"), candidate.EventName,
			availabilityString(meta, "resourceVersion"), w.p.Fixture.EventCreator,
			candidate.Correlation, w.p.Fixture.PodUID, candidate.EventRule, "redteam"}
		return w.saveJSON("event-reconciled-owned.json", w.event)
	}
	return errors.New("ambiguous event remains unresolved after bounded exact-name reads")
}

func (w *availabilityWorker) readMeasuredGuardrailEvent(stimulus *attackStimulusEvidence) (*availabilityEvent, error) {
	obj, err := w.kube("created-event", "get", "securityevents.amtd.r6security.com", stimulus.EventName, "-o", "json")
	if err != nil {
		return nil, err
	}
	meta, spec := availabilityMeta(obj), availabilityMap(obj["spec"])
	labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
	rule := availabilityMap(spec["rule"])
	targets, _ := spec["targets"].([]any)
	if availabilityUID(obj) != stimulus.EventUID || availabilityString(meta, "name") != stimulus.EventName ||
		availabilityString(meta, "creationTimestamp") != stimulus.EventCreatedAt ||
		availabilityString(meta, "resourceVersion") == "" ||
		availabilityString(labels, "phorvex.ai/attack-correlation") != stimulus.Correlation ||
		availabilityString(labels, "phorvex.ai/console-vllm") != "true" ||
		availabilityString(notes, "phorvex.ai/creator-identity") != w.p.Fixture.EventCreator ||
		len(targets) != 1 || targets[0] != "vllm/"+w.p.Fixture.PodName ||
		rule["type"] != "phorvex.attack.guardrail" || rule["source"] != "redteam" {
		return nil, errors.New("injected event original identity or authority differs")
	}
	return &availabilityEvent{stimulus.EventUID, stimulus.EventName,
		availabilityString(meta, "resourceVersion"), w.p.Fixture.EventCreator,
		stimulus.Correlation, w.p.Fixture.PodUID, "phorvex.attack.guardrail", "redteam"}, nil
}
