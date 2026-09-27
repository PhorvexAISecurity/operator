package console

import (
	"errors"
	"os"
	"strings"

	"github.com/phorvex/phorvex/internal/audittransport"
	"sigs.k8s.io/yaml"
)

// The attack-history projection reopens every bounded original. The worker's
// status, classifications and claimed event/operation are never authority.
func readGuardrailEffectProbeResult(out, id, admittedSHA string) (*guardrailEffectProbeResult, error) {
	raw, err := readNATSResponseSizedFile(out, "guardrail-effect-terminal.json", 96<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var term availabilityTerminal
	if err = availabilityDecode(raw, &term); err != nil {
		return nil, err
	}
	if term.Schema != "guardrail-effect-terminal-v1" || term.RunID != id || !staticSHA256.MatchString(admittedSHA) ||
		term.ProfileSHA256 != admittedSHA || len(term.Receipts) < 3 || len(term.Receipts) > 250 ||
		term.ConsolePOSTsAttempted != 1 || term.ConsoleGETsAttempted != 0 ||
		term.GuardedChatsAttempted > 6 || term.SecurityEventsAttempted > 1 ||
		term.KubeReadsAttempted > 120 || term.ExactEventDeletesAttempted > 1 {
		return nil, errors.New("guardrail effect terminal identity or budget differs")
	}
	e := availabilityEvidence{out: out, files: map[string][]byte{}, terminal: term}
	for _, receipt := range term.Receipts {
		if receipt.File == "" || strings.ContainsAny(receipt.File, "/\\") || strings.HasPrefix(receipt.File, ".") ||
			receipt.Bytes < 1 || receipt.Bytes > 1<<20 || !staticSHA256.MatchString(receipt.SHA256) || e.files[receipt.File] != nil {
			return nil, errors.New("guardrail effect receipt inventory malformed")
		}
		b, re := readNATSResponseSizedFile(out, receipt.File, int64(receipt.Bytes))
		if re != nil || len(b) != receipt.Bytes || availabilityHash(b) != receipt.SHA256 {
			return nil, errors.New("guardrail effect original receipt changed")
		}
		e.files[receipt.File] = b
	}
	profileRaw, err := e.original("profile-original.yaml")
	if err != nil || availabilityHash(profileRaw) != admittedSHA {
		return nil, errors.New("guardrail effect original reviewed profile differs")
	}
	e.p, err = parseGuardrailAvailabilityProfile(profileRaw)
	// Historical effect runs retain their original one-file source contract.
	// New admission requires a dual-listener pin, and snapshot replay enforces
	// it when that field exists in the exact original profile bytes.
	if err != nil || (e.p.Fixture.ActiveVariant != "pgv1" && e.p.Fixture.ActiveVariant != "pgv2") {
		return nil, errors.New("guardrail effect original active variant unpinned")
	}
	if err = e.decode("self-identity.json", &e.self); err != nil || e.self["name"] == "" || !staticUID.MatchString(e.self["uid"]) {
		return nil, errors.New("guardrail effect original self identity differs")
	}
	return e.projectMeasuredGuardrailEffect()
}

func (e *availabilityEvidence) projectMeasuredGuardrailEffect() (*guardrailEffectProbeResult, error) {
	result := newGuardrailEffectProbeResult(e.terminal.ProfileSHA256)
	result.GuardedChatsAttempted = e.terminal.GuardedChatsAttempted
	result.SecurityEventsAttempted = e.terminal.SecurityEventsAttempted
	markerRaw, err := e.original("private-marker.bin")
	if err != nil || !availabilityMarker.Match(markerRaw) {
		return result, errors.New("guardrail effect private marker unavailable or malformed")
	}
	marker := string(markerRaw)
	result.MarkerSHA256 = availabilityHash(markerRaw)
	var intent map[string]any
	if e.decode("private-intent.json", &intent) != nil || intent["runID"] != e.terminal.RunID ||
		intent["markerSHA256"] != result.MarkerSHA256 || intent["maximumGuardedChats"] != float64(6) ||
		intent["maximumSecurityEvents"] != float64(1) || intent["consoleLaunchPOSTs"] != float64(1) {
		return result, errors.New("guardrail effect fixed private intent differs")
	}
	requests := map[string][]byte{}
	for _, which := range []string{"canary", "say_ok", "arithmetic"} {
		requests[which] = availabilityRequest(e.p.Fixture.ModelID, marker, which)
		if availabilityMap(intent["requestSHA256"])[which] != availabilityHash(requests[which]) {
			return result, errors.New("guardrail effect fixed request hash differs")
		}
	}
	for i, row := range e.terminal.Calls {
		phase := "before"
		if i >= 3 {
			phase = "after"
		}
		want := phase + "-" + []string{"canary", "say_ok", "arithmetic"}[i%3]
		if row.ID != want {
			return result, errors.New("guardrail effect call order differs")
		}
	}
	if len(e.terminal.Calls) != 3 && len(e.terminal.Calls) != 6 {
		return result, nil
	}
	before, err := e.snapshot("before")
	if err != nil || guardrailEffectProtected(before, e.p) != nil {
		return result, errors.New("original protected effect baseline differs")
	}
	for _, which := range []string{"canary", "say_ok", "arithmetic"} {
		pre, pe := e.snapshot("before-" + which + "-pre")
		post, po := e.snapshot("before-" + which + "-post")
		if pe != nil || po != nil || !availabilitySameSource(before, pre, false) || !availabilitySameSource(before, post, false) {
			return result, errors.New("original pre-event call source drift")
		}
		_, cl, ce := e.call("before-"+which, which, marker, requests[which])
		if ce != nil {
			return result, ce
		}
		switch which {
		case "canary":
			result.Before.Canary = cl
		case "say_ok":
			result.Before.SayOK = cl
		case "arithmetic":
			result.Before.Arithmetic = cl
		}
	}
	gate := guardrailEffectBaselineGate(result.Before)
	if gate != "THREAT_LANDED_BEFORE_INJECTED_RESPONSE" {
		if len(e.terminal.Calls) != 3 || e.terminal.SecurityEventsAttempted != 0 ||
			e.terminal.ExactEventDeletesAttempted != 0 || !e.terminal.CleanupVerified || e.terminal.Status != gate {
			return result, errors.New("pre-event stop contradicted by a mutation or terminal")
		}
		for _, forbidden := range []string{"event-intent.json", "event-producer.json", "created-event.json", "audit-terminal.json", "delete-intent.json"} {
			if e.files[forbidden] != nil {
				return result, errors.New("pre-event stop has a contradictory event or audit receipt")
			}
		}
		result.Status, result.Accepted, result.CleanupVerified = gate, gate != "UNKNOWN", true
		return result, nil
	}
	prepost, pe := e.snapshot("prepost")
	immediate, ie := e.snapshot("immediate-pre-event")
	if pe != nil || ie != nil || availabilityAdmissionMatches(before, prepost, immediate) != nil {
		return result, errors.New("original immediate pre-event source or journal drift")
	}
	var population map[string]any
	if e.findKube("prepost-target-population", &population) != nil || availabilityOneTargetPopulation(population, before, e.p.Fixture.PodName) != nil {
		return result, errors.New("original pre-event target population differs")
	}
	if e.terminal.SecurityEventsAttempted != 1 || len(e.terminal.Calls) != 6 {
		return result, nil
	}
	result.EventMode = "INJECTED"
	operation, err := e.snapshot("operation")
	if err != nil || !availabilitySameSource(before, operation, true) {
		return result, errors.New("original operation source identity differs")
	}
	for _, which := range []string{"canary", "say_ok", "arithmetic"} {
		pre, pe := e.snapshot("after-" + which + "-pre")
		post, po := e.snapshot("after-" + which + "-post")
		if pe != nil || po != nil || !availabilitySameSource(operation, pre, false) || !availabilitySameSource(operation, post, false) {
			return result, errors.New("original post-event call source drift")
		}
		_, cl, ce := e.call("after-"+which, which, marker, requests[which])
		if ce != nil {
			return result, ce
		}
		switch which {
		case "canary":
			result.After.Canary = cl
		case "say_ok":
			result.After.SayOK = cl
		case "arithmetic":
			result.After.Arithmetic = cl
		}
	}
	final, err := e.snapshot("final")
	if err != nil || !availabilitySameSource(operation, final, false) {
		return result, errors.New("original final operation source drift")
	}
	event, selected, err := e.joinMeasuredGuardrailEffect(before)
	if err != nil {
		result.Issues = append(result.Issues, "exact injected event, authenticated decision or cleanup join unavailable")
		return result, nil
	}
	result.CleanupVerified = true
	result.EventUID = event.UID
	if selected == nil {
		if availabilitySameSource(before, operation, false) {
			result.Status, result.Accepted = "INJECTED_EVENT_NO_SELECTED_EFFECT", true
		}
		return result, nil
	}
	op, err := guardrailEffectTransition(before, operation, *selected, e.p)
	if err != nil {
		result.Issues = append(result.Issues, "selected decision and protected operation do not join")
		return result, nil
	}
	result.DecisionID, result.OperationID = selected.DecisionID, op
	result.PriorVariant, result.NextVariant = before.ActiveVariant, operation.ActiveVariant
	result.Status = guardrailEffectAfterStatus(result.Before, result.After)
	result.Accepted = result.Status != "UNKNOWN"
	return result, nil
}

func (e *availabilityEvidence) measuredEvent(before availabilitySnapshot) (availabilityEvent, error) {
	var event availabilityEvent
	var intent map[string]any
	var start availabilityAuditStart
	if e.decode("audit-start.json", &start) != nil || start.Schema != "guardrail-availability-audit-start-v1" ||
		e.decode("event-intent.json", &intent) != nil || intent["runID"] != e.terminal.RunID ||
		intent["auditStartSHA256"] != availabilityHash(mustAvailabilityJSON(start)) ||
		intent["baselineGate"] != "THREAT_LANDED_BEFORE_INJECTED_RESPONSE" ||
		intent["maximumSecurityEvents"] != float64(1) || intent["targetPodUID"] != before.TargetPodUID {
		return event, errors.New("original event intent or authenticated start differs")
	}
	startManifest, err := e.original("audit-start-manifest.json")
	if err != nil || availabilityHash(startManifest) != start.ManifestSHA256 {
		return event, errors.New("original audit checkpoint manifest differs")
	}
	var producer attackStimulusEvidence
	if e.decode("event-producer.json", &producer) != nil || !producer.Observed ||
		producer.EventUID == "" || producer.EventName == "" || producer.TargetUID != before.TargetPodUID ||
		producer.EventRule != "phorvex.attack.guardrail" {
		return event, errors.New("original injected producer result differs")
	}
	if e.decode("created-event.json", &event) != nil || event.UID != producer.EventUID ||
		event.Name != producer.EventName || event.Correlation != producer.Correlation ||
		event.TargetPodUID != before.TargetPodUID || event.CreatorIdentity != e.p.Fixture.EventCreator ||
		event.RuleType != producer.EventRule || event.Source != "redteam" || event.ResourceVersion == "" {
		return event, errors.New("original created event receipt differs")
	}
	manifestRaw, me := e.original("event-create-manifest.yaml")
	replyRaw, re := e.original("event-create-reply.json")
	if me != nil || re != nil || len(manifestRaw) > 64<<10 || len(replyRaw) > 64<<10 {
		return event, errors.New("original injected create request or reply absent")
	}
	var manifest map[string]any
	var reply vllmSecurityEvent
	if yaml.UnmarshalStrict(manifestRaw, &manifest) != nil || availabilityDecode(replyRaw, &reply) != nil {
		return event, errors.New("original injected create request or reply malformed")
	}
	mm := availabilityMap(manifest["metadata"])
	ml := availabilityMap(mm["labels"])
	ms := availabilityMap(manifest["spec"])
	mr := availabilityMap(ms["rule"])
	mt, _ := ms["targets"].([]any)
	if manifest["apiVersion"] != "amtd.r6security.com/v1beta1" || manifest["kind"] != "SecurityEvent" ||
		len(mm) != 2 || mm["name"] != event.Name || len(ml) != 3 ||
		ml["phorvex.ai/redteam"] != "true" || ml["phorvex.ai/console-vllm"] != "true" ||
		ml["phorvex.ai/attack-correlation"] != event.Correlation ||
		len(ms) != 4 || ms["description"] != guardrailEffectEventDescription ||
		len(mt) != 1 || mt[0] != "vllm/"+e.p.Fixture.PodName ||
		len(mr) != 3 || mr["type"] != "phorvex.attack.guardrail" ||
		mr["source"] != "redteam" || mr["threatLevel"] != "critical" || ms["anomalyScore"] != "0.95" ||
		reply.Metadata.Name != event.Name || reply.Metadata.Namespace != "" ||
		reply.Metadata.UID != event.UID || reply.Metadata.CreationTimestamp != producer.EventCreatedAt ||
		reply.Metadata.Labels["phorvex.ai/attack-correlation"] != event.Correlation ||
		reply.Metadata.Labels["phorvex.ai/console-vllm"] != "true" ||
		len(reply.Spec.Targets) != 1 || reply.Spec.Targets[0] != "vllm/"+e.p.Fixture.PodName ||
		reply.Spec.Rule.Type != event.RuleType || reply.Spec.Rule.Source != event.Source {
		return event, errors.New("original injected create request or API acknowledgement differs")
	}
	var obj map[string]any
	if e.findKube("created-event", &obj) != nil || availabilityUID(obj) != event.UID ||
		availabilityString(availabilityMeta(obj), "name") != event.Name ||
		availabilityString(availabilityMeta(obj), "resourceVersion") != event.ResourceVersion {
		return event, errors.New("original Kubernetes event identity differs")
	}
	meta, spec := availabilityMeta(obj), availabilityMap(obj["spec"])
	if availabilityString(meta, "creationTimestamp") != producer.EventCreatedAt ||
		availabilityString(meta, "creationTimestamp") == "" {
		return event, errors.New("original event creation timestamp differs")
	}
	labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
	targets, _ := spec["targets"].([]any)
	if availabilityString(labels, "phorvex.ai/attack-correlation") != event.Correlation ||
		availabilityString(labels, "phorvex.ai/console-vllm") != "true" ||
		availabilityString(notes, "phorvex.ai/creator-identity") != event.CreatorIdentity ||
		len(targets) != 1 || targets[0] != "vllm/"+e.p.Fixture.PodName ||
		availabilityMap(spec["rule"])["type"] != event.RuleType ||
		availabilityMap(spec["rule"])["source"] != event.Source {
		return event, errors.New("original Kubernetes event creator/rule/target differs")
	}
	var inventory map[string]any
	if e.findKube("prepost-event-inventory", &inventory) != nil ||
		availabilityString(availabilityMeta(inventory), "continue") != "" {
		return event, errors.New("original pre-event inventory incomplete")
	}
	items, ok := inventory["items"].([]any)
	if !ok || len(items) > 512 {
		return event, errors.New("original pre-event inventory malformed")
	}
	for _, raw := range items {
		item := availabilityMap(raw)
		if availabilityUID(item) == event.UID || availabilityString(availabilityMeta(item), "name") == event.Name {
			return event, errors.New("original pre-event inventory contains created event")
		}
	}
	return event, nil
}

// Direction-neutral consumer for the authenticated exact window. The same
// strict interval/NOOP/ownership predicates are used by recovery; only the
// operation direction and outcome oracle differ.
func (e *availabilityEvidence) joinMeasuredGuardrailEffect(before availabilitySnapshot) (availabilityEvent, *availabilityDecision, error) {
	event, err := e.measuredEvent(before)
	if err != nil {
		return event, nil, err
	}
	var audit availabilityAuditTerminal
	var start availabilityAuditStart
	if e.decode("audit-terminal.json", &audit) != nil || e.decode("audit-start.json", &start) != nil {
		return event, nil, errors.New("authenticated audit terminal absent")
	}
	startRaw, se := e.original("audit-start-manifest.json")
	endRaw, ee := e.original("audit-end-manifest.json")
	finalRaw, fe := e.original("audit-terminal-manifest.json")
	var sm, em, fm audittransport.Manifest
	if se != nil || ee != nil || fe != nil || availabilityDecode(startRaw, &sm) != nil ||
		availabilityDecode(endRaw, &em) != nil || availabilityDecode(finalRaw, &fm) != nil ||
		!availabilityValidManifest(sm) || !availabilityValidManifest(em) || !availabilityValidManifest(fm) ||
		availabilityHash(startRaw) != start.ManifestSHA256 || availabilityHash(endRaw) != audit.EndManifestSHA256 ||
		availabilityHash(finalRaw) != audit.TerminalManifestSHA256 || sm.Segments[0] != start.Segment ||
		start.CheckpointSize != start.Segment.Size || start.AlignedOffset > start.CheckpointSize ||
		sm.FetchedAt > em.FetchedAt || em.FetchedAt > fm.FetchedAt {
		return event, nil, errors.New("audit original manifests do not join")
	}
	spans, err := availabilitySpans(start, em)
	if err != nil {
		return event, nil, err
	}
	finalSpans, err := availabilitySpans(start, fm)
	if err != nil || len(finalSpans) < len(spans) {
		return event, nil, errors.New("audit final spans missing")
	}
	var sum int64
	index := 0
	for i, span := range spans {
		seg, off, end := span[0].(audittransport.Segment), span[1].(int64), span[2].(int64)
		later := finalSpans[i][0].(audittransport.Segment)
		if seg.Generation != later.Generation || seg.Anchor != later.Anchor || later.Size < end {
			return event, nil, errors.New("audit final generation changed")
		}
		for off < end {
			if index >= len(audit.ChunkReceipts) {
				return event, nil, errors.New("audit chunk receipt absent")
			}
			c := audit.ChunkReceipts[index]
			want := int(min(int64(audittransport.ChunkBytes), end-off))
			if c.SegmentID != seg.ID || c.Generation != seg.Generation || c.Offset != off || c.Bytes != want || !staticSHA256.MatchString(c.SHA256) {
				return event, nil, errors.New("audit chunk does not cover frozen span")
			}
			off += int64(want)
			sum += int64(want)
			index++
		}
	}
	if audit.Schema != "guardrail-availability-audit-terminal-v1" || audit.Status != "COMPLETE" ||
		!audit.CoverageComplete || audit.RawAuditRetained || audit.CloseStartedLate ||
		audit.SourceIdentity != start.SourceIdentity || audit.SourceIdentity != e.p.Fixture.AuditURL+"|"+e.p.Fixture.AuditServerName ||
		audit.StartSHA256 != availabilityHash(mustAvailabilityJSON(start)) ||
		audit.UnboundTargetRows == nil || *audit.UnboundTargetRows != 0 ||
		audit.PayloadBytes > 96<<20 || audit.PayloadBytes < audit.FrozenBytes ||
		audit.BytesRead != audit.FrozenBytes || sum != audit.FrozenBytes ||
		index != len(audit.ChunkReceipts) || audit.DataGETs != index || audit.DataGETs > 100 ||
		audit.ControlGETs < 2 || audit.ControlGETs > 3 || audit.AuditReadElapsedSeconds >= 180 {
		return event, nil, errors.New("authenticated audit coverage incomplete")
	}
	var selected *availabilityDecision
	exactObservations := 0
	for i := range audit.TargetRows {
		d := &audit.TargetRows[i]
		if d.PolicyUID != before.PolicyUID || d.AssetUID != before.TargetPodUID || d.DecisionID == "" || d.TickID == "" || d.OtherTrustedEventCount != 0 {
			return event, nil, errors.New("audit target or competing trusted event differs")
		}
		if d.Selected || d.Actuated || d.Action != "noop" || d.DispatchOutcome != "not-attempted" || d.TopLevelDispatchOutcome != "" || d.Handler != "" || d.MutationKind != "" || d.GracefulTermination {
			if selected != nil {
				return event, nil, errors.New("competing mutating target decision")
			}
			selected = d
			continue
		}
		if d.EventCoverage == "EXACT_TRUSTED_EVENT_OBSERVED" {
			exactObservations++
			if d.ExactEventUID != event.UID || d.ExactEventName != event.Name ||
				d.ExactEventCreator != event.CreatorIdentity || d.ExactEventTargetPodUID != before.TargetPodUID || d.EventWeight <= 0 {
				return event, nil, errors.New("passive event observation differs")
			}
		} else if d.EventCoverage != "EXACT_EVENT_NOT_PRESENT_IN_THIS_DECISION" || d.ExactEventUID != "" {
			return event, nil, errors.New("unbound passive event observation")
		}
	}
	if selected != nil {
		if !selected.Selected || !selected.Actuated || selected.Action != "guardrail-rotate" ||
			selected.DispatchOutcome != "emitted" || selected.TopLevelDispatchOutcome != "emitted" ||
			selected.EventCoverage != "EXACT_TRUSTED_EVENT_OBSERVED" ||
			selected.ExactEventUID != event.UID || selected.ExactEventName != event.Name ||
			selected.ExactEventCreator != event.CreatorIdentity || selected.ExactEventTargetPodUID != before.TargetPodUID ||
			selected.EventWeight <= 0 || selected.EventEvidence <= 0 {
			return event, nil, errors.New("selected decision lacks exact injected event")
		}
		exactObservations++
	}
	if len(audit.TargetRows) == 0 || exactObservations == 0 || !e.terminal.CleanupVerified || e.terminal.ExactEventDeletesAttempted != 1 {
		return event, nil, errors.New("exact event observation or cleanup absent")
	}
	var cluster, predelete, ack, absence map[string]any
	var intent availabilityEvent
	if e.decode("cleanup-cluster.json", &cluster) != nil || availabilityUID(cluster) != before.ClusterUID ||
		e.decode("event-predelete.json", &predelete) != nil || e.decode("delete-intent.json", &intent) != nil ||
		e.decode("delete-ack.json", &ack) != nil || e.decode("event-absence.json", &absence) != nil || intent != event {
		return event, nil, errors.New("original event cleanup receipts absent")
	}
	meta, spec := availabilityMeta(predelete), availabilityMap(predelete["spec"])
	labels, notes := availabilityMap(meta["labels"]), availabilityMap(meta["annotations"])
	targets, _ := spec["targets"].([]any)
	if availabilityString(meta, "uid") != event.UID || availabilityString(meta, "name") != event.Name ||
		availabilityString(meta, "resourceVersion") != event.ResourceVersion ||
		availabilityString(notes, "phorvex.ai/creator-identity") != event.CreatorIdentity ||
		availabilityString(labels, "phorvex.ai/attack-correlation") != event.Correlation ||
		len(targets) != 1 || targets[0] != "vllm/"+e.p.Fixture.PodName ||
		availabilityMap(spec["rule"])["type"] != event.RuleType ||
		availabilityMap(spec["rule"])["source"] != event.Source ||
		ack["acknowledged"] != true || ack["uid"] != event.UID || ack["resourceVersion"] != event.ResourceVersion ||
		absence["notFound"] != true || absence["uid"] != event.UID || absence["name"] != event.Name {
		return event, nil, errors.New("exact owned event delete or absence differs")
	}
	return event, selected, nil
}
