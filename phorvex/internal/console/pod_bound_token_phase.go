package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const podBoundPhaseFile = "pod-bound-token-phases.jsonl"

type podBoundPhaseRow struct {
	Schema    string `json:"schema"`
	RunID     string `json:"runID"`
	Nonce     string `json:"nonce"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	At        string `json:"at"`
}

// The producer's final phase hash binds create-once intents, API ACKs and
// exact-UID cleanup to the artifact. Absence is a separate API observation,
// made only after the native rotate request and before credential replay.
func verifyPodBoundPhaseJournal(out string, req podBoundTokenRequest, barrier podBoundTokenBarrier, artifact podBoundTokenArtifact) error {
	raw, err := readNATSResponseSizedFile(out, podBoundPhaseFile, 256<<10)
	if err != nil {
		return err
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || podBoundHash(raw) != artifact.PhaseJournalSHA256 {
		return errors.New("Pod-bound token phase journal hash or framing differs")
	}
	requested, e1 := time.Parse(time.RFC3339Nano, req.RequestedAt)
	barrierAt, e2 := time.Parse(time.RFC3339Nano, barrier.ObservedAt)
	end, e3 := time.Parse(time.RFC3339Nano, artifact.ObservationEndedAt)
	sourceAfter, e4 := time.Parse(time.RFC3339Nano, artifact.Result.Replay.SourceAfterAt)
	if e1 != nil || e2 != nil || e3 != nil || (artifact.Result.MechanismObserved && e4 != nil) {
		return errors.New("Pod-bound token phase boundary unavailable")
	}
	intents := map[string]bool{}
	created := map[string]string{}
	deletes := map[string]string{}
	deleted := map[string]bool{}
	var last time.Time
	var monitorAck, sourcePatchAck time.Time
	absence := 0
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		if len(line) == 0 || len(line) > 2048 {
			return errors.New("Pod-bound token phase row size invalid")
		}
		if err := rejectNATSNestedDuplicates(line); err != nil {
			return err
		}
		var row podBoundPhaseRow
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&row) != nil || row.Schema != "pod-bound-token-phase-v1" ||
			row.RunID != req.RunID || row.Nonce != req.Nonce || row.Resource == "" || row.Name == "" {
			return errors.New("Pod-bound token phase identity differs")
		}
		at, err := time.Parse(time.RFC3339Nano, row.At)
		if err != nil || at.IsZero() || (!last.IsZero() && at.Before(last)) {
			return errors.New("Pod-bound token phase order differs")
		}
		last = at
		key := row.Resource + "/" + row.Name
		switch row.Operation {
		case "CREATE_INTENT":
			if row.Name != req.PolicyName || row.UID != "" || at.After(requested) || intents[key] {
				return fmt.Errorf("Pod-bound token create intent differs for %s", key)
			}
			intents[key] = true
		case "CREATE_ACK":
			if !intents[key] || row.UID == "" || created[key] != "" || at.After(requested) {
				return fmt.Errorf("Pod-bound token create ACK differs for %s", key)
			}
			created[key] = row.UID
			if req.CaseID == podBoundTokenCPUCaseID && row.Resource == "podmonitors" {
				monitorAck = at
			}
		case "PATCH_INTENT", "PATCH_ACK":
			if row.Resource != "pods" || row.Name != req.SourcePodName || row.UID != req.SourcePodUID || at.After(requested) {
				return errors.New("Pod-bound token source patch phase differs")
			}
			if req.CaseID == podBoundTokenCPUCaseID && row.Operation == "PATCH_ACK" {
				sourcePatchAck = at
			}
		case "ORIGINAL_POD_ABSENT":
			if row.Resource != "pods" || row.Name != req.SourcePodName || row.UID != req.SourcePodUID ||
				at.Before(barrierAt) || at.After(end) || (e4 == nil && at.After(sourceAfter)) {
				return errors.New("Pod-bound token original UID absence phase differs")
			}
			absence++
		case "DELETE_INTENT":
			if row.UID == "" || at.Before(end) || deletes[key] != "" || (created[key] != "" && created[key] != row.UID) ||
				(created[key] == "" && !podBoundGeneratedCleanupName(row.Resource, row.Name, req)) {
				return fmt.Errorf("Pod-bound token delete intent differs for %s", key)
			}
			deletes[key] = row.UID
		case "DELETE_ACK":
			if deletes[key] == "" || row.UID != deletes[key] || deleted[key] || (created[key] != "" && created[key] != row.UID) {
				return fmt.Errorf("Pod-bound token delete ACK differs for %s", key)
			}
			deleted[key] = true
		default:
			return errors.New("Pod-bound token unknown phase operation")
		}
	}
	if req.CaseID == podBoundTokenCPUCaseID {
		first, parseErr := time.Parse(time.RFC3339Nano, req.MetricFirstAt)
		if parseErr != nil || monitorAck.IsZero() || sourcePatchAck.IsZero() || !first.After(monitorAck) || !first.After(sourcePatchAck) {
			return errors.New("CPU token metric sample predates owned source and PodMonitor setup")
		}
	}
	for _, resource := range []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"} {
		key := resource + "/" + req.PolicyName
		if !intents[key] || created[key] == "" || !deleted[key] {
			return fmt.Errorf("Pod-bound token owned %s create or cleanup incomplete", resource)
		}
	}
	for resource, want := range map[string]string{"deployments": req.DeploymentUID, "services": req.ServiceUID, "phorvexpolicies": req.PolicyUID, "podmonitors": req.PodMonitorUID} {
		if created[resource+"/"+req.PolicyName] != want || want == "" {
			return fmt.Errorf("Pod-bound token %s ACK UID differs from baseline", resource)
		}
	}
	if artifact.Result.Operation.OriginalPodAbsent && absence != 1 {
		return errors.New("Pod-bound token original UID absence witness missing")
	}
	if !artifact.Result.Operation.OriginalPodAbsent && absence != 0 {
		return errors.New("Pod-bound token original UID absence claim differs")
	}
	return nil
}

func podBoundGeneratedCleanupName(resource, name string, req podBoundTokenRequest) bool {
	if resource == "adaptivemovingtargetdefenses" {
		return name == "phorvex-"+req.Namespace+"-"+req.Nonce
	}
	if resource != "networkpolicies" {
		return false
	}
	for _, pod := range []struct{ name, uid string }{{req.SourcePodName, req.SourcePodUID}, {req.PeerPodName, req.PeerPodUID}} {
		if name == "phorvex-quarantine-"+podBoundHash([]byte(pod.uid)) {
			return true
		}
		legacy := req.Namespace + "-" + pod.name + "-policy"
		if len(legacy) <= 63 && name == legacy {
			return true
		}
		sum := podBoundHash([]byte("phoenix-quarantine-policy-v1\x00" + req.Namespace + "\x00" + pod.name))
		if name == "amtd-q-"+sum[:48] {
			return true
		}
	}
	return false
}
