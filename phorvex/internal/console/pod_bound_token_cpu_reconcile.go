package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

// cpuPreEventProof is evidence of a *cleaned* setup failure, not a successful
// response or a change to the original partial/unsafe RunStatus.
type cpuPreEventProof struct {
	runID, nonce, namespaceUID, name                       string
	created                                                map[string]string
	deploymentUID, replicaSetUID, sourcePodUID, peerPodUID string
	amtdUID                                                string
	phaseSHA256, inventorySHA256                           string
}

var cpuPreEventResources = map[string]bool{
	"serviceaccounts": true, "deployments": true, "services": true,
	"poddisruptionbudgets": true, "roles": true, "rolebindings": true,
	"phorvexpolicies": true, "podmonitors": true,
}

// Each of these files would mean the run crossed, or ambiguously approached,
// the request/event/observation boundary. A pre-event admission cannot use it.
var cpuPostFixtureFiles = [...]string{
	podBoundRequestFile, "pod-bound-token-audit-start.json", podBoundBarrierFile,
	podBoundArtifactFile, podBoundTerminalFile, podBoundSealFile,
	podBoundObservationEndFile, podBoundObservationCommittedFile,
	podBoundEventCleanupFile, podBoundReplayFile,
}

func cpuPreEventProofAt(prior *RunStatus, out, expectedTarget string) (cpuPreEventProof, error) {
	var proof cpuPreEventProof
	if prior == nil || !prior.UnsafeToRetry || prior.Config != podBoundTokenCPUConfig ||
		prior.ExecutionKind != "" || prior.State != "partial" || prior.Outcome != "" ||
		prior.CleanupStatus != "UNVERIFIED" || prior.Namespace != podBoundTokenCPUNamespace ||
		prior.ScopeTenant != podBoundTokenCPUNamespace || prior.ScopeTarget != expectedTarget ||
		prior.ScopeTarget == "" || prior.ScopeTarget == defaultTargetID ||
		prior.ID == "" || filepath.Base(out) != prior.ID || prior.Owner == "" || prior.Finished == "" ||
		prior.Trials != 0 || len(prior.Arms) != 0 || prior.NativeActuator {
		return proof, errors.New("CPU token pre-event predecessor status differs")
	}
	unsafe, err := readPodBoundTokenUnsafe(out, prior.ID)
	if err != nil || unsafe.CleanupStatus != "CONFIRMED_ABSENT" || !mongoSHA.MatchString(unsafe.InventorySHA256) ||
		!mongoKubeUID.MatchString(unsafe.NamespaceUID) || len(unsafe.CreatedUIDs) == 0 ||
		unsafe.ErrorSHA256 != podBoundHash([]byte("CPU token source-Pod measured request rate unavailable before event")) ||
		prior.Error != fmt.Sprintf("Pod-bound token early unsafe receipt: %d created UIDs, cleanup CONFIRMED_ABSENT; exact reconciliation required", len(unsafe.CreatedUIDs)) {
		return proof, errors.New("CPU token original unsafe cleanup or status differs")
	}
	for _, name := range cpuPostFixtureFiles {
		if _, err := os.Lstat(filepath.Join(out, name)); !errors.Is(err, os.ErrNotExist) {
			return proof, errors.New("CPU token predecessor has request, event or terminal artifacts")
		}
	}
	raw, err := readNATSResponseSizedFile(out, podBoundPhaseFile, 256<<10)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' || podBoundHash(raw) != unsafe.PhaseJournalSHA256 {
		return proof, errors.New("CPU token original phase journal differs")
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) != 36 {
		return proof, errors.New("CPU token original phase count differs")
	}
	type phaseState struct {
		intent, created, deleteIntent, deleted bool
		uid                                    string
	}
	states := map[string]*phaseState{}
	var last time.Time
	var deleting, patchIntent, patched, amtdIntent, amtdDeleted bool
	var patchName string
	var amtdUID string
	for _, line := range lines {
		if len(line) == 0 || len(line) > 2048 || rejectNATSNestedDuplicates(line) != nil {
			return proof, errors.New("CPU token original phase row ambiguous")
		}
		var row podBoundPhaseRow
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&row) != nil || decoder.Decode(new(any)) != io.EOF ||
			row.Schema != "pod-bound-token-phase-v1" || row.RunID != prior.ID || row.Nonce != unsafe.Nonce {
			return proof, errors.New("CPU token original phase identity differs")
		}
		at, err := time.Parse(time.RFC3339Nano, row.At)
		if err != nil || at.IsZero() || !last.IsZero() && at.Before(last) {
			return proof, errors.New("CPU token original phase chronology differs")
		}
		last = at
		if row.Operation == "PATCH_INTENT" || row.Operation == "PATCH_ACK" {
			if deleting || row.Resource != "pods" || unsafe.SourcePodUID == "" ||
				row.UID != unsafe.SourcePodUID || !strings.HasPrefix(row.Name, "pod-token-"+unsafe.Nonce+"-") {
				return proof, errors.New("CPU token original source patch identity differs")
			}
			if row.Operation == "PATCH_INTENT" {
				if patchIntent || patched {
					return proof, errors.New("CPU token source patch duplicated")
				}
				patchIntent, patchName = true, row.Name
			} else {
				if !patchIntent || patched || row.Name != patchName {
					return proof, errors.New("CPU token source patch acknowledgement differs")
				}
				patched = true
			}
			continue
		}
		if row.Resource == "adaptivemovingtargetdefenses" {
			if row.Name != "phorvex-"+podBoundTokenCPUNamespace+"-"+unsafe.Nonce ||
				!mongoKubeUID.MatchString(row.UID) || row.Operation != "DELETE_INTENT" && row.Operation != "DELETE_ACK" ||
				states["phorvexpolicies"] == nil || !states["phorvexpolicies"].deleted {
				return proof, errors.New("CPU token generated AMTD cleanup identity differs")
			}
			deleting = true
			if row.Operation == "DELETE_INTENT" {
				if amtdIntent {
					return proof, errors.New("CPU token generated AMTD delete duplicated")
				}
				amtdIntent, amtdUID = true, row.UID
			} else {
				if !amtdIntent || amtdDeleted || row.UID != amtdUID {
					return proof, errors.New("CPU token generated AMTD delete acknowledgement differs")
				}
				amtdDeleted = true
			}
			continue
		}
		if !cpuPreEventResources[row.Resource] || row.Name != "pod-token-"+unsafe.Nonce {
			return proof, errors.New("CPU token original created resource differs")
		}
		state := states[row.Resource]
		if state == nil {
			state = &phaseState{}
			states[row.Resource] = state
		}
		switch row.Operation {
		case "CREATE_INTENT":
			if deleting || state.intent || row.UID != "" {
				return proof, errors.New("CPU token create intent differs")
			}
			state.intent = true
		case "CREATE_ACK":
			if deleting || !state.intent || state.created || !mongoKubeUID.MatchString(row.UID) {
				return proof, errors.New("CPU token create acknowledgement differs")
			}
			state.created, state.uid = true, row.UID
		case "DELETE_INTENT":
			deleting = true
			if !state.created || state.deleteIntent || row.UID != state.uid {
				return proof, errors.New("CPU token delete intent differs")
			}
			state.deleteIntent = true
		case "DELETE_ACK":
			if !state.deleteIntent || state.deleted || row.UID != state.uid {
				return proof, errors.New("CPU token delete acknowledgement differs")
			}
			state.deleted = true
		default:
			return proof, errors.New("CPU token pre-event journal contains an effect phase")
		}
	}
	if !patchIntent || !patched {
		return proof, errors.New("CPU token source patch incomplete")
	}
	if !amtdIntent || !amtdDeleted {
		return proof, errors.New("CPU token generated AMTD cleanup incomplete")
	}
	if recorded, err := time.Parse(time.RFC3339Nano, unsafe.RecordedAt); err != nil || recorded.Before(last) {
		return proof, errors.New("CPU token unsafe receipt predates cleanup phases")
	}
	created := map[string]string{}
	rows := make([]string, 0, len(states))
	for resource, state := range states {
		if !state.intent || !state.created || !state.deleteIntent || !state.deleted {
			return proof, errors.New("CPU token original create/delete chain incomplete")
		}
		created[resource] = state.uid
		rows = append(rows, resource+"/pod-token-"+unsafe.Nonce+"/"+state.uid)
	}
	sort.Strings(rows)
	if len(rows) != len(cpuPreEventResources) || !sort.StringsAreSorted(unsafe.CreatedUIDs) || len(rows) != len(unsafe.CreatedUIDs) {
		return proof, errors.New("CPU token original created UID list differs")
	}
	for i := range rows {
		if rows[i] != unsafe.CreatedUIDs[i] {
			return proof, errors.New("CPU token original created UID list differs")
		}
	}
	if unsafe.DeploymentUID != created["deployments"] ||
		!mongoKubeUID.MatchString(unsafe.DeploymentUID) || !mongoKubeUID.MatchString(unsafe.ReplicaSetUID) ||
		!mongoKubeUID.MatchString(unsafe.SourcePodUID) || !mongoKubeUID.MatchString(unsafe.PeerPodUID) ||
		unsafe.SourcePodUID == unsafe.PeerPodUID ||
		unsafe.SourcePodUID == unsafe.DeploymentUID || unsafe.PeerPodUID == unsafe.DeploymentUID {
		return proof, errors.New("CPU token original Deployment, ReplicaSet or Pod UID differs")
	}
	proof = cpuPreEventProof{runID: prior.ID, nonce: unsafe.Nonce, namespaceUID: unsafe.NamespaceUID,
		name: "pod-token-" + unsafe.Nonce, created: created, deploymentUID: unsafe.DeploymentUID,
		replicaSetUID: unsafe.ReplicaSetUID, sourcePodUID: unsafe.SourcePodUID,
		peerPodUID: unsafe.PeerPodUID, amtdUID: amtdUID, phaseSHA256: unsafe.PhaseJournalSHA256,
		inventorySHA256: unsafe.InventorySHA256}
	return proof, nil
}

// Caller holds rm.mu. Every retained unsafe CPU setup failure is validated;
// the bound prevents a growing history from silently weakening admission.
func (rm *RunManager) cpuPreEventProofsLocked(expectedTarget string) ([]cpuPreEventProof, error) {
	if rm == nil || rm.runs == nil || rm.loadErr != nil {
		return nil, errors.New("CPU token retained run history unavailable")
	}
	var priors []*RunStatus
	for _, status := range rm.runs {
		if status == nil {
			return nil, errors.New("CPU token prior run history ambiguous")
		}
		if status.UnsafeToRetry && status.Config == podBoundTokenCPUConfig {
			priors = append(priors, status)
			if len(priors) > 32 {
				return nil, errors.New("CPU token unsafe setup history exceeds reviewed bound")
			}
		}
	}
	sort.Slice(priors, func(i, j int) bool { return priors[i].ID < priors[j].ID })
	proofs := make([]cpuPreEventProof, 0, len(priors))
	for _, prior := range priors {
		if rm.procs[prior.ID] != nil || rm.stopping[prior.ID] ||
			strings.Contains(prior.Error, "reconciliation pending") ||
			!cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(prior.ID)) {
			return nil, errors.New("CPU token unsafe predecessor remains active or unresolved")
		}
		proof, err := cpuPreEventProofAt(prior, rm.cfg.runOutputPath(prior.ID), expectedTarget)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}
