package console

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// An early post-mutation receipt cannot be promoted to a mechanism result.
// It remains visible so operators can reconcile exact created UIDs.
type PodBoundTokenUnsafeReceipt struct {
	Schema             string   `json:"schema"`
	RunID              string   `json:"runID"`
	Nonce              string   `json:"nonce"`
	NamespaceUID       string   `json:"namespaceUID"`
	CreatedUIDs        []string `json:"createdUIDs"`
	DeploymentUID      string   `json:"deploymentUID"`
	ReplicaSetUID      string   `json:"replicaSetUID"`
	SourcePodUID       string   `json:"sourcePodUID"`
	PeerPodUID         string   `json:"peerPodUID"`
	PhaseJournalSHA256 string   `json:"phaseJournalSHA256"`
	CleanupStatus      string   `json:"cleanupStatus"`
	InventorySHA256    string   `json:"inventorySHA256"`
	ErrorSHA256        string   `json:"errorSHA256"`
	RecordedAt         string   `json:"recordedAt"`
}

func readPodBoundTokenUnsafe(out, id string) (*PodBoundTokenUnsafeReceipt, error) {
	var r PodBoundTokenUnsafeReceipt
	if _, err := readPodBoundJSON(out, "pod-bound-token-unsafe.json", &r); err != nil {
		return nil, err
	}
	if r.Schema != "pod-bound-token-unsafe-v1" || r.RunID != id || !podBoundTokenNonce.MatchString(r.Nonce) ||
		r.NamespaceUID == "" || len(r.CreatedUIDs) > 32 || !mongoSHA.MatchString(r.PhaseJournalSHA256) ||
		!mongoSHA.MatchString(r.ErrorSHA256) || (r.InventorySHA256 != "" && !mongoSHA.MatchString(r.InventorySHA256)) ||
		(r.CleanupStatus != "UNCONFIRMED" && r.CleanupStatus != "CONFIRMED_ABSENT") {
		return nil, errors.New("Pod-bound token unsafe receipt identity differs")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.RecordedAt); err != nil {
		return nil, errors.New("Pod-bound token unsafe receipt time invalid")
	}
	for _, uid := range r.CreatedUIDs {
		parts := strings.Split(uid, "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || len(uid) > 256 {
			return nil, errors.New("Pod-bound token unsafe created UID invalid")
		}
	}
	journal, err := readNATSResponseSizedFile(out, podBoundPhaseFile, 256<<10)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if errors.Is(err, os.ErrNotExist) {
		journal = nil
	}
	if podBoundHash(journal) != r.PhaseJournalSHA256 {
		return nil, errors.New("Pod-bound token unsafe phase journal differs")
	}
	return &r, nil
}

func (rm *RunManager) PodBoundTokenUnsafe(id string) (*PodBoundTokenUnsafeReceipt, error) {
	rm.mu.Lock()
	st := rm.runs[id]
	out := rm.runOut[id]
	rm.mu.Unlock()
	if st == nil || !podBoundNamedCase(st.Config) || out == "" {
		return nil, nil
	}
	r, err := readPodBoundTokenUnsafe(rm.cfg.runOutputPath(out), id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return r, err
}

func podBoundUnsafeStatus(out, id string) string {
	r, err := readPodBoundTokenUnsafe(out, id)
	if err != nil {
		return "Pod-bound token observation or exact cleanup unverified; reconciliation required"
	}
	return fmt.Sprintf("Pod-bound token early unsafe receipt: %d created UIDs, cleanup %s; exact reconciliation required", len(r.CreatedUIDs), r.CleanupStatus)
}
