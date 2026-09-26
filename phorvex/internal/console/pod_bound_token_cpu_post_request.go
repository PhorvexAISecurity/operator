package console

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

// cpuCleanupProof records an old run's owned effect footprint. Admission never
// changes the old partial result and never interprets this as a defense result.
type cpuCleanupProof struct {
	cpuPreEventProof
	clusterUID, requestSHA256, auditStartSHA256 string
	peerPodName                                 string
	postRequest                                 bool
}

func cpuPostRequestCleanupProofAt(prior *RunStatus, out, expectedTarget string) (cpuCleanupProof, error) {
	var proof cpuCleanupProof
	for _, name := range []string{"pod-bound-token-unsafe.json", podBoundRequestFile,
		"pod-bound-token-audit-start.json"} {
		raw, err := readNATSResponseSizedFile(out, name, 256<<10)
		if err != nil || rejectAmbiguousMongoJSON(raw) != nil {
			return proof, errors.New("CPU token post-request original JSON is ambiguous")
		}
	}
	phaseRaw, err := readNATSResponseSizedFile(out, podBoundPhaseFile, 256<<10)
	if err != nil || len(phaseRaw) == 0 || phaseRaw[len(phaseRaw)-1] != '\n' {
		return proof, errors.New("CPU token post-request phase original unavailable")
	}
	for _, line := range bytes.Split(phaseRaw[:len(phaseRaw)-1], []byte{'\n'}) {
		if rejectAmbiguousMongoJSON(line) != nil {
			return proof, errors.New("CPU token post-request phase JSON is ambiguous")
		}
	}
	base, err := cpuCleanupBaseProofAt(prior, out, expectedTarget, true)
	if err != nil {
		return proof, err
	}
	var req podBoundTokenRequest
	reqRaw, err := readPodBoundJSON(out, podBoundRequestFile, &req)
	if err != nil {
		return proof, errors.New("CPU token post-request original unavailable")
	}
	requested, err := time.Parse(time.RFC3339Nano, req.RequestedAt)
	if err != nil || base.lastCreateAt.IsZero() || base.firstDeleteAt.IsZero() ||
		requested.Before(base.lastCreateAt) || !requested.Before(base.firstDeleteAt) ||
		req.Schema != "pod-bound-token-request-v1" || req.CaseID != podBoundTokenCPUCaseID ||
		req.RunID != prior.ID || req.Nonce != base.nonce || req.Namespace != podBoundTokenCPUNamespace ||
		req.NamespaceUID != base.namespaceUID || !mongoKubeUID.MatchString(req.ClusterUID) ||
		req.ServiceName != base.name || req.PolicyName != base.name ||
		req.SourcePodName != base.sourcePodName || !strings.HasPrefix(req.SourcePodName, base.name+"-") ||
		!strings.HasPrefix(req.PeerPodName, base.name+"-") || req.PeerPodName == req.SourcePodName ||
		req.SourcePodUID != base.sourcePodUID || req.PeerPodUID != base.peerPodUID ||
		req.DeploymentUID != base.deploymentUID || req.ReplicaSetUID != base.replicaSetUID ||
		req.ServiceUID != base.created["services"] || req.PDBUID != base.created["poddisruptionbudgets"] ||
		req.PolicyUID != base.created["phorvexpolicies"] || req.PodMonitorUID != base.created["podmonitors"] ||
		req.PolicyGeneration < 1 || !mongoSHA.MatchString(req.PolicySpecSHA256) ||
		!mongoSHA.MatchString(req.ProfileSHA256) || !mongoSHA.MatchString(req.MetricQuerySHA256) ||
		req.ManagerPodUID == "" || req.ManagerContainerID == "" || req.ManagerImageID == "" ||
		req.SourceCaptureID == "" || req.PeerCaptureID == "" ||
		req.SourceBeforeHTTP != 200 || req.PeerBeforeHTTP != 200 || req.ServiceBeforeHTTP != 200 ||
		req.MetricStatus != "MEASURED_FRESH" || req.MetricSourcePodName != req.SourcePodName ||
		!podBoundCPURequestTimeValid(req, requested) {
		return proof, errors.New("CPU token post-request identity or chronology differs")
	}
	first, e1 := time.Parse(time.RFC3339Nano, req.MetricFirstAt)
	second, e2 := time.Parse(time.RFC3339Nano, req.MetricSecondAt)
	if e1 != nil || e2 != nil || !first.After(base.lastCreateAt) || second.Sub(first) < 15*time.Second ||
		second.After(requested) || requested.Sub(second) > 90*time.Second ||
		req.MetricFirstValue < 0 || req.MetricSecondValue <= req.MetricFirstValue {
		return proof, errors.New("CPU token post-request measured source differs")
	}
	var auditStart podBoundTokenAuditStart
	auditRaw, err := readPodBoundJSON(out, "pod-bound-token-audit-start.json", &auditStart)
	if err != nil || auditStart.Schema != "pod-bound-token-audit-start-v1" ||
		auditStart.RunID != prior.ID || auditStart.Nonce != base.nonce ||
		auditStart.RequestSHA256 != podBoundHash(reqRaw) ||
		auditStart.Segment.ID != "live" || auditStart.Segment.Generation == "" ||
		auditStart.Segment.Anchor == "" || auditStart.Segment.Size < 0 ||
		auditStart.Offset != auditStart.Segment.Size ||
		strings.TrimSpace(auditStart.SourceIdentity) == "" {
		return proof, errors.New("CPU token post-request authenticated audit start differs")
	}
	baseStatus := fmt.Sprintf("Pod-bound token early unsafe receipt: %d created UIDs, cleanup CONFIRMED_ABSENT; exact reconciliation required", len(base.created))
	if _, err := os.Lstat(filepath.Join(out, podBoundCoordinatorFailureFile)); errors.Is(err, os.ErrNotExist) {
		if prior.Error != baseStatus {
			return proof, errors.New("CPU token post-request historical status differs")
		}
	} else if err != nil {
		return proof, errors.New("CPU token post-request coordinator diagnostic ambiguous")
	} else {
		failureRaw, readErr := readNATSResponseSizedFile(out, podBoundCoordinatorFailureFile, 256<<10)
		if readErr != nil || rejectAmbiguousMongoJSON(failureRaw) != nil {
			return proof, errors.New("CPU token post-request coordinator diagnostic JSON ambiguous")
		}
		failure, err := readPodBoundCoordinatorFailure(out, prior.ID)
		if err != nil || failure.RequestSHA256 != podBoundHash(reqRaw) ||
			prior.Error != baseStatus+podBoundCoordinatorStatus(out, prior.ID, nil) {
			return proof, errors.New("CPU token post-request coordinator diagnostic differs")
		}
		switch failure.Stage {
		case "post-audit-authorization", "post-audit-source", "post-audit-source-manifest",
			"post-audit-disjointness", "signal-intent", "typed-event-create", "decision-observation":
		default:
			return proof, errors.New("CPU token post-request coordinator stage passed the accepted boundary")
		}
	}
	proof = cpuCleanupProof{cpuPreEventProof: base, clusterUID: req.ClusterUID,
		requestSHA256: podBoundHash(reqRaw), auditStartSHA256: podBoundHash(auditRaw),
		peerPodName: req.PeerPodName, postRequest: true}
	return proof, nil
}

// Caller holds rm.mu. Every unsafe CPU predecessor must prove its own exact
// phase and scope. A request selects the post-request branch; malformed or
// contradictory files cannot fall back to the pre-event branch.
func (rm *RunManager) cpuCleanupProofsLocked(expectedTarget string) ([]cpuCleanupProof, error) {
	if rm == nil || rm.runs == nil || rm.loadErr != nil || expectedTarget == "" || expectedTarget == defaultTargetID {
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
	proofs := make([]cpuCleanupProof, 0, len(priors))
	for _, prior := range priors {
		out := rm.cfg.runOutputPath(prior.ID)
		if rm.procs[prior.ID] != nil || rm.stopping[prior.ID] ||
			strings.Contains(prior.Error, "reconciliation pending") ||
			!cataloguev1.ExecutionLockAvailable(out) {
			return nil, errors.New("CPU token unsafe predecessor remains active or unresolved")
		}
		_, err := os.Lstat(filepath.Join(out, podBoundRequestFile))
		if errors.Is(err, os.ErrNotExist) {
			base, err := cpuPreEventProofAt(prior, out, expectedTarget)
			if err != nil {
				return nil, err
			}
			proofs = append(proofs, cpuCleanupProof{cpuPreEventProof: base})
		} else if err == nil {
			proof, err := cpuPostRequestCleanupProofAt(prior, out, expectedTarget)
			if err != nil {
				return nil, err
			}
			proofs = append(proofs, proof)
		} else {
			return nil, errors.New("CPU token predecessor request path ambiguous")
		}
	}
	return proofs, nil
}
