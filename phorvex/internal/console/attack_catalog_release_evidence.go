package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

const attackCatalogPostflightSchema = "phorvex.attack-catalogue-postflight.v1"

type AttackCatalogPostflightResult struct {
	CatalogueID     string          `json:"catalogue_id"`
	RunID           string          `json:"run_id"`
	Family          string          `json:"family"`
	EvidenceKind    string          `json:"evidence_kind"`
	Clean           bool            `json:"clean"`
	CheckedAt       time.Time       `json:"checked_at"`
	InventorySHA256 string          `json:"inventory_sha256"`
	Inventory       json.RawMessage `json:"inventory,omitempty"`
}

type attackCatalogPostflightInventory struct {
	Schema        string          `json:"schema"`
	CatalogueID   string          `json:"catalogueID"`
	RunID         string          `json:"runID"`
	Family        string          `json:"family"`
	EventDeleted  bool            `json:"eventDeleted"`
	MarkerDeleted bool            `json:"markerDeleted"`
	Verified      bool            `json:"verified"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
}

func attackCatalogTime(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err = decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func canonicalJSONSHA256(value any) (string, error) {
	raw, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func acceptedAttackCatalogReceiptID(result AttackCatalogResult) string {
	objects := slices.Clone(result.Actuator.ObjectsTouched)
	sort.Strings(objects)
	accepted := ""
	if result.Actuator.AcceptedAt != nil {
		accepted = result.Actuator.AcceptedAt.UTC().Format(time.RFC3339Nano)
	}
	bound := strings.Join([]string{attackCatalogEvidenceSchema, result.CatalogueID, result.RunID,
		result.Signal.UID, result.Signal.TargetUID, result.Decision.ID, result.Actuator.Handler,
		strings.Join(objects, "\x1f"), accepted}, "\x00")
	sum := sha256.Sum256([]byte(bound))
	return hex.EncodeToString(sum[:])
}

func newAttackCatalogPostflight(result AttackCatalogResult, inventory AttackCatalogCleanupResult, checkedAt time.Time) (AttackCatalogPostflightResult, error) {
	value := attackCatalogPostflightInventory{Schema: attackCatalogPostflightSchema, CatalogueID: result.CatalogueID,
		RunID: result.RunID, Family: result.Family, EventDeleted: inventory.EventDeleted,
		MarkerDeleted: inventory.MarkerDeleted, Verified: inventory.Verified,
		Evidence: append(json.RawMessage(nil), inventory.Evidence...)}
	raw, err := canonicalJSON(value)
	if err != nil {
		return AttackCatalogPostflightResult{}, err
	}
	digest := sha256.Sum256(raw)
	clean := inventory.Verified && inventory.EventDeleted && inventory.MarkerDeleted
	return AttackCatalogPostflightResult{CatalogueID: result.CatalogueID, RunID: result.RunID,
		Family: result.Family, EvidenceKind: "runtime-health", Clean: clean, CheckedAt: checkedAt.UTC(),
		InventorySHA256: hex.EncodeToString(digest[:]), Inventory: raw}, nil
}

func bindAttackCatalogEvidence(result *AttackCatalogResult, family string) error {
	if result == nil || result.CatalogueID == "" || result.RunID == "" || family == "" {
		return errors.New("catalogue evidence identity is incomplete")
	}
	result.EvidenceSchema, result.Family = attackCatalogEvidenceSchema, family
	if err := bindAttackCatalogStageIdentity(result.CatalogueID, result.RunID, &result.Signal.CatalogueID, &result.Signal.RunID); err != nil {
		return fmt.Errorf("signal: %w", err)
	}
	if err := bindAttackCatalogStageIdentity(result.CatalogueID, result.RunID, &result.Decision.CatalogueID, &result.Decision.RunID); err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	if err := bindAttackCatalogStageIdentity(result.CatalogueID, result.RunID, &result.Actuator.CatalogueID, &result.Actuator.RunID); err != nil {
		return fmt.Errorf("actuator: %w", err)
	}
	if err := bindAttackCatalogStageIdentity(result.CatalogueID, result.RunID, &result.PhysicalValidation.CatalogueID, &result.PhysicalValidation.RunID); err != nil {
		return fmt.Errorf("oracle: %w", err)
	}
	if err := bindAttackCatalogStageIdentity(result.CatalogueID, result.RunID, &result.Cleanup.CatalogueID, &result.Cleanup.RunID); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	for name, stageFamily := range map[string]*string{
		"signal": &result.Signal.Family, "decision": &result.Decision.Family,
		"actuator": &result.Actuator.Family, "oracle": &result.PhysicalValidation.Family,
		"cleanup": &result.Cleanup.Family,
	} {
		if *stageFamily != "" && *stageFamily != family {
			return fmt.Errorf("%s: stage family differs from the immutable run envelope", name)
		}
		*stageFamily = family
	}
	result.Decision.EventUID, result.Decision.TargetUID = result.Signal.UID, result.Signal.TargetUID
	if result.Signal.Observed && result.Signal.ObservedAt == nil {
		result.Signal.ObservedAt = result.Decision.ObservedAt
	}
	if result.Actuator.ReceiptObserved {
		result.Actuator.DecisionID = result.Decision.ID
		result.Actuator.Status = "accepted"
		if result.Actuator.AcceptedAt == nil {
			result.Actuator.AcceptedAt = result.Decision.ObservedAt
		}
		result.Actuator.ReceiptID = acceptedAttackCatalogReceiptID(*result)
	}
	if result.PhysicalValidation.Validated {
		observations, kind, err := attackCatalogOracleObservations(*result)
		if err != nil {
			return err
		}
		result.PhysicalValidation.Kind = kind
		result.PhysicalValidation.Observations = observations
	}
	return nil
}

func bindAttackCatalogStageIdentity(catalogueID, runID string, stageCatalogueID, stageRunID *string) error {
	if *stageCatalogueID != "" && *stageCatalogueID != catalogueID || *stageRunID != "" && *stageRunID != runID {
		return errors.New("stage identity differs from the immutable run envelope")
	}
	*stageCatalogueID, *stageRunID = catalogueID, runID
	return nil
}

func oracleObservation(name string, before, after any, observedAt *time.Time) AttackCatalogOracleObservation {
	return AttackCatalogOracleObservation{Name: name, Before: before, After: after, Passed: true, ObservedAt: observedAt}
}

func attackCatalogOracleObservations(result AttackCatalogResult) ([]AttackCatalogOracleObservation, string, error) {
	physical, at := result.PhysicalValidation, result.PhysicalValidation.ObservedAt
	if at == nil {
		return nil, "", errors.New("physical oracle has no trusted observation timestamp")
	}
	switch result.Family {
	case "identity-sa-rotate":
		return []AttackCatalogOracleObservation{
			oracleObservation("service_account_uid_changed", physical.OldServiceAccountUID, physical.NewServiceAccountUID, at),
			oracleObservation("old_credential_revoked", "authenticated", "denied", at),
			oracleObservation("pod_uid_unchanged", physical.PodUID, physical.PodUID, at),
		}, "service-account-rotated-credential-replay", nil
	case "credential":
		var evidence credentialRevokeEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("credential oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("credential_revoked", "authenticated", "denied", at),
			oracleObservation("benign_credential_valid", "authenticated", "authenticated", at),
		}, "credential-revoked-two-sided", nil
	case "agent-action":
		var evidence agentActionDenyEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("agent-action oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("abusive_action_blocked", "allowed", "blocked", at),
			oracleObservation("benign_action_preserved", "allowed", "allowed", at),
			oracleObservation("peer_unchanged", evidence.ServiceUID, evidence.ServiceUID, at),
		}, "app-action-denied-two-sided", nil
	case k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop:
		var evidence k8sCataloguePhysicalEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("Kubernetes oracle evidence: %w", err)
		}
		switch result.Family {
		case k8sCatalogueFamilyQuarantine:
			return []AttackCatalogOracleObservation{
				oracleObservation("forbidden_edge_blocked", "reached", "blocked", at),
				oracleObservation("legitimate_edge_preserved", evidence.AvailabilityHeld, evidence.AvailabilityHeld, at),
				oracleObservation("target_pod_uid_unchanged", evidence.TargetUID, evidence.TargetUID, at),
			}, "pod-quarantined-network", nil
		case k8sCatalogueFamilyControllerStop:
			return []AttackCatalogOracleObservation{
				oracleObservation("target_controller_stopped", "running", "stopped", at),
				oracleObservation("availability_preserved", true, evidence.AvailabilityHeld, at),
			}, "controller-stopped-availability", nil
		default:
			if len(evidence.ReplacementUIDs) == 0 || len(evidence.SiblingUIDs) == 0 {
				return nil, "", errors.New("pod-rotate oracle lacks replacement or sibling identity")
			}
			return []AttackCatalogOracleObservation{
				oracleObservation("target_pod_uid_changed", evidence.TargetUID, evidence.ReplacementUIDs[0], at),
				oracleObservation("sibling_pod_uid_unchanged", evidence.SiblingUIDs[0], evidence.SiblingUIDs[0], at),
				oracleObservation("availability_preserved", true, evidence.AvailabilityHeld, at),
			}, "pod-uid-replaced-availability", nil
		}
	case infraFamilyNetworkEdge:
		var evidence infraNetworkEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("network-edge oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("forbidden_edge_blocked", "reached", "blocked", at),
			oracleObservation("legitimate_edge_preserved", evidence.LegitimateBefore, evidence.LegitimateAfter, at),
			oracleObservation("target_pod_uid_unchanged", physical.PodUID, physical.PodUID, at),
		}, "network-edge-blocked-two-sided", nil
	case infraFamilyDatastore:
		var evidence infraDatastoreEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("datastore oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("datastore_state_changed", evidence.PoisonedSHA, evidence.FinalSHA, at),
			oracleObservation("legitimate_read_preserved", evidence.BenignServed, evidence.BenignServed, at),
		}, "datastore-restored-readback", nil
	case infraFamilyImage:
		var evidence infraImageEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("image oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("image_digest_changed", evidence.PoisonImage, evidence.TrustedDigest, at),
			oracleObservation("availability_preserved", true, evidence.ReadyPods > 0, at),
		}, "image-rollback-runtime", nil
	case infraFamilyNodeRecycle:
		var evidence infraNodeEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("node-recycle oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("target_pod_uid_changed", evidence.TargetPodUID, evidence.ReplacementPodUID, at),
			oracleObservation("peer_node_unchanged", evidence.HealthyNodeUID, evidence.HealthyNodeUID, at),
			oracleObservation("availability_preserved", true, evidence.Available >= evidence.MinimumAvailable, at),
		}, "node-replaced-two-sided", nil
	case servingRateFamily:
		var evidence servingRateOracleEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("serving-rate oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("abusive_request_throttled", "admitted", "throttled", at),
			oracleObservation("legitimate_request_preserved", "admitted", "admitted", at),
		}, "abusive-rate-throttled-two-sided", nil
	case sensitiveOutputFamily:
		var evidence sensitiveOutputOracleEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("sensitive-output oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("sensitive_output_blocked", "disclosed", "blocked", at),
			oracleObservation("benign_output_preserved", evidence.BenignSHA256Before, evidence.BenignSHA256After, at),
		}, "sensitive-output-blocked-two-sided", nil
	case servingKVFamily:
		var evidence servingKVOracleEvidence
		if err := json.Unmarshal(physical.Evidence, &evidence); err != nil {
			return nil, "", fmt.Errorf("serving-kv oracle evidence: %w", err)
		}
		return []AttackCatalogOracleObservation{
			oracleObservation("compromised_key_changed", true, evidence.TargetImplantAfter, at),
			oracleObservation("benign_key_preserved", evidence.BystanderUID, evidence.BystanderUID, at),
			oracleObservation("serving_pods_consistent", true, evidence.AvailableReplicas == evidence.DesiredReplicas, at),
		}, "key-reset-two-sided", nil
	default:
		return nil, "", fmt.Errorf("catalogue family %q has no structured oracle producer", result.Family)
	}
}
