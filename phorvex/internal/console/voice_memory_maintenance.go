package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type voiceMemoryMaintenance struct {
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Time          time.Time `json:"time"`
	Receipt       string    `json:"receipt"`
	Operation     string    `json:"operation"`
	Namespace     string    `json:"namespace"`
	Policy        string    `json:"policy"`
	PolicyUID     string    `json:"policyUID"`
	TargetName    string    `json:"targetName"`
	TargetUID     string    `json:"targetUID"`
	Outcome       string    `json:"outcome"`
	Effect        string    `json:"effect"`
	Error         string    `json:"error"`
}

func voiceMemoryOperationID(policyUID, deploymentUID, eventUID, tickID, decisionID string) string {
	sum := sha256.Sum256([]byte("phorvex-voice-memory-v1\x00" + policyUID + "\x00" + deploymentUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(sum[:])
}

func voiceMemoryJournalName(deploymentUID string, revision uint64) string {
	sum := sha256.Sum256([]byte(deploymentUID))
	return "phorvex-voice-memory-" + hex.EncodeToString(sum[:16]) + "-" + strconv.FormatUint(revision, 10)
}

func voiceMemoryMaintenanceMatches(row voiceMemoryMaintenance, record *attackRecord, snap voiceMemorySnapshot, selected voiceMemoryDecision) bool {
	end, err := time.Parse(time.RFC3339Nano, record.ObservationEnd)
	if err != nil || selected.SelectedAt.IsZero() || !selected.Selected || selected.DecisionID == "" || selected.TickID == "" {
		return false
	}
	return row.SchemaVersion == audit.SchemaVersionCurrent && row.Kind == "phorvex.maintenance" &&
		row.Operation == string(model.ActionVoiceMemoryNoteRevoke) &&
		row.Receipt == voiceMemoryJournalName(snap.DeploymentUID, snap.Rule.Revision+1) &&
		row.Namespace == "voice" && row.Policy == voiceMemoryPolicyName && row.PolicyUID == snap.PolicyUID &&
		row.TargetName == record.Pod && row.TargetUID == record.TargetUID && row.Outcome == "confirmed" && row.Error == "" &&
		(row.Effect == "Voice memory rule confirmed on current serving Pods" || row.Effect == "previously confirmed per-Pod Voice memory rule") &&
		!row.Time.Before(selected.SelectedAt) && !row.Time.After(end)
}

func (s *Server) voiceMemoryRecoveryConfirmed(ctx context.Context, record *attackRecord, snap voiceMemorySnapshot,
	selected voiceMemoryDecision) (bool, error) {
	rows, err := s.readVoiceMemoryMaintenanceWindow(ctx)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if voiceMemoryMaintenanceMatches(row, record, snap, selected) {
			return true, nil
		}
	}
	return false, nil
}

// Read the same authenticated audit source as decisions, with the same size,
// generation, and immutable-range checks. Maintenance is a distinct wire kind.
func (s *Server) readVoiceMemoryMaintenanceWindow(ctx context.Context) ([]voiceMemoryMaintenance, error) {
	path := s.cfg.auditPathForContext("")
	f, err := openDecisionSource(ctx, path, s.cfg.AuditSource)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	generation, err := auditGeneration(f)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = int64(16 << 20)
	start := max(int64(0), stat.Size()-window)
	startAnchor, err := auditAnchor(f, start)
	if err != nil {
		return nil, err
	}
	endAnchor, err := auditAnchor(f, stat.Size())
	if err != nil {
		return nil, err
	}
	raw := make([]byte, stat.Size()-start)
	if len(raw) > 0 {
		if _, err := f.ReadAt(raw, start); err != nil {
			return nil, err
		}
	}
	if remote, ok := f.(interface{ Verify() error }); ok {
		if err := remote.Verify(); err != nil {
			return nil, err
		}
	} else {
		capturedHash := sha256.Sum256(raw)
		verify, openErr := openDecisionSource(ctx, path, s.cfg.AuditSource)
		if openErr != nil {
			return nil, errAuditChanged
		}
		defer verify.Close()
		verifyGeneration, verifyErr := auditGeneration(verify)
		if verifyErr != nil || verifyGeneration != generation {
			return nil, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(verify, start); anchorErr != nil || anchor != startAnchor {
			return nil, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(verify, stat.Size()); anchorErr != nil || anchor != endAnchor {
			return nil, errAuditChanged
		}
		verifiedHash, hashErr := auditRangeHash(verify, uint64(start), uint64(len(raw)))
		if hashErr != nil || verifiedHash != capturedHash {
			return nil, errAuditChanged
		}
	}
	if start > 0 {
		if offset := bytes.IndexByte(raw, '\n'); offset >= 0 {
			raw = raw[offset+1:]
		} else {
			return nil, nil
		}
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		if offset := bytes.LastIndexByte(raw, '\n'); offset >= 0 {
			raw = raw[:offset+1]
		} else {
			return nil, nil
		}
	}
	rows := make([]voiceMemoryMaintenance, 0, 8)
	for len(raw) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		offset := bytes.IndexByte(raw, '\n')
		if offset < 0 {
			return nil, errors.New("Voice maintenance audit has an incomplete line")
		}
		line := raw[:offset]
		raw = raw[offset+1:]
		if len(line) == 0 || len(line) > liveRecordBytes {
			continue
		}
		var row voiceMemoryMaintenance
		if json.Unmarshal(line, &row) == nil && row.Kind == "phorvex.maintenance" {
			rows = append(rows, row)
			if len(rows) > 256 {
				return nil, fmt.Errorf("Voice maintenance window exceeded bound")
			}
		}
	}
	return rows, nil
}
