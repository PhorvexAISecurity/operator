package currentinventory

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const MaxRecords = 4096

type Result struct {
	Records []model.AdmittedCurrentInventory
	Status  string
	Gaps    []string
}

type Ledger interface {
	ContainsExact(policyUID, evidenceID, payloadDigest, eventUID string) bool
	Put(model.AdmittedCurrentInventory) error
	Query(policyUID, ownerUID string, now time.Time) Result
}

type stored struct {
	record    model.AdmittedCurrentInventory
	canonical []byte
}

type scopedGap struct {
	reason     string
	validUntil time.Time
}

type Store struct {
	mu        sync.Mutex
	byID      map[string]stored
	byOwner   map[string][]string
	gaps      map[string][]scopedGap
	watermark time.Time
	max       int
}

func NewStore() *Store {
	return &Store{byID: map[string]stored{}, byOwner: map[string][]string{}, gaps: map[string][]scopedGap{}, max: MaxRecords}
}
func idKey(policyUID, evidenceID string) string  { return policyUID + "\x00" + evidenceID }
func ownerKey(policyUID, ownerUID string) string { return policyUID + "\x00" + ownerUID }

func (s *Store) ContainsExact(policyUID, evidenceID, payloadDigest, eventUID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[idKey(policyUID, evidenceID)]
	return ok && s.watermark.Before(x.record.Inventory.Observation.ValidUntil) && x.record.CanonicalPayloadSHA256 == payloadDigest && x.record.SecurityEvent.UID == eventUID
}

func (s *Store) advance(now time.Time) {
	if now.After(s.watermark) {
		s.watermark = now
	}
	removed := false
	for key, value := range s.byID {
		if !s.watermark.Before(value.record.Inventory.Observation.ValidUntil) {
			delete(s.byID, key)
			removed = true
		}
	}
	if removed {
		s.byOwner = make(map[string][]string)
		for key, value := range s.byID {
			owner := ownerKey(value.record.Inventory.PolicyEpoch.UID, value.record.Inventory.StableWorkloadOwner.UID)
			s.byOwner[owner] = append(s.byOwner[owner], key)
		}
	}
	for owner, gaps := range s.gaps {
		kept := gaps[:0]
		for _, gap := range gaps {
			if s.watermark.Before(gap.validUntil) {
				kept = append(kept, gap)
			}
		}
		if len(kept) == 0 {
			delete(s.gaps, owner)
		} else {
			s.gaps[owner] = kept
		}
	}
}

func (s *Store) addGap(owner, reason string, validUntil time.Time) {
	for i := range s.gaps[owner] {
		if s.gaps[owner][i].reason == reason {
			if validUntil.After(s.gaps[owner][i].validUntil) {
				s.gaps[owner][i].validUntil = validUntil
			}
			return
		}
	}
	s.gaps[owner] = append(s.gaps[owner], scopedGap{reason: reason, validUntil: validUntil})
}

func (s *Store) Put(r model.AdmittedCurrentInventory) error {
	if r.SchemaVersion != model.AdmittedCurrentInventorySchemaV1 || r.SecurityEvent.Name == "" || r.SecurityEvent.UID == "" || r.SecurityEvent.CreationTimestamp.IsZero() || r.AuthenticatedCreator == "" || r.AuthenticatedCreator != r.Inventory.Classification.ObserverIdentity || r.AdmissionTime.IsZero() || r.IngestedAt.IsZero() || r.TrustBoundary.ConfigurationUID == "" || r.TrustBoundary.ConfigurationResourceVersion == "" || r.TrustBoundary.ActivationTime.IsZero() || r.TrustBoundary.ContractVersion != BoundaryContract || r.AdmissionTime.Before(r.SecurityEvent.CreationTimestamp) || !r.IngestedAt.Before(r.Inventory.Observation.ValidUntil) {
		return errors.New("incomplete admitted current inventory")
	}
	raw, digest, err := Marshal(r.Inventory)
	if err != nil || digest != r.CanonicalPayloadSHA256 {
		return errors.New("admitted current inventory digest mismatch")
	}
	key := idKey(r.Inventory.PolicyEpoch.UID, r.Inventory.EvidenceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(r.IngestedAt)
	owner := ownerKey(r.Inventory.PolicyEpoch.UID, r.Inventory.StableWorkloadOwner.UID)
	if !s.watermark.Before(r.Inventory.Observation.ValidUntil) {
		return errors.New("current inventory observation already expired")
	}
	if old, ok := s.byID[key]; ok {
		if bytes.Equal(old.canonical, []byte(raw)) && old.record.SecurityEvent.UID == r.SecurityEvent.UID {
			return nil
		}
		s.addGap(owner, "current-inventory-conflict", r.Inventory.Observation.ValidUntil)
		oldOwner := ownerKey(old.record.Inventory.PolicyEpoch.UID, old.record.Inventory.StableWorkloadOwner.UID)
		s.addGap(oldOwner, "current-inventory-conflict", old.record.Inventory.Observation.ValidUntil)
		return errors.New("conflicting current inventory evidence")
	}
	if len(s.byID) >= s.max {
		s.addGap(owner, "current-inventory-capacity-exhausted", r.Inventory.Observation.ValidUntil)
		return errors.New("current inventory capacity exhausted")
	}
	s.byID[key] = stored{record: r, canonical: []byte(raw)}
	s.byOwner[owner] = append(s.byOwner[owner], key)
	return nil
}

func (s *Store) Query(policyUID, ownerUID string, now time.Time) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(now)
	owner := ownerKey(policyUID, ownerUID)
	out := Result{Status: "available"}
	for _, gap := range s.gaps[owner] {
		out.Gaps = append(out.Gaps, gap.reason)
	}
	if len(out.Gaps) > 0 {
		out.Status = "partial"
	}
	for _, key := range s.byOwner[owner] {
		r := s.byID[key].record
		out.Records = append(out.Records, r)
	}
	sort.Slice(out.Records, func(i, j int) bool { return out.Records[i].Inventory.EvidenceID < out.Records[j].Inventory.EvidenceID })
	return out
}
