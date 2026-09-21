// Package losshistory retains immutable admitted completed-disclosure records.
package losshistory

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	MaxRecords       = 4096
	MaxRecordBytes   = 64 << 10
	incompleteMarker = ".history-incomplete"
)

type Result struct {
	Records []model.AdmittedLossV1
	Status  string
	Gaps    []string
}

type stored struct {
	record model.AdmittedLossV1
	raw    []byte
}

type Store struct {
	root     string
	max      int
	mu       sync.RWMutex
	byID     map[string]stored
	byOwner  map[string][]string
	gaps     []string
	full     bool
	writeAll func(io.Writer, []byte) error
}

func (s *Store) addGap(gap string) {
	for _, prior := range s.gaps {
		if prior == gap {
			return
		}
	}
	s.gaps = append(s.gaps, gap)
}

// latchGap records that this store can no longer claim complete history. The
// marker is monotonic: successful later writes cannot prove that the missing
// record was recovered, so restart must preserve the partial verdict.
func (s *Store) latchGap(gap string) {
	s.addGap(gap)
	if err := validateDir(s.root); err != nil {
		s.addGap("history-incomplete-marker-unavailable")
		return
	}
	path := filepath.Join(s.root, incompleteMarker)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		_, writeErr := f.Write([]byte("retention-incomplete\n"))
		err = errors.Join(writeErr, f.Sync(), f.Close())
	} else if errors.Is(err, os.ErrExist) {
		return
	}
	if err != nil {
		s.addGap("history-incomplete-marker-unavailable")
		if f != nil {
			_ = f.Close()
		}
		return
	}
	if dir, openErr := os.Open(s.root); openErr == nil {
		if syncErr := errors.Join(dir.Sync(), dir.Close()); syncErr != nil {
			s.addGap("history-incomplete-marker-unavailable")
		}
	} else {
		s.addGap("history-incomplete-marker-unavailable")
	}
}

func (s *Store) retentionError(gap string, err error) error {
	s.latchGap(gap)
	return err
}

func validateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || perm&0007 != 0 || (perm&0700 != 0700 && perm&0070 != 0070) {
		return errors.New("loss history root must be a private regular directory")
	}
	return nil
}

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("loss history root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	if err := validateDir(abs); err != nil {
		return nil, err
	}
	s := &Store{root: abs, max: MaxRecords, byID: map[string]stored{}, byOwner: map[string][]string{}, writeAll: writeBytes}
	s.scan()
	return s, nil
}

func writeBytes(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func idKey(policyUID, evidenceID string) string  { return policyUID + "\x00" + evidenceID }
func ownerKey(policyUID, ownerUID string) string { return policyUID + "\x00" + ownerUID }

func fileName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".json"
}

func canonicalRecord(r model.AdmittedLossV1) ([]byte, error) {
	if r.SchemaVersion != model.AdmittedLossSchemaV1 {
		return nil, errors.New("unsupported admitted loss schema")
	}
	if err := disclosure.Validate(r.Disclosure); err != nil {
		return nil, err
	}
	_, payload, digest, err := disclosure.Parse(mustPayload(r.Disclosure))
	if err != nil || digest != r.CanonicalPayloadSHA256 || len(payload) == 0 {
		return nil, errors.New("admitted payload digest mismatch")
	}
	if r.SecurityEvent.Name == "" || r.SecurityEvent.UID == "" || r.SecurityEvent.CreationTimestamp.IsZero() ||
		r.AuthenticatedCreator == "" || r.TrustBoundary.ConfigurationUID == "" ||
		r.TrustBoundary.ConfigurationResourceVersion == "" || r.TrustBoundary.ActivationTime.IsZero() ||
		r.TrustBoundary.ContractVersion != disclosure.BoundaryContract || r.IngestedAt.IsZero() {
		return nil, errors.New("incomplete admitted authority")
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) == 0 || len(b) > MaxRecordBytes {
		return nil, errors.New("admitted loss exceeds record bound")
	}
	return b, nil
}

func mustPayload(p model.CompletedDisclosureV1) string {
	b, _ := json.Marshal(p)
	return string(b)
}

func openRecord(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > MaxRecordBytes {
		_ = f.Close()
		return nil, errors.New("loss history entry is not a bounded private regular file")
	}
	return f, nil
}

func readRecord(path string) ([]byte, error) {
	f, err := openRecord(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	if err != nil || len(b) == 0 || len(b) > MaxRecordBytes {
		return nil, errors.New("loss history entry unreadable or oversized")
	}
	return b, nil
}

func (s *Store) add(r model.AdmittedLossV1, raw []byte) error {
	key := idKey(r.Disclosure.PolicyEpoch.UID, r.Disclosure.EvidenceID)
	if prior, ok := s.byID[key]; ok {
		if bytes.Equal(prior.raw, raw) {
			return nil
		}
		return errors.New("conflicting completed-disclosure evidence ID")
	}
	s.byID[key] = stored{record: r, raw: append([]byte(nil), raw...)}
	okey := ownerKey(r.Disclosure.PolicyEpoch.UID, r.Disclosure.StableWorkloadOwner.UID)
	s.byOwner[okey] = append(s.byOwner[okey], key)
	return nil
}

func (s *Store) scan() {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		s.addGap("history-root-unreadable")
		return
	}
	for _, entry := range entries {
		if entry.Name() == incompleteMarker {
			info, statErr := entry.Info()
			if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				s.addGap("history-incomplete-marker-invalid")
			} else {
				s.addGap("history-retention-incomplete")
			}
			continue
		}
		if len(s.byID) >= s.max {
			s.full = true
			s.addGap("history-capacity-exhausted")
			break
		}
		name := entry.Name()
		if len(name) != sha256.Size*2+len(".json") || !strings.HasSuffix(name, ".json") {
			s.addGap("history-unrecognized-entry")
			continue
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(name, ".json")); err != nil {
			s.addGap("history-invalid-entry-name")
			continue
		}
		raw, err := readRecord(filepath.Join(s.root, name))
		if err != nil {
			s.addGap("history-entry-unreadable")
			continue
		}
		var r model.AdmittedLossV1
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			s.addGap("history-entry-invalid")
			continue
		}
		canonical, err := canonicalRecord(r)
		key := idKey(r.Disclosure.PolicyEpoch.UID, r.Disclosure.EvidenceID)
		if err != nil || !bytes.Equal(raw, canonical) || fileName(key) != name {
			s.addGap("history-entry-tampered")
			continue
		}
		if err := s.add(r, raw); err != nil {
			s.addGap("history-evidence-conflict")
		}
	}
}

// ContainsExact recognizes an acknowledgement-lost retry without re-resolving
// an original Pod that may already have been replaced.
func (s *Store) ContainsExact(policyUID, evidenceID, payloadDigest, eventUID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := idKey(policyUID, evidenceID)
	r, ok := s.byID[key]
	if !ok || r.record.CanonicalPayloadSHA256 != payloadDigest || r.record.SecurityEvent.UID != eventUID {
		return false
	}
	raw, err := readRecord(filepath.Join(s.root, fileName(key)))
	if err != nil || !bytes.Equal(raw, r.raw) {
		s.addGap("history-entry-changed-after-load")
		return false
	}
	return true
}

func (s *Store) Put(r model.AdmittedLossV1) error {
	if s == nil {
		return errors.New("loss history unavailable")
	}
	raw, err := canonicalRecord(r)
	if err != nil {
		return err
	}
	key := idKey(r.Disclosure.PolicyEpoch.UID, r.Disclosure.EvidenceID)
	path := filepath.Join(s.root, fileName(key))
	if filepath.Dir(path) != s.root {
		return errors.New("loss history path escaped root")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateDir(s.root); err != nil {
		return s.retentionError("history-root-unavailable", err)
	}
	if prior, ok := s.byID[key]; ok {
		if prior.record.CanonicalPayloadSHA256 == r.CanonicalPayloadSHA256 && prior.record.SecurityEvent.UID == r.SecurityEvent.UID {
			disk, readErr := readRecord(path)
			if readErr == nil && bytes.Equal(disk, prior.raw) {
				return nil
			}
			s.addGap("history-entry-changed-after-load")
			return errors.New("loss history acknowledgement retry found changed durable evidence")
		}
		return errors.New("conflicting completed-disclosure evidence ID")
	}
	if len(s.byID) >= s.max {
		s.full = true
		return s.retentionError("history-capacity-exhausted", errors.New("loss history capacity exhausted"))
	}
	if prior, readErr := readRecord(path); readErr == nil {
		var existing model.AdmittedLossV1
		var existingCanonical []byte
		var validationErr error
		if decodeErr := json.Unmarshal(prior, &existing); decodeErr == nil {
			existingCanonical, validationErr = canonicalRecord(existing)
		} else {
			validationErr = decodeErr
		}
		if validationErr == nil && bytes.Equal(prior, existingCanonical) && existing.CanonicalPayloadSHA256 == r.CanonicalPayloadSHA256 && existing.SecurityEvent.UID == r.SecurityEvent.UID {
			return s.add(existing, prior)
		}
		return s.retentionError("history-entry-collision-or-tamper", errors.New("loss history collision or on-disk tamper"))
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return s.retentionError("history-entry-unreadable", readErr)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	tmp := filepath.Join(s.root, "."+fileName(key)+"."+hex.EncodeToString(random)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := s.writeAll(f, raw); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	if err := f.Sync(); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	if err := f.Close(); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			prior, readErr := readRecord(path)
			if readErr == nil {
				var existing model.AdmittedLossV1
				var existingCanonical []byte
				var decodeErr error
				if err := json.Unmarshal(prior, &existing); err == nil {
					existingCanonical, decodeErr = canonicalRecord(existing)
				} else {
					decodeErr = err
				}
				if decodeErr == nil && bytes.Equal(prior, existingCanonical) && existing.CanonicalPayloadSHA256 == r.CanonicalPayloadSHA256 && existing.SecurityEvent.UID == r.SecurityEvent.UID {
					_ = os.Remove(tmp)
					committed = true
					return s.add(existing, prior)
				}
			}
		}
		return s.retentionError("history-retention-failed", err)
	}
	if err := os.Remove(tmp); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	committed = true
	dir, err := os.Open(s.root)
	if err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return s.retentionError("history-retention-failed", err)
	}
	return s.add(r, raw)
}

func (s *Store) Query(policyUID, ownerUID string) Result {
	if s == nil {
		return Result{Status: "unavailable", Gaps: []string{"retained-loss-history-source-unavailable"}}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Result{Status: "available", Gaps: append([]string(nil), s.gaps...)}
	if err := validateDir(s.root); err != nil {
		result.Status = "unavailable"
		result.Gaps = append(result.Gaps, "history-root-unavailable")
		return result
	}
	if s.full || len(result.Gaps) > 0 {
		result.Status = "partial"
	}
	for _, key := range s.byOwner[ownerKey(policyUID, ownerUID)] {
		entry := s.byID[key]
		raw, err := readRecord(filepath.Join(s.root, fileName(key)))
		if err != nil || !bytes.Equal(raw, entry.raw) {
			result.Status = "partial"
			result.Gaps = append(result.Gaps, "history-entry-changed-after-load")
			continue
		}
		result.Records = append(result.Records, entry.record)
	}
	sort.Slice(result.Records, func(i, j int) bool {
		a, b := result.Records[i], result.Records[j]
		if a.Disclosure.ProtectedScope.Version != b.Disclosure.ProtectedScope.Version {
			return a.Disclosure.ProtectedScope.Version < b.Disclosure.ProtectedScope.Version
		}
		return a.Disclosure.EvidenceID < b.Disclosure.EvidenceID
	})
	return result
}

func (s *Store) String() string {
	if s == nil {
		return "loss-history(unavailable)"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("loss-history(records=%d,partial=%t)", len(s.byID), s.full || len(s.gaps) > 0)
}
