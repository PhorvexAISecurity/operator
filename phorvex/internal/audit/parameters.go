package audit

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
	"strings"
	"sync"
	"syscall"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	ParameterMaterialManifest        = "manifest"
	ParameterMaterialPolicyOverrides = "policy-overrides"
	MaxParameterMaterialBytes        = 1 << 20
	MaxParameterMaterialDocuments    = 4096
	MaxParameterMaterialTotalBytes   = MaxParameterMaterialBytes * MaxParameterMaterialDocuments
)

// ParameterMaterialStore retains canonical decision inputs next to the audit
// stream. Documents are immutable and addressed by the same digest carried in
// each decision row. The fixed document limit bounds growth without deleting a
// document that an already-retained decision can still reference; together the
// limits cap canonical material at MaxParameterMaterialTotalBytes.
type ParameterMaterialStore struct {
	root     string
	maxDocs  int
	mu       sync.Mutex
	writeAll func(io.Writer, []byte) error
}

func NewParameterMaterialStore(auditPath string) (*ParameterMaterialStore, error) {
	if auditPath == "" {
		return nil, errors.New("audit path is required for parameter material retention")
	}
	abs, err := filepath.Abs(auditPath)
	if err != nil {
		return nil, err
	}
	s := &ParameterMaterialStore{root: abs + ".parameters", maxDocs: MaxParameterMaterialDocuments, writeAll: writeParameterBytes}
	if err := preparePrivateMaterialStore(s.root); err != nil {
		return nil, fmt.Errorf("prepare parameter material store: %w", err)
	}
	return s, nil
}

func validatePrivateMaterialDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("parameter material directory must be a private regular directory")
	}
	return nil
}

func writeParameterBytes(out io.Writer, raw []byte) error {
	n, err := out.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}

func parameterDigest(hash string) (string, error) {
	if len(hash) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(hash, "sha256:") {
		return "", errors.New("parameter material hash must be sha256")
	}
	digest := strings.TrimPrefix(hash, "sha256:")
	if strings.ToLower(digest) != digest {
		return "", errors.New("parameter material digest must be lowercase")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("parameter material digest is invalid")
	}
	return digest, nil
}

func validParameterMaterialKind(kind string) bool {
	return kind == ParameterMaterialManifest || kind == ParameterMaterialPolicyOverrides
}

func (s *ParameterMaterialStore) materialPath(kind, hash string) (string, error) {
	if s == nil || s.root == "" || !validParameterMaterialKind(kind) {
		return "", errors.New("invalid parameter material store or kind")
	}
	if err := validatePrivateMaterialDir(s.root); err != nil {
		return "", err
	}
	digest, err := parameterDigest(hash)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.root, kind)
	if err := validatePrivateMaterialDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, digest+".json")
	if filepath.Dir(path) != dir {
		return "", errors.New("parameter material path escaped its root")
	}
	return path, nil
}

func canonicalParameterMaterial(kind string, material any) ([]byte, string, error) {
	var raw []byte
	var hash string
	var err error
	switch kind {
	case ParameterMaterialManifest:
		value, ok := material.(model.DecisionParameterManifest)
		if !ok {
			return nil, "", errors.New("manifest material has wrong type")
		}
		value = value.Canonical()
		hash, err = value.CanonicalHash()
		if err == nil {
			raw, err = json.Marshal(value)
		}
	case ParameterMaterialPolicyOverrides:
		value, ok := material.(model.EffectivePolicyOverrides)
		if !ok {
			return nil, "", errors.New("policy override material has wrong type")
		}
		value = value.Canonical()
		hash, err = value.CanonicalHash()
		if err == nil {
			raw, err = json.Marshal(value)
		}
	default:
		return nil, "", errors.New("unknown parameter material kind")
	}
	if err != nil {
		return nil, "", err
	}
	if len(raw) == 0 || len(raw) > MaxParameterMaterialBytes {
		return nil, "", errors.New("parameter material exceeds its size bound")
	}
	return raw, hash, nil
}

func (s *ParameterMaterialStore) documentCount() (int, error) {
	if err := validatePrivateMaterialDir(s.root); err != nil {
		return 0, err
	}
	total := 0
	for _, kind := range []string{ParameterMaterialManifest, ParameterMaterialPolicyOverrides} {
		dir := filepath.Join(s.root, kind)
		if err := validatePrivateMaterialDir(dir); err != nil {
			return 0, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return 0, err
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return 0, err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				return 0, errors.New("parameter material directory contains a non-private non-regular entry")
			}
			// Count crash-left temporary files as capacity too. They are not
			// silently deleted, and repeated interruptions therefore fail
			// explicitly instead of creating unbounded sibling-store growth.
			total++
		}
	}
	return total, nil
}

func openParameterMaterial(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > MaxParameterMaterialBytes {
		_ = f.Close()
		return nil, errors.New("parameter material is not a bounded private regular file")
	}
	return f, nil
}

func readParameterMaterialFile(path string) ([]byte, error) {
	f, err := openParameterMaterial(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxParameterMaterialBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxParameterMaterialBytes {
		return nil, errors.New("parameter material is unreadable or exceeds its size bound")
	}
	return raw, nil
}

func (s *ParameterMaterialStore) retain(kind, hash string, raw []byte) error {
	path, err := s.materialPath(kind, hash)
	if err != nil {
		return err
	}
	if existing, readErr := readParameterMaterialFile(path); readErr == nil {
		if !bytes.Equal(existing, raw) {
			return errors.New("parameter material digest collision or on-disk tamper")
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	count, err := s.documentCount()
	if err != nil {
		return err
	}
	if count >= s.maxDocs {
		return errors.New("parameter material capacity exhausted")
	}
	dir := filepath.Dir(path)
	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(suffix)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := s.writeAll(f, raw); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readParameterMaterialFile(path)
			if readErr == nil && bytes.Equal(existing, raw) {
				_ = os.Remove(tmp)
				committed = true
				return nil
			}
		}
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	committed = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// Store verifies the exact row reference before retaining its two canonical
// documents. A failure never turns into a retained status at the audit boundary.
func (s *ParameterMaterialStore) Store(ref *model.ParameterSetReference, manifest model.DecisionParameterManifest, overrides model.EffectivePolicyOverrides) error {
	if err := model.VerifyParameterSet(ref, &manifest, &overrides); err != nil {
		return err
	}
	manifestRaw, manifestHash, err := canonicalParameterMaterial(ParameterMaterialManifest, manifest)
	if err != nil || manifestHash != ref.ManifestHash {
		return errors.Join(errors.New("manifest hash mismatch"), err)
	}
	overridesRaw, overridesHash, err := canonicalParameterMaterial(ParameterMaterialPolicyOverrides, overrides)
	if err != nil || overridesHash != ref.PolicyOverridesHash {
		return errors.Join(errors.New("policy override hash mismatch"), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.retain(ParameterMaterialManifest, manifestHash, manifestRaw); err != nil {
		return err
	}
	return s.retain(ParameterMaterialPolicyOverrides, overridesHash, overridesRaw)
}

// ReadParameterMaterial reads one strict digest name from a store sibling. It
// re-hashes canonical bytes so a tampered file is never exported as requested.
func ReadParameterMaterial(auditPath, kind, hash string) ([]byte, error) {
	abs, err := filepath.Abs(auditPath)
	if err != nil {
		return nil, err
	}
	s := &ParameterMaterialStore{root: abs + ".parameters"}
	path, err := s.materialPath(kind, hash)
	if err != nil {
		return nil, err
	}
	raw, err := readParameterMaterialFile(path)
	if err != nil {
		return nil, err
	}
	want, _ := parameterDigest(hash)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("parameter material digest does not match its name")
	}
	return raw, nil
}
