package currentinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	Annotation                  = "phorvex.ai/current-protected-inventory-v1"
	AdmissionTimeAnnotation     = "phorvex.ai/current-inventory-admitted-at"
	AdmissionContractAnnotation = "phorvex.ai/current-inventory-admission-contract"
	BoundaryContractAnnotation  = "phorvex.ai/current-inventory-boundary-contract"
	BoundaryContract            = "current-protected-inventory-boundary-v1"
	MaxPayloadBytes             = 32 << 10
	MaxObservationTTL           = 5 * time.Minute
)

func validText(s string, max int) bool {
	return s != "" && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func digest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func identity(x model.ObjectIdentity) bool {
	return validText(x.APIVersion, 128) && validText(x.Kind, 128) && validText(x.Name, 253) && validText(x.UID, 128)
}

func Validate(p model.CurrentInventoryV1) error {
	if p.SchemaVersion != model.CurrentInventorySchemaV1 || !p.Synthetic || !validText(p.EvidenceID, 256) {
		return errors.New("invalid current inventory schema, identity, or synthetic classification")
	}
	if !validText(p.PolicyEpoch.Namespace, 63) || !validText(p.PolicyEpoch.Name, 253) || !validText(p.PolicyEpoch.UID, 128) || p.PolicyEpoch.Generation < 1 ||
		!validText(p.DecisionAsset.Namespace, 63) || !validText(p.DecisionAsset.Name, 253) || !validText(p.DecisionAsset.TargetUID, 128) ||
		!identity(p.ImmediateController) || !identity(p.StableWorkloadOwner) || !identity(p.SourceBinding.ConfigMap) {
		return errors.New("incomplete current inventory Kubernetes identity")
	}
	if p.DecisionAsset.Namespace != p.PolicyEpoch.Namespace {
		return errors.New("current inventory decision asset is outside policy namespace")
	}
	if p.SourceBinding.ConfigMap.APIVersion != "v1" || p.SourceBinding.ConfigMap.Kind != "ConfigMap" || p.SourceBinding.ConfigMap.Namespace != p.DecisionAsset.Namespace ||
		!validText(p.SourceBinding.ResourceVersion, 128) || !validText(p.SourceBinding.Key, 253) || !validText(p.SourceBinding.VolumeName, 253) ||
		!validText(p.SourceBinding.ContainerName, 253) || !validText(p.SourceBinding.MountPath, 1024) || !path.IsAbs(p.SourceBinding.MountPath) || path.Clean(p.SourceBinding.MountPath) != p.SourceBinding.MountPath || p.SourceBinding.MountPath == "/" ||
		!validText(p.SourceBinding.ProjectedPath, 1024) || p.SourceBinding.ProjectedPath == "." || path.IsAbs(p.SourceBinding.ProjectedPath) || path.Clean(p.SourceBinding.ProjectedPath) != p.SourceBinding.ProjectedPath || strings.HasPrefix(p.SourceBinding.ProjectedPath, "../") ||
		p.SourceBinding.Bytes <= 0 || p.SourceBinding.Bytes > MaxPayloadBytes || !digest(p.SourceBinding.SHA256) {
		return errors.New("invalid current inventory source binding")
	}
	if !validText(p.ProtectedScope.Tenant, 253) || !validText(p.ProtectedScope.Asset, 1024) || !validText(p.ProtectedScope.Version, 256) || !validText(p.ProtectedScope.Property, 256) ||
		p.Classification.RuleVersion != model.CurrentInventoryRuleVersionV1 || !digest(p.Classification.RuleDigest) ||
		p.Classification.InventoryClass != model.CurrentInventoryClass || p.Classification.PossibleOutcome != "unauthorized-disclosure" || !validText(p.Classification.ObserverIdentity, 512) {
		return errors.New("invalid current inventory protected classification")
	}
	o := p.Observation
	if o.StartedAt.IsZero() || o.CompletedAt.Before(o.StartedAt) || !o.ValidUntil.After(o.CompletedAt) || o.ValidUntil.Sub(o.CompletedAt) > MaxObservationTTL ||
		o.StatusCode != 200 || !o.ManifestEOF {
		return errors.New("invalid current inventory observation interval")
	}
	return nil
}

// RejectDuplicateFields closes encoding/json's last-key-wins behavior at this
// authority boundary, recursively for every object in the document.
func RejectDuplicateFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("current inventory JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return errors.New("current inventory JSON contains a duplicate field")
				}
				seen[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("current inventory JSON object is incomplete")
			}
		case '[':
			for dec.More() {
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("current inventory JSON array is incomplete")
			}
		default:
			return errors.New("current inventory JSON delimiter is invalid")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing current inventory JSON data")
	}
	return nil
}

func Parse(raw string) (model.CurrentInventoryV1, []byte, string, error) {
	var p model.CurrentInventoryV1
	if raw == "" || len(raw) > MaxPayloadBytes {
		return p, nil, "", errors.New("current inventory payload is empty or oversized")
	}
	if err := RejectDuplicateFields([]byte(raw)); err != nil {
		return p, nil, "", err
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, nil, "", err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return p, nil, "", errors.New("trailing current inventory JSON data")
	}
	if err := Validate(p); err != nil {
		return p, nil, "", err
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return p, nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return p, canonical, hex.EncodeToString(sum[:]), nil
}

func Marshal(p model.CurrentInventoryV1) (string, string, error) {
	if err := Validate(p); err != nil {
		return "", "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}
func EqualPayload(a, b string) bool {
	_, ca, _, ea := Parse(a)
	_, cb, _, eb := Parse(b)
	return ea == nil && eb == nil && bytes.Equal(ca, cb)
}
