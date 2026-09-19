package actuator

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const migProfilesVersion = 1
const maxMIGProfilesBytes = 1 << 20

type MIGProfileRule struct {
	Namespace string `json:"namespace"`
	Resource  string `json:"resource"`
	Profile   string `json:"profile"`
}

type MIGProfiles struct {
	Version       int              `json:"version"`
	Rules         []MIGProfileRule `json:"rules"`
	byKey         map[string]MIGProfileRule
	validationErr error
}

func (p *MIGProfiles) index() (map[string]MIGProfileRule, error) {
	if p == nil || p.Version != migProfilesVersion {
		return nil, fmt.Errorf("MIG profile configuration version must be %d", migProfilesVersion)
	}
	byKey := make(map[string]MIGProfileRule, len(p.Rules))
	for i, r := range p.Rules {
		if r.Namespace == "" || r.Resource == "" || r.Profile == "" || strings.ContainsAny(r.Namespace+r.Resource, "*?[]") {
			return nil, fmt.Errorf("MIG profile rule %d must use exact non-empty namespace, resource and profile", i)
		}
		if errs := validation.IsDNS1123Label(r.Namespace); len(errs) > 0 {
			return nil, fmt.Errorf("MIG profile rule %d has invalid namespace", i)
		}
		if errs := validation.IsQualifiedName(r.Resource); len(errs) > 0 {
			return nil, fmt.Errorf("MIG profile rule %d has invalid resource name", i)
		}
		if !isCanonicalMIGResource(r.Resource) || !profilePattern.MatchString(r.Profile) {
			return nil, fmt.Errorf("MIG profile rule %d has unsupported resource or profile", i)
		}
		key := r.Namespace + "\x00" + r.Resource
		if _, exists := byKey[key]; exists {
			return nil, fmt.Errorf("MIG profile rule %d duplicates namespace/resource", i)
		}
		byKey[key] = r
	}
	return byKey, nil
}

func (p *MIGProfiles) validate() error {
	byKey, err := p.index()
	if err != nil {
		return err
	}
	p.byKey = byKey
	p.validationErr = nil
	return nil
}

func snapshotMIGProfiles(p *MIGProfiles) *MIGProfiles {
	if p == nil {
		return nil
	}
	result := &MIGProfiles{Version: p.Version, Rules: append([]MIGProfileRule(nil), p.Rules...)}
	if err := result.validate(); err != nil {
		result.validationErr = err
		result.byKey = map[string]MIGProfileRule{}
	}
	return result
}

func LoadMIGProfilesFile(path string) (*MIGProfiles, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMIGProfilesBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMIGProfilesBytes {
		return nil, fmt.Errorf("MIG profile configuration exceeds %d bytes", maxMIGProfilesBytes)
	}
	if err := rejectDuplicateJSONFields(b); err != nil {
		return nil, fmt.Errorf("MIG profile configuration: %w", err)
	}
	if err := validateExactObjectArrayJSONKeys(
		b,
		"rules",
		"MIG profile rule",
		map[string]struct{}{"version": {}, "rules": {}},
		map[string]struct{}{"namespace": {}, "resource": {}, "profile": {}},
	); err != nil {
		return nil, fmt.Errorf("MIG profile configuration: %w", err)
	}
	var p MIGProfiles
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("MIG profile configuration has trailing JSON")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *MIGProfiles) Resolve(namespace, resource string) (MIGProfileRule, error) {
	if p == nil {
		return MIGProfileRule{}, fmt.Errorf("operator MIG profile configuration is disabled")
	}
	if p.validationErr != nil {
		return MIGProfileRule{}, p.validationErr
	}
	byKey := p.byKey
	if byKey == nil {
		var err error
		byKey, err = p.index()
		if err != nil {
			return MIGProfileRule{}, err
		}
	}
	r, ok := byKey[namespace+"\x00"+resource]
	if !ok {
		return MIGProfileRule{}, fmt.Errorf("no operator MIG profile rule for namespace %q resource %q", namespace, resource)
	}
	return r, nil
}
