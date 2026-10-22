package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"io"
	"path/filepath"
	"regexp"
)

var endpointLeaseImageDigest = regexp.MustCompile(`^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$`)

const (
	endpointLeaseAction       = "endpoint-lease-revoke"
	endpointLeaseScenario     = "ai2-endpoint-security"
	endpointLeaseRoute        = "/api/vllm/attack"
	endpointLeaseProfilePath  = "/etc/phorvex-endpoint-lease/profile.json"
	endpointLeasePolicyCM     = "phorvex-endpoint-lease-policy"
	endpointLeaseJournalCM    = "phorvex-endpoint-lease-journal"
	endpointLeaseTenantSecret = "phorvex-endpoint-lease-keys"
	endpointLeaseConsoleKey   = "vllm-endpoint-lease-callers"
	endpointLeaseModel        = "Qwen/Qwen2.5-7B-Instruct-AWQ"
)

// The profile contains opaque IDs and SHA-256 pins only. A/B bearers and the
// HMAC seed never appear here, in the event, or in a terminal result.
type endpointLeaseProfile struct {
	Version             int    `json:"version"`
	ServiceName         string `json:"serviceName"`
	ServiceUID          string `json:"serviceUID"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	PolicyConfigMapUID  string `json:"policyConfigMapUID"`
	JournalUID          string `json:"journalUID"`
	TenantSecretUID     string `json:"tenantSecretUID"`
	ConsoleSecretUID    string `json:"consoleSecretUID"`
	SourceConfigMapName string `json:"sourceConfigMapName"`
	SourceConfigMapUID  string `json:"sourceConfigMapUID"`
	ProxySourceSHA256   string `json:"proxySourceSHA256"`
	ProxyImage          string `json:"proxyImage"`
	ApprovedEngineImage string `json:"approvedEngineImage"`
	SeedSHA256          string `json:"seedSHA256"`
	ClientASHA256       string `json:"clientASHA256"`
	ClientBSHA256       string `json:"clientBSHA256"`
	ClientAHMAC         string `json:"clientAHMAC"`
	ClientBHMAC         string `json:"clientBHMAC"`
	EventCreator        string `json:"eventCreator"`
	AuditSourceIdentity string `json:"auditSourceIdentity"`
	ModelID             string `json:"modelId"`
	MaxRunSeconds       int    `json:"maxRunSeconds"`

	SourceUpgrade *endpointLeaseSourceUpgrade `json:"sourceUpgrade,omitempty"`
}

func parseEndpointLeaseProfile(raw []byte) (endpointLeaseProfile, error) {
	var p endpointLeaseProfile
	bad := errors.New("reviewed endpoint lease profile invalid")
	if len(raw) == 0 || len(raw) > 8192 || rejectNATSNestedDuplicates(raw) != nil {
		return p, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, bad
	}
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return p, bad
	}
	encoded, _ := json.Marshal(canonical)
	if obj, ok := canonical.(map[string]any); ok {
		if value, present := obj["sourceUpgrade"]; present && value == nil {
			return p, bad
		}
	}
	if !bytes.Equal(raw, encoded) || p.Version != 1 || p.ServiceName != "vllm" ||
		p.PolicyName != "vllm-defense" || p.SourceConfigMapName != "guardrail-proxy" ||
		p.ModelID != endpointLeaseModel || p.MaxRunSeconds != 900 ||
		p.EventCreator != eventtrust.Injector() ||
		p.AuditSourceIdentity == "" || len(p.AuditSourceIdentity) > 256 ||
		p.PolicyGeneration < 1 || !endpointLeaseImageDigest.MatchString(p.ProxyImage) ||
		!endpointLeaseImageDigest.MatchString(p.ApprovedEngineImage) ||
		p.ClientAHMAC == p.ClientBHMAC || p.ClientASHA256 == p.ClientBSHA256 {
		return p, bad
	}
	for _, value := range []string{p.ServiceUID, p.PolicyUID, p.PolicyConfigMapUID, p.JournalUID,
		p.TenantSecretUID, p.ConsoleSecretUID, p.SourceConfigMapUID} {
		if !staticUID.MatchString(value) {
			return p, bad
		}
	}
	for _, value := range []string{p.ProxySourceSHA256, p.SeedSHA256, p.ClientASHA256,
		p.ClientBSHA256, p.ClientAHMAC, p.ClientBHMAC} {
		if !staticSHA256.MatchString(value) {
			return p, bad
		}
	}
	if p.SourceUpgrade != nil {
		if _, _, err := endpointLeaseUpgradePrior(p); err != nil {
			return p, bad
		}
	}
	return p, nil
}

func loadEndpointLeaseProfile(cfg Config) (endpointLeaseProfile, error) {
	var p endpointLeaseProfile
	if !cfg.EndpointLeaseEnabled || !staticSHA256.MatchString(cfg.EndpointLeaseProfileSHA256) ||
		cfg.EndpointLeaseProfilePath != endpointLeaseProfilePath ||
		!filepath.IsAbs(cfg.EndpointLeaseProfilePath) || cfg.AuditSource == nil {
		return p, errors.New("reviewed endpoint lease profile or authenticated audit source unavailable")
	}
	raw, err := readPinnedNamedProfile(cfg.EndpointLeaseProfilePath, cfg.EndpointLeaseProfileSHA256)
	if err != nil {
		return p, errors.New("endpoint lease profile bytes unavailable")
	}
	p, err = parseEndpointLeaseProfile(raw)
	if err != nil || cfg.AuditSourceIdentity != p.AuditSourceIdentity {
		return endpointLeaseProfile{}, errors.New("endpoint lease source or audit identity differs")
	}
	return p, nil
}
