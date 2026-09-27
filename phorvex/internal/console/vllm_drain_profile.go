package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// The caller supplies no destination or model. Every value is reviewable in a
// digest-pinned mounted profile and must be rechecked against current source.
type drainLiveProfile struct {
	Schema                  string            `json:"schema"`
	Context                 string            `json:"context"`
	ClusterUID              string            `json:"clusterUID"`
	PodName                 string            `json:"podName"`
	PodUID                  string            `json:"podUID"`
	PodImageID              string            `json:"podImageID"`
	PodContainerID          string            `json:"podContainerID"`
	ProxyImageID            string            `json:"proxyImageID"`
	ProxyContainerID        string            `json:"proxyContainerID"`
	ServiceName             string            `json:"serviceName"`
	ServiceUID              string            `json:"serviceUID"`
	ServiceSelector         map[string]string `json:"serviceSelector"`
	PolicyName              string            `json:"policyName"`
	PolicyUID               string            `json:"policyUID"`
	PolicyGeneration        int64             `json:"policyGeneration"`
	ManagerPodName          string            `json:"managerPodName"`
	ManagerPodUID           string            `json:"managerPodUID"`
	ManagerImageID          string            `json:"managerImageID"`
	ManagerContainerID      string            `json:"managerContainerID"`
	ConsoleDeploymentName   string            `json:"consoleDeploymentName"`
	ConsoleDeploymentUID    string            `json:"consoleDeploymentUID"`
	ConsoleImageID          string            `json:"consoleImageID"`
	ModelID                 string            `json:"modelID"`
	AuditSourceIdentity     string            `json:"auditSourceIdentity"`
	ServingCompletionSHA256 string            `json:"servingCompletionSHA256"`
	ServingEngineSHA256     string            `json:"servingEngineSHA256"`
	DrainProxySourceSHA256  string            `json:"drainProxySourceSHA256"`
	DrainEngineSourceSHA256 string            `json:"drainEngineSourceSHA256"`
	MaxRunSeconds           int               `json:"maxRunSeconds"`
}

func parseDrainLiveProfile(raw []byte) (drainLiveProfile, error) {
	var p drainLiveProfile
	bad := errors.New("request-drain profile lacks reviewed exact source or fixed limits")
	if len(raw) == 0 || len(raw) > 16<<10 {
		return p, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF {
		return p, bad
	}
	if p.Schema != "live-request-drain-v1" || p.Context == "" || p.Context == "in-cluster" ||
		strings.Contains(p.Context, "__SET_") || !staticUID.MatchString(p.ClusterUID) ||
		!staticUID.MatchString(p.PodUID) || !staticUID.MatchString(p.ServiceUID) ||
		!staticUID.MatchString(p.PolicyUID) || !staticUID.MatchString(p.ManagerPodUID) ||
		!staticUID.MatchString(p.ConsoleDeploymentUID) ||
		!mongoPinnedImage.MatchString(p.PodImageID) || !mongoPinnedImage.MatchString(p.ManagerImageID) ||
		p.PodContainerID == "" || p.ProxyContainerID == "" || p.ManagerContainerID == "" || !mongoPinnedImage.MatchString(p.ProxyImageID) ||
		!mongoPinnedImage.MatchString(p.ConsoleImageID) ||
		!staticSHA256.MatchString(p.ServingCompletionSHA256) ||
		!staticSHA256.MatchString(p.ServingEngineSHA256) ||
		p.ServingCompletionSHA256 != "30ed34497113131c2749b7091bc4a49b5dd374b23b15bc5c7981c3e90ede804a" ||
		p.ServingEngineSHA256 != "35e4419aeb3ca2c1c0153254ac0a179db454cae4a33f7d37b3b9020ebdcfa73e" ||
		!staticSHA256.MatchString(p.DrainProxySourceSHA256) ||
		!staticSHA256.MatchString(p.DrainEngineSourceSHA256) ||
		p.PolicyName != "vllm-defense" || p.PolicyGeneration < 1 || len(p.ServiceSelector) == 0 || len(p.ServiceSelector) > 8 ||
		p.AuditSourceIdentity == "" || strings.Contains(p.AuditSourceIdentity, "__SET_") ||
		p.ModelID != "Qwen/Qwen2.5-7B-Instruct-AWQ" ||
		p.MaxRunSeconds != 240 {
		return p, bad
	}
	for _, name := range []string{p.PodName, p.ServiceName, p.ManagerPodName, p.ConsoleDeploymentName} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return p, bad
		}
	}
	for key, value := range p.ServiceSelector {
		if key == "" || value == "" || len(validation.IsQualifiedName(key)) != 0 || len(validation.IsValidLabelValue(value)) != 0 {
			return p, bad
		}
	}
	return p, nil
}

func loadDrainLiveProfile(cfg Config) (drainLiveProfile, []byte, error) {
	var p drainLiveProfile
	if !cfg.DrainLiveEnabled || !staticSHA256.MatchString(cfg.DrainLiveProfileSHA256) ||
		cfg.DrainLiveProfilePath == "" || !filepath.IsAbs(cfg.DrainLiveProfilePath) ||
		filepath.Clean(cfg.DrainLiveProfilePath) != cfg.DrainLiveProfilePath || cfg.AuditSource == nil {
		return p, nil, errors.New("reviewed request-drain profile or authenticated audit source unavailable")
	}
	raw, err := readPinnedNamedProfile(cfg.DrainLiveProfilePath, cfg.DrainLiveProfileSHA256)
	if err != nil {
		return p, nil, errors.New("request-drain profile bytes unavailable")
	}
	p, err = parseDrainLiveProfile(raw)
	if err != nil {
		return p, nil, err
	}
	if cfg.AuditSourceIdentity != p.AuditSourceIdentity {
		return p, nil, errors.New("authenticated audit source identity drift")
	}
	return p, raw, nil
}
