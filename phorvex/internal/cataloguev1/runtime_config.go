package cataloguev1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const RuntimeConfigVersion = 1

// RuntimeConfig is the private, server-generated child configuration. It may
// contain credential paths, but never credential bytes.
type RuntimeConfig struct {
	Version         int                          `json:"version"`
	StateDir        string                       `json:"stateDir"`
	KubeconfigPath  string                       `json:"kubeconfigPath,omitempty"`
	KubeContext     string                       `json:"kubeContext,omitempty"`
	FixedLoopback   string                       `json:"fixedLoopback"`
	ScopedTokenFile string                       `json:"scopedTokenFile"`
	AllowedTenant   string                       `json:"allowedTenant"`
	DeniedTenant    string                       `json:"deniedTenant"`
	DeniedTarget    string                       `json:"deniedTarget"`
	ExpectedSubject string                       `json:"expectedSubject"`
	GrantFile       string                       `json:"grantFile"`
	Voice           VoiceRuntime                 `json:"voice"`
	MCPVoiceModel   *MCPVoiceModelRuntime        `json:"mcpVoiceModel,omitempty"`
	GPU             GPUFixtureRuntime            `json:"gpu"`
	Guardrail       *GuardrailCalibrationRuntime `json:"guardrail,omitempty"`
	MCP             *MCPSessionRuntime           `json:"mcp,omitempty"`
	Chroma          *ChromaRuntime               `json:"chroma,omitempty"`
	LiteLLM         *LiteLLMRuntime              `json:"liteLLM,omitempty"`
	CRM             *CRMCapabilityRuntime        `json:"crm,omitempty"`
}

func (c RuntimeConfig) SHA256() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (c RuntimeConfig) Validate() error {
	if c.Version != RuntimeConfigVersion || !filepath.IsAbs(filepath.Clean(c.StateDir)) {
		return errors.New("catalogue v1 runtime version or state directory is invalid")
	}
	if (c.KubeconfigPath == "") != (c.KubeContext == "") || (c.KubeconfigPath != "" && !filepath.IsAbs(filepath.Clean(c.KubeconfigPath))) {
		return errors.New("catalogue v1 kubeconfig path and context must be an absolute, complete pair")
	}
	if (c.GPU.KubeconfigPath == "") != (c.GPU.KubeContext == "") || (c.GPU.KubeconfigPath != "" && !filepath.IsAbs(filepath.Clean(c.GPU.KubeconfigPath))) {
		return errors.New("catalogue v1 GPU kubeconfig path and context must be an absolute, complete pair")
	}
	if c.FixedLoopback != "" {
		u, err := url.Parse(c.FixedLoopback)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("catalogue v1 loopback origin is invalid")
		}
	}
	if c.MCPVoiceModel != nil && c.MCPVoiceModel.Enabled {
		if err := ValidateMCPVoiceModelConfig(*c.MCPVoiceModel, c.Voice, c.MCP, c.LiteLLM); err != nil {
			return err
		}
	}
	if c.Guardrail != nil {
		if err := ValidateGuardrailCalibrationRuntime(*c.Guardrail); err != nil {
			return err
		}
	}
	if c.MCP != nil {
		if err := ValidateMCPSessionRuntime(*c.MCP); err != nil {
			return err
		}
	}
	if c.Chroma != nil {
		if err := ValidateChromaRuntime(*c.Chroma); err != nil {
			return err
		}
	}
	if c.LiteLLM != nil {
		if err := ValidateLiteLLMRuntime(*c.LiteLLM); err != nil {
			return err
		}
		if c.LiteLLM.InferenceEnabled {
			if err := ValidateLiteLLMInferenceRuntime(*c.LiteLLM); err != nil {
				return err
			}
		}
	}
	if c.CRM != nil {
		if err := ValidateCRMLocalAuthority(*c.CRM); err != nil {
			return err
		}
	}
	return nil
}

func WriteRuntimeConfig(path string, c RuntimeConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'))
}

func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	raw, err := readPrivateRecord(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	var c RuntimeConfig
	if err = json.Unmarshal(raw, &c); err != nil {
		return RuntimeConfig{}, err
	}
	return c, c.Validate()
}

func (c RuntimeConfig) Runtime(restConfig *rest.Config, kube kubernetes.Interface, client *http.Client) (Runtime, error) {
	hash, err := c.SHA256()
	if err != nil {
		return Runtime{}, err
	}
	var loopback *url.URL
	if strings.TrimSpace(c.FixedLoopback) != "" {
		loopback, err = url.Parse(c.FixedLoopback)
		if err != nil {
			return Runtime{}, err
		}
	}
	runtime := Runtime{StateDir: c.StateDir, ConfigSHA256: hash, KubeconfigPath: c.KubeconfigPath, KubeContext: c.KubeContext, RESTConfig: restConfig, Kube: kube, HTTPClient: client,
		FixedLoopback: loopback, ScopedTokenFile: c.ScopedTokenFile, AllowedTenant: c.AllowedTenant,
		DeniedTenant: c.DeniedTenant, DeniedTarget: c.DeniedTarget, ExpectedSubject: c.ExpectedSubject,
		GrantFile: c.GrantFile, Voice: c.Voice, GPU: c.GPU}
	if c.MCPVoiceModel != nil {
		runtime.MCPVoiceModel = *c.MCPVoiceModel
	}
	if c.Guardrail != nil {
		runtime.Guardrail = *c.Guardrail
	}
	if c.MCP != nil {
		runtime.MCP = *c.MCP
	}
	if c.Chroma != nil {
		runtime.Chroma = *c.Chroma
	}
	if c.LiteLLM != nil {
		runtime.LiteLLM = *c.LiteLLM
	}
	if c.CRM != nil {
		runtime.CRM = *c.CRM
	}
	return runtime, nil
}
