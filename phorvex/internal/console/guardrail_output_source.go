package console

import (
	"bytes"
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	guardrailOutputRuleID    = "support-internal-audit-marker-v1"
	guardrailOutputPath      = "/v1/support/case"
	guardrailOutputBody      = `{"caseId":"CAT-001"}`
	guardrailOutputEventType = "phorvex.attack.sensitive-output"
)

type guardrailOutputProfile struct {
	Context              string                 `json:"context"`
	Namespace            string                 `json:"namespace"`
	Kubeconfig           string                 `json:"kubeconfig"`
	ExpectedNamespaceUID string                 `json:"expectedNamespaceUID"`
	OwnedAck             bool                   `json:"ownedAck"`
	TrialsPerArm         int                    `json:"trialsPerArm"`
	MasterSeed           int64                  `json:"masterSeed"`
	OutDir               string                 `json:"outDir"`
	ScenarioFilter       []string               `json:"scenarioFilter"`
	DefenderFilter       []string               `json:"defenderFilter"`
	Fixture              guardrailOutputFixture `json:"guardrailOutputFixture"`
}

type guardrailOutputFixture struct {
	RunID                     string `json:"runID"`
	Transport                 string `json:"transport"`
	ClusterUID                string `json:"clusterUID"`
	PodName                   string `json:"podName"`
	PodUID                    string `json:"podUID"`
	PodImageID                string `json:"podImageID"`
	ServiceName               string `json:"serviceName"`
	ServiceUID                string `json:"serviceUID"`
	SourceConfigMapName       string `json:"sourceConfigMapName"`
	SourceUID                 string `json:"sourceUID"`
	SourceSHA256              string `json:"sourceSHA256"`
	SupportImageID            string `json:"supportImageID"`
	SupportSourceSHA256       string `json:"supportSourceSHA256"`
	ModelTargetPodName        string `json:"modelTargetPodName"`
	ModelTargetPodUID         string `json:"modelTargetPodUID"`
	ModelTargetImageID        string `json:"modelTargetImageID"`
	ModelServiceName          string `json:"modelServiceName"`
	ModelServiceUID           string `json:"modelServiceUID"`
	OutputPolicyConfigMapName string `json:"outputPolicyConfigMapName"`
	OutputPolicyConfigMapUID  string `json:"outputPolicyConfigMapUID"`
	OutputPolicyRuleSHA256    string `json:"outputPolicyRuleSHA256"`
	InitialActivationRevision int64  `json:"initialActivationRevision"`
	ManagerPodName            string `json:"managerPodName"`
	ManagerPodUID             string `json:"managerPodUID"`
	ManagerImageID            string `json:"managerImageID"`
	ConsoleDeploymentName     string `json:"consoleDeploymentName"`
	ConsoleDeploymentUID      string `json:"consoleDeploymentUID"`
	ConsoleImageID            string `json:"consoleImageID"`
	PolicyName                string `json:"policyName"`
	PolicyUID                 string `json:"policyUID"`
	PolicyGeneration          int64  `json:"policyGeneration"`
	ModelID                   string `json:"modelID"`
	EventCreator              string `json:"eventCreator"`
	ConsoleURL                string `json:"consoleURL"`
	ScopedTokenFile           string `json:"scopedTokenFile"`
	AuditURL                  string `json:"auditURL"`
	AuditServerName           string `json:"auditServerName"`
	AuditCAFile               string `json:"auditCAFile"`
	AuditClientCertFile       string `json:"auditClientCertFile"`
	AuditClientKeyFile        string `json:"auditClientKeyFile"`
	MaxRunSeconds             int    `json:"maxRunSeconds"`
	CleanupSeconds            int    `json:"cleanupSeconds"`
}

func parseGuardrailOutputProfile(raw []byte) (guardrailOutputProfile, error) {
	var p guardrailOutputProfile
	bad := errors.New("guardrail output profile lacks reviewed exact fixture, rule, model and audit pins")
	if len(raw) == 0 || len(raw) > 64<<10 || yaml.UnmarshalStrict(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &p) != nil {
		return p, errors.New("guardrail output core profile pin invalid")
	}
	f := p.Fixture
	if bytes.Contains(raw, []byte("__SET_")) || !p.OwnedAck || p.Namespace != "vllm" || p.Context == "" || p.Context == "in-cluster" ||
		p.Kubeconfig != "" || p.ExpectedNamespaceUID != "" || p.TrialsPerArm != 1 || p.MasterSeed != 1337 || p.OutDir != "out-guardrail-output-response" || len(p.ScenarioFilter) != 0 || len(p.DefenderFilter) != 0 ||
		!staticRunID.MatchString(f.RunID) || f.Transport != "in-cluster" ||
		!staticUID.MatchString(f.ClusterUID) || !staticUID.MatchString(f.PodUID) || !staticUID.MatchString(f.ServiceUID) ||
		!staticUID.MatchString(f.SourceUID) || !staticUID.MatchString(f.OutputPolicyConfigMapUID) ||
		!staticUID.MatchString(f.ModelTargetPodUID) || !staticUID.MatchString(f.ModelServiceUID) ||
		!staticUID.MatchString(f.ManagerPodUID) || !staticUID.MatchString(f.ConsoleDeploymentUID) || !staticUID.MatchString(f.PolicyUID) ||
		!mongoPinnedImage.MatchString(f.PodImageID) || !mongoPinnedImage.MatchString(f.SupportImageID) ||
		!mongoPinnedImage.MatchString(f.ModelTargetImageID) || !mongoPinnedImage.MatchString(f.ManagerImageID) ||
		!mongoPinnedImage.MatchString(f.ConsoleImageID) || !staticSHA256.MatchString(f.SourceSHA256) ||
		!staticSHA256.MatchString(f.SupportSourceSHA256) || !staticSHA256.MatchString(f.OutputPolicyRuleSHA256) ||
		f.SourceConfigMapName != "guardrail-output-fixture" || f.OutputPolicyConfigMapName != "phorvex-output-policy-"+f.PodName ||
		f.InitialActivationRevision != 0 || f.PolicyName != "guardrail-output-fixture" || f.PolicyGeneration < 1 ||
		f.ModelID != "Qwen/Qwen2.5-7B-Instruct-AWQ" || f.ModelTargetPodUID == f.PodUID ||
		!strings.HasPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:") ||
		len(validation.IsDNS1123Subdomain(strings.TrimPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:"))) != 0 ||
		f.ConsoleURL != "http://127.0.0.1:8090" || f.MaxRunSeconds != 900 || f.CleanupSeconds != 90 {
		return p, errors.New("guardrail output fixture pin invalid")
	}
	for _, n := range []string{f.PodName, f.ServiceName, f.ModelTargetPodName, f.ModelServiceName, f.ManagerPodName, f.ConsoleDeploymentName} {
		if n == "" || len(validation.IsDNS1123Subdomain(n)) != 0 {
			return p, errors.New("guardrail output DNS name invalid")
		}
	}
	u, err := url.Parse(f.AuditURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(u.Hostname(), ".phorvex-system.svc") || u.Port() != "8445" || f.AuditServerName != u.Hostname() {
		return p, errors.New("guardrail output audit endpoint invalid")
	}
	for path, want := range map[string]string{
		f.ScopedTokenFile:     "/etc/phorvex-catalogue-v1/token",
		f.AuditCAFile:         "/etc/audit-client/ca.crt",
		f.AuditClientCertFile: "/etc/audit-client/tls.crt",
		f.AuditClientKeyFile:  "/etc/audit-client/tls.key",
	} {
		if path != want || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return p, bad
		}
	}
	return p, nil
}

func loadGuardrailOutputProfile(cfg Config) (guardrailOutputProfile, []byte, error) {
	var p guardrailOutputProfile
	if !cfg.GuardrailOutputEnabled || !staticSHA256.MatchString(cfg.GuardrailOutputProfileSHA256) ||
		cfg.GuardrailOutputProfilePath == "" || !filepath.IsAbs(cfg.GuardrailOutputProfilePath) ||
		filepath.Clean(cfg.GuardrailOutputProfilePath) != cfg.GuardrailOutputProfilePath || cfg.AuditSource == nil {
		return p, nil, errors.New("reviewed guardrail output profile or authenticated audit source unavailable")
	}
	raw, err := readPinnedNamedProfile(cfg.GuardrailOutputProfilePath, cfg.GuardrailOutputProfileSHA256)
	if err != nil {
		return p, nil, errors.New("reviewed guardrail output profile bytes unavailable")
	}
	p, err = parseGuardrailOutputProfile(raw)
	if err != nil || cfg.AuditSourceIdentity != p.Fixture.AuditURL+"|"+p.Fixture.AuditServerName {
		return p, nil, errors.New("reviewed guardrail output profile or audit identity differs")
	}
	return p, raw, nil
}
