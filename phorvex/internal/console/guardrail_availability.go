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
	guardrailAvailabilityConfig = "guardrail-availability-recovery"
	guardrailAvailabilitySchema = "guardrail-availability-result-v1"
)

type guardrailAvailabilityProfile struct {
	Context              string   `json:"context"`
	Namespace            string   `json:"namespace"`
	Kubeconfig           string   `json:"kubeconfig"`
	ExpectedNamespaceUID string   `json:"expectedNamespaceUID"`
	OwnedAck             bool     `json:"ownedAck"`
	TrialsPerArm         int      `json:"trialsPerArm"`
	ScenarioFilter       []string `json:"scenarioFilter"`
	DefenderFilter       []string `json:"defenderFilter"`
	Fixture              struct {
		RunID                  string `json:"runID"`
		Transport              string `json:"transport"`
		ClusterUID             string `json:"clusterUID"`
		PodName                string `json:"podName"`
		PodUID                 string `json:"podUID"`
		PodImageID             string `json:"podImageID"`
		ServiceUID             string `json:"serviceUID"`
		SourceConfigMapName    string `json:"sourceConfigMapName"`
		SourceUID              string `json:"sourceUID"`
		SourceSHA256           string `json:"sourceSHA256"`
		BoundarySourceSHA256   string `json:"boundarySourceSHA256,omitempty"`
		GuardrailJournalName   string `json:"guardrailJournalName"`
		GuardrailJournalUID    string `json:"guardrailJournalUID"`
		JournalInitiallyAbsent bool   `json:"journalInitiallyAbsent,omitempty"`
		ManagerPodName         string `json:"managerPodName"`
		ManagerPodUID          string `json:"managerPodUID"`
		ManagerImageID         string `json:"managerImageID"`
		ConsoleDeploymentName  string `json:"consoleDeploymentName"`
		ConsoleDeploymentUID   string `json:"consoleDeploymentUID"`
		ConsoleImageID         string `json:"consoleImageID"`
		PolicyName             string `json:"policyName"`
		PolicyUID              string `json:"policyUID"`
		PolicyGeneration       int64  `json:"policyGeneration"`
		ModelID                string `json:"modelID"`
		// The effect action requires this explicit active baseline pin. The
		// availability recovery suite retains its own pgv1-only gate.
		ActiveVariant       string `json:"activeVariant,omitempty"`
		EventCreator        string `json:"eventCreator"`
		ConsoleURL          string `json:"consoleURL"`
		ScopedTokenFile     string `json:"scopedTokenFile"`
		AuditURL            string `json:"auditURL"`
		AuditServerName     string `json:"auditServerName"`
		AuditCAFile         string `json:"auditCAFile"`
		AuditClientCertFile string `json:"auditClientCertFile"`
		AuditClientKeyFile  string `json:"auditClientKeyFile"`
		MaxRunSeconds       int    `json:"maxRunSeconds"`
		CleanupSeconds      int    `json:"cleanupSeconds"`
	} `json:"guardrailAvailabilityFixture"`
}

func parseGuardrailAvailabilityProfile(raw []byte) (guardrailAvailabilityProfile, error) {
	var p guardrailAvailabilityProfile
	bad := errors.New("guardrail availability profile lacks reviewed exact identity, route or fixed bounds")
	if len(raw) == 0 || len(raw) > 64<<10 ||
		yaml.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &p) != nil {
		return p, bad
	}
	f := p.Fixture
	if strings.Contains(p.Context, "__SET_") {
		return p, bad
	}
	if !p.OwnedAck || p.Namespace != "vllm" || p.Context == "" || p.Context == "in-cluster" ||
		p.Kubeconfig != "" || p.ExpectedNamespaceUID != "" || p.TrialsPerArm != 1 ||
		len(p.ScenarioFilter) != 0 || len(p.DefenderFilter) != 0 || !staticRunID.MatchString(f.RunID) ||
		f.Transport != "in-cluster" || !staticUID.MatchString(f.ClusterUID) || !staticUID.MatchString(f.PodUID) ||
		!staticUID.MatchString(f.ServiceUID) || !staticUID.MatchString(f.SourceUID) ||
		((f.JournalInitiallyAbsent && f.GuardrailJournalUID != "") || (!f.JournalInitiallyAbsent && !staticUID.MatchString(f.GuardrailJournalUID))) || !staticUID.MatchString(f.ManagerPodUID) ||
		!staticUID.MatchString(f.ConsoleDeploymentUID) || !staticUID.MatchString(f.PolicyUID) ||
		!mongoPinnedImage.MatchString(f.PodImageID) || !mongoPinnedImage.MatchString(f.ManagerImageID) ||
		!mongoPinnedImage.MatchString(f.ConsoleImageID) || !staticSHA256.MatchString(f.SourceSHA256) ||
		f.SourceConfigMapName != "guardrail-proxy" || f.PolicyName != "vllm-defense" || f.PolicyGeneration < 1 ||
		f.ModelID != "Qwen/Qwen2.5-7B-Instruct-AWQ" ||
		!strings.HasPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:") ||
		len(validation.IsDNS1123Subdomain(strings.TrimPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:"))) != 0 ||
		f.ConsoleURL != "http://127.0.0.1:8090" || f.MaxRunSeconds != 600 || f.CleanupSeconds != 90 {
		return p, bad
	}
	for _, name := range []string{f.PodName, f.GuardrailJournalName, f.ManagerPodName, f.ConsoleDeploymentName} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return p, bad
		}
	}
	u, err := url.Parse(f.AuditURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(u.Hostname(), ".phorvex-system.svc") || u.Port() != "8445" || f.AuditServerName != u.Hostname() {
		return p, bad
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

type GuardrailAvailabilityControls struct {
	Canary     string `json:"canary"`
	SayOK      string `json:"sayOK"`
	Arithmetic string `json:"arithmetic"`
}
type GuardrailAvailabilityOperation struct {
	EventUID     string `json:"eventUID"`
	DecisionID   string `json:"decisionID"`
	OperationID  string `json:"operationID"`
	PriorVariant string `json:"priorVariant"`
	NextVariant  string `json:"nextVariant"`
	Generation   int64  `json:"generation"`
}
type GuardrailAvailabilityResult struct {
	Accepted              bool                           `json:"accepted"`
	Status                string                         `json:"status"`
	Issues                []string                       `json:"issues"`
	EventMode             string                         `json:"eventMode"`
	NaturalDetector       string                         `json:"naturalDetector"`
	SecurityEfficacy      string                         `json:"securityEfficacy"`
	SyntheticThreat       string                         `json:"syntheticThreat"`
	Route                 string                         `json:"route"`
	LoadedWeightsAttested bool                           `json:"loadedWeightsAttested"`
	Before                GuardrailAvailabilityControls  `json:"before"`
	After                 GuardrailAvailabilityControls  `json:"after"`
	Operation             GuardrailAvailabilityOperation `json:"operation"`
	CleanupVerified       bool                           `json:"cleanupVerified"`
}
