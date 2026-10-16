package config

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Admission for the separately versioned application-output case. Runtime
// admission repeats these pins against the installed objects before any event.
func validateGuardrailOutputFixture(c TargetConfig) error {
	f := c.GuardrailOutputFixture
	if f == nil {
		return nil
	}
	bad := errors.New("config: guardrail output requires one reviewed exact-Pod synthetic support response profile")
	if !c.OwnedAck || c.Namespace != "vllm" || c.Context == "" || c.Context == "in-cluster" || c.Kubeconfig != "" || c.ExpectedNamespaceUID != "" ||
		c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 0 || len(c.DefenderFilter) != 0 ||
		c.GuardrailStaticFixture != nil || c.GuardrailAvailabilityFixture != nil || c.NATSExposureFixture != nil || c.MongoExposureFixture != nil ||
		c.PodBoundTokenFixture != nil || c.NATSJetStreamFixture != nil || c.GPUFunctionalFixture != nil ||
		c.NativeRouteFixture != nil || c.CRMCapabilityFixture != nil || c.BenignCheckpointLocalFixture ||
		f.Transport != "in-cluster" || !natsExposureRunID.MatchString(f.RunID) ||
		!kubernetesUIDPattern.MatchString(f.ClusterUID) || !kubernetesUIDPattern.MatchString(f.PodUID) ||
		!kubernetesUIDPattern.MatchString(f.ServiceUID) || !kubernetesUIDPattern.MatchString(f.SourceUID) ||
		!kubernetesUIDPattern.MatchString(f.ModelTargetPodUID) || !kubernetesUIDPattern.MatchString(f.ModelServiceUID) ||
		!kubernetesUIDPattern.MatchString(f.OutputPolicyConfigMapUID) || !kubernetesUIDPattern.MatchString(f.ManagerPodUID) ||
		!kubernetesUIDPattern.MatchString(f.ConsoleDeploymentUID) || !kubernetesUIDPattern.MatchString(f.PolicyUID) ||
		!natsExposureImage.MatchString(f.PodImageID) || !natsExposureImage.MatchString(f.SupportImageID) ||
		!natsExposureImage.MatchString(f.ModelTargetImageID) ||
		!natsExposureImage.MatchString(f.ManagerImageID) || !natsExposureImage.MatchString(f.ConsoleImageID) ||
		!natsExposureDigest.MatchString(f.SourceSHA256) || !natsExposureDigest.MatchString(f.SupportSourceSHA256) ||
		!natsExposureDigest.MatchString(f.OutputPolicyRuleSHA256) || f.SourceConfigMapName != "guardrail-output-fixture" ||
		f.OutputPolicyConfigMapName != "phorvex-output-policy-"+f.PodName || f.InitialActivationRevision != 0 ||
		f.PolicyName != "guardrail-output-fixture" || f.PolicyGeneration < 1 || f.ModelID != "Qwen/Qwen2.5-7B-Instruct-AWQ" ||
		f.ModelTargetPodUID == f.PodUID ||
		!strings.HasPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:") ||
		len(validation.IsDNS1123Subdomain(strings.TrimPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:"))) != 0 ||
		f.ConsoleURL != "http://127.0.0.1:8090" || f.MaxRunSeconds != 900 || f.CleanupSeconds != 90 {
		return bad
	}
	for _, name := range []string{f.PodName, f.ServiceName, f.ModelTargetPodName, f.ModelServiceName, f.ManagerPodName, f.ConsoleDeploymentName} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return bad
		}
	}
	u, err := url.Parse(f.AuditURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(u.Hostname(), ".phorvex-system.svc") || u.Port() != "8445" || f.AuditServerName != u.Hostname() {
		return bad
	}
	for path, want := range map[string]string{
		f.ScopedTokenFile:     "/etc/phorvex-catalogue-v1/token",
		f.AuditCAFile:         "/etc/audit-client/ca.crt",
		f.AuditClientCertFile: "/etc/audit-client/tls.crt",
		f.AuditClientKeyFile:  "/etc/audit-client/tls.key",
	} {
		if path != want || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return bad
		}
	}
	return nil
}
