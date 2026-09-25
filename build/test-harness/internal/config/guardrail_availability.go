package config

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// validateGuardrailAvailabilityFixture is the harness-side admission for one
// server-owned case. Console admission duplicates the predicate independently.
func validateGuardrailAvailabilityFixture(c TargetConfig) error {
	f := c.GuardrailAvailabilityFixture
	if f == nil {
		return nil
	}
	bad := errors.New("config: guardrail availability requires one reviewed, exact-target, six-call injected case")
	if !c.OwnedAck || c.Namespace != "vllm" || c.Context == "" || c.Context == "in-cluster" || c.Kubeconfig != "" || c.ExpectedNamespaceUID != "" ||
		c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 0 || len(c.DefenderFilter) != 0 ||
		c.GuardrailStaticFixture != nil || c.NATSExposureFixture != nil || c.MongoExposureFixture != nil ||
		c.PodBoundTokenFixture != nil || c.NATSJetStreamFixture != nil || c.GPUFunctionalFixture != nil ||
		c.InstalledManagerFixture != nil || c.NativeRouteFixture != nil || c.CRMCapabilityFixture != nil ||
		c.BenignCheckpointLocalFixture || f.Transport != "in-cluster" || !natsExposureRunID.MatchString(f.RunID) ||
		!kubernetesUIDPattern.MatchString(f.ClusterUID) || !kubernetesUIDPattern.MatchString(f.PodUID) ||
		!kubernetesUIDPattern.MatchString(f.ServiceUID) || !kubernetesUIDPattern.MatchString(f.SourceUID) ||
		!kubernetesUIDPattern.MatchString(f.GuardrailJournalUID) || !kubernetesUIDPattern.MatchString(f.ManagerPodUID) ||
		!kubernetesUIDPattern.MatchString(f.ConsoleDeploymentUID) || !kubernetesUIDPattern.MatchString(f.PolicyUID) ||
		!natsExposureImage.MatchString(f.PodImageID) || !natsExposureImage.MatchString(f.ManagerImageID) ||
		!natsExposureImage.MatchString(f.ConsoleImageID) || !natsExposureDigest.MatchString(f.SourceSHA256) ||
		f.SourceConfigMapName != "guardrail-proxy" || f.PolicyName != "vllm-defense" || f.PolicyGeneration < 1 ||
		f.ModelID != "Qwen/Qwen2.5-7B-Instruct-AWQ" ||
		!strings.HasPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:") ||
		len(validation.IsDNS1123Subdomain(strings.TrimPrefix(f.EventCreator, "system:serviceaccount:phorvex-system:"))) != 0 ||
		f.ConsoleURL != "http://127.0.0.1:8090" || f.MaxRunSeconds != 600 || f.CleanupSeconds != 90 {
		return bad
	}
	for _, name := range []string{f.PodName, f.GuardrailJournalName, f.ManagerPodName, f.ConsoleDeploymentName} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return bad
		}
	}
	u, err := url.Parse(f.AuditURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(u.Hostname(), ".phorvex-system.svc") || u.Port() != "8445" ||
		f.AuditServerName != u.Hostname() {
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
