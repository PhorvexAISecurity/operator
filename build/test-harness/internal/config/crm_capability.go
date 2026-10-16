package config

import (
	"errors"
	"path/filepath"
	"regexp"
)

var crmRunIDPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)
var crmSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateCRMCapabilityFixture(c TargetConfig) error {
	f := c.CRMCapabilityFixture
	if f == nil {
		return nil
	}
	if c.Namespace == "crm" {
		return errors.New("config: installed CRM namespace is not a disposable fixture")
	}
	if !crmRunIDPattern.MatchString(f.RunID) || f.NamespaceUID == "" ||
		f.NamespaceUID != c.ExpectedNamespaceUID || !kubernetesUIDPattern.MatchString(f.NamespaceUID) ||
		!crmSHA256Pattern.MatchString(f.ManifestSHA256) || !crmSHA256Pattern.MatchString(f.KubeconfigSHA256) || f.ServiceAccountName == "" {
		return errors.New("config: CRM capability run, namespace UID or manifest SHA-256 is invalid")
	}
	if c.Kubeconfig == "" || !filepath.IsAbs(c.Kubeconfig) || filepath.Clean(c.Kubeconfig) != c.Kubeconfig ||
		c.TrialsPerArm != 1 || len(c.DefenderFilter) != 1 || c.DefenderFilter[0] != "d-nomtd" ||
		len(c.ScenarioFilter) != 1 || (c.ScenarioFilter[0] != "c2-crm-refund-capability" && c.ScenarioFilter[0] != "c2-crm-reset-capability") {
		return errors.New("config: CRM capability requires one exact scenario, d-nomtd arm and pinned kubeconfig")
	}
	if c.NATSExposureFixture != nil || c.NATSJetStreamFixture != nil ||
		c.GPUFunctionalFixture != nil || c.NativeRouteFixture != nil || c.BenignCheckpointLocalFixture {
		return errors.New("config: CRM capability cannot combine with another fixture")
	}
	return nil
}
