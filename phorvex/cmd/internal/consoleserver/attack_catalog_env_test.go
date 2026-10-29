package consoleserver

import (
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestAttackCatalogEnvironmentRequiresFixedProfilePath(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || cfg.AttackCatalogEnabled {
		t.Fatalf("disabled defaults changed: enabled=%v err=%v", cfg.AttackCatalogEnabled, err)
	}
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED"] = "true"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT"] = "phorvex-test"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT"] = "console-identity-test"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE"] = "/tmp/client-choice.json"
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("caller-variable profile path was accepted")
	}
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE"] = "/etc/phorvex-attack-catalog/identity-profile.json"
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || !cfg.AttackCatalogEnabled ||
		cfg.AttackCatalogAuthorizationTenant != values["PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT"] ||
		cfg.AttackCatalogIdentityTenant != values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT"] ||
		cfg.AttackCatalogIdentityProfilePath != values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE"] {
		t.Fatalf("fixed profile was not admitted: %+v err=%v", cfg, err)
	}
}

func TestAttackCatalogPrometheusEvidenceRequiresPinnedDeploymentSource(t *testing.T) {
	values := map[string]string{
		"PHORVEX_CONSOLE_RUN_PROMETHEUS_EVIDENCE_ENABLED": "true",
	}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("Prometheus evidence was enabled without the attack catalogue")
	}
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED"] = "true"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT"] = "phorvex-test"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT"] = "console-identity-test"
	values["PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE"] = "/etc/phorvex-attack-catalog/identity-profile.json"
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("Prometheus evidence was enabled without its URL and environment")
	}
	values["PHORVEX_PROM_URL"] = "http://prometheus.monitoring.svc:9090"
	values["PHORVEX_CONSOLE_RUN_PROMETHEUS_ENVIRONMENT"] = "staging"
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil {
		t.Fatalf("valid Prometheus evidence configuration refused: %v", err)
	}
	if !cfg.RunPrometheusEvidence.Enabled || cfg.RunPrometheusEvidence.URL != values["PHORVEX_PROM_URL"] ||
		cfg.RunPrometheusEvidence.Environment != "staging" {
		t.Fatalf("Prometheus evidence configuration not retained: %+v", cfg.RunPrometheusEvidence)
	}
}
