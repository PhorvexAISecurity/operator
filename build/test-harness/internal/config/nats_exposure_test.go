package config

import (
	"strings"
	"testing"
)

func validNATSExposureConfig() TargetConfig {
	nonce := "0123456789abcdef01234567"
	return TargetConfig{Context: "reviewed-dev-cluster", Namespace: "phorvex-nats-exposure-fixture", TrialsPerArm: 1, ScenarioFilter: []string{"c2-nats-uncredentialed-exposure"}, DefenderFilter: []string{"d-nomtd"}, NATSExposureFixture: &NATSExposureFixtureConfig{RunID: "run-42", Nonce: nonce, Transport: "in-cluster", ClusterUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ConfigSHA256: strings.Repeat("a", 64), NodeName: "ip-10-0-0-1", ObserverImage: "docker.io/phorvex/console@sha256:" + strings.Repeat("b", 64), BrokerImageID: "docker.io/library/nats@sha256:" + strings.Repeat("c", 64), BrokerVersion: "2.10.29", MaxRunSeconds: 600}}
}
func TestNATSExposureConfigOneUseContract(t *testing.T) {
	base := validNATSExposureConfig()
	if err := validateNATSExposureFixture(base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*TargetConfig)
	}{
		{"preselected uid", func(c *TargetConfig) { c.ExpectedNamespaceUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" }},
		{"wrong namespace", func(c *TargetConfig) { c.Namespace = "nats" }},
		{"different arm", func(c *TargetConfig) { c.DefenderFilter = []string{"d-phorvex"} }},
		{"adaptive multiplicity", func(c *TargetConfig) { c.TrialsPerArm = 2 }},
		{"mutable image", func(c *TargetConfig) { c.NATSExposureFixture.ObserverImage = "console:latest" }},
		{"generic context marker", func(c *TargetConfig) { c.Context = "in-cluster" }},
		{"missing transport marker", func(c *TargetConfig) { c.NATSExposureFixture.Transport = "" }},
		{"kubeconfig in explicit mode", func(c *TargetConfig) { c.Kubeconfig = "/tmp/not-used" }},
		{"missing cluster pin", func(c *TargetConfig) { c.NATSExposureFixture.ClusterUID = "" }},
		{"other fixture", func(c *TargetConfig) { c.InstalledManagerFixture = &InstalledManagerFixtureConfig{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := base
			fixture := *base.NATSExposureFixture
			copy.NATSExposureFixture = &fixture
			tc.change(&copy)
			if err := validateNATSExposureFixture(copy); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}
