package config

import (
	"errors"
	"path/filepath"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation"
)

// MongoExposureFixture is server-owned. Only RunID and Nonce change per run;
// neither a browser nor a generic scenario may supply a target or payload.
type MongoExposureFixtureConfig struct {
	RunID             string   `json:"runID"`
	Nonce             string   `json:"nonce"`
	Transport         string   `json:"transport"`
	ClusterUID        string   `json:"clusterUID"`
	MongoDeployment   string   `json:"mongoDeployment"`
	MongoService      string   `json:"mongoService"`
	MongoImageID      string   `json:"mongoImageID"`
	PolicyName        string   `json:"policyName"`
	ManagerNamespace  string   `json:"managerNamespace"`
	ManagerDeployment string   `json:"managerDeployment"`
	ManagerImageID    string   `json:"managerImageID"`
	AllowedNodeNames  []string `json:"allowedNodeNames"`
	MaxRunSeconds     int      `json:"maxRunSeconds"`
}

var mongoNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var mongoRunID = regexp.MustCompile(`^run-[1-9][0-9]*$`)
var mongoImage = regexp.MustCompile(`^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$`)

func validateMongoExposureFixture(c TargetConfig) error {
	f := c.MongoExposureFixture
	if f == nil {
		return nil
	}
	if c.Namespace != "document-store" || c.ExpectedNamespaceUID != "" || c.Kubeconfig != "" || c.Context == "" || c.Context == "in-cluster" || f.Transport != "in-cluster" {
		return errors.New("config: Mongo exposure requires the fixed existing document-store namespace, logical target and explicit in-cluster transport")
	}
	if !filepath.IsAbs(c.OutDir) || filepath.Clean(c.OutDir) != c.OutDir {
		return errors.New("config: Mongo exposure output directory must be exact and absolute")
	}
	if !mongoRunID.MatchString(f.RunID) || !mongoNonce.MatchString(f.Nonce) || !kubernetesUIDPattern.MatchString(f.ClusterUID) {
		return errors.New("config: Mongo exposure requires server-generated run, nonce and exact cluster UID")
	}
	if c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 1 || c.ScenarioFilter[0] != "c2-mongo-uncredentialed-service-exposure" || len(c.DefenderFilter) != 0 || f.MaxRunSeconds < 120 || f.MaxRunSeconds > 600 {
		return errors.New("config: Mongo exposure requires one bounded unscored dedicated case")
	}
	if c.NATSExposureFixture != nil || c.NATSJetStreamFixture != nil || c.GPUFunctionalFixture != nil || c.NativeRouteFixture != nil || c.BenignCheckpointLocalFixture {
		return errors.New("config: Mongo exposure cannot share another external fixture")
	}
	if f.MongoDeployment != "mongo" || f.MongoService != "mongo" || f.PolicyName != "mongo-defense" || f.ManagerNamespace == "" || f.ManagerDeployment == "" ||
		len(validation.IsDNS1123Subdomain(f.ManagerNamespace)) != 0 || len(validation.IsDNS1123Subdomain(f.ManagerDeployment)) != 0 ||
		!mongoImage.MatchString(f.MongoImageID) || !mongoImage.MatchString(f.ManagerImageID) {
		return errors.New("config: Mongo exposure source identities and images must be fixed and digest pinned")
	}
	if len(f.AllowedNodeNames) < 1 || len(f.AllowedNodeNames) > 4 {
		return errors.New("config: Mongo exposure requires one to four server-owned CPU node names")
	}
	seen := map[string]bool{}
	for _, name := range f.AllowedNodeNames {
		if len(validation.IsDNS1123Subdomain(name)) != 0 || seen[name] {
			return errors.New("config: Mongo exposure CPU node name invalid or duplicate")
		}
		seen[name] = true
	}
	return nil
}
