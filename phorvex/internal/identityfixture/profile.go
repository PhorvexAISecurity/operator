// Package identityfixture is an explicitly enabled CONSOLE/TEST producer. It
// grants no capability to ordinary tenant workloads and changes no brain scores.
package identityfixture

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const ProfileEnv = "PHORVEX_CONSOLE_IDENTITY_FIXTURE"
const Label = "phorvex.ai/console-identity-fixture"
const Image = "docker.io/library/python@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
const Mount = "/var/run/secrets/kubernetes.io/serviceaccount"

var Command = []string{"python3", "-c", "import time; time.sleep(1800)"}

// This root-owned deployment input must be mounted into both Console and the
// operator. A namespace label, request body or tenant ConfigMap cannot enable it.
// NamespaceUID admits one owner-provisioned, otherwise unused test namespace.
type Profile struct {
	JournalNamespace string `json:"journalNamespace"`
	Namespace        string `json:"namespace"`
	NamespaceUID     string `json:"namespaceUID"`
	PolicyName       string `json:"policyName"`
	PolicyUID        string `json:"policyUID"`
	PolicyGeneration int64  `json:"policyGeneration"`
	Cluster          string `json:"eksCluster"`
	Region           string `json:"awsRegion"`
}

func Load() (Profile, error) {
	var p Profile
	path := strings.TrimSpace(os.Getenv(ProfileEnv))
	if path == "" {
		return p, errors.New("Console/test identity fixture profile not installed")
	}
	f, err := os.Open(path)
	if err != nil {
		return p, errors.New("Console/test identity fixture profile not installed")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 8193))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Validate() != nil {
		return Profile{}, errors.New("invalid Console/test identity fixture profile")
	}
	return p, nil
}
func (p Profile) Validate() error {
	if !strings.HasPrefix(p.Namespace, NamespacePrefix) || len(validation.IsDNS1123Label(p.Namespace)) != 0 ||
		p.NamespaceUID == "" || p.PolicyUID == "" || p.PolicyGeneration <= 0 || len(validation.IsDNS1123Subdomain(p.PolicyName)) != 0 || p.PolicyName == "" ||
		p.JournalNamespace == "" || p.JournalNamespace == p.Namespace || p.Cluster == "" || p.Region == "" || strings.HasPrefix(p.Cluster, "-") || strings.HasPrefix(p.Region, "-") {
		return errors.New("exact owned Console/test namespace, policy and EKS pins required")
	}
	return nil
}

func NoFederation(p *corev1.Pod, sa *corev1.ServiceAccount) bool {
	if _, ok := sa.Annotations["eks.amazonaws.com/role-arn"]; ok {
		return false
	}
	for _, v := range p.Spec.Volumes {
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil && s.ServiceAccountToken.Audience != "" {
					return false
				}
			}
		}
	}
	for _, c := range p.Spec.Containers {
		for _, e := range c.Env {
			if strings.HasPrefix(e.Name, "AWS_") {
				return false
			}
		}
	}
	return true
}
