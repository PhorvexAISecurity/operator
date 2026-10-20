package brainapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// ContractVersion is the dispatcher-brain contract a build speaks. A brain refuses
// a client built against another version.
const ContractVersion = 2

// DecisionConfig is the process configuration that changes decisions. The
// dispatcher and a separate brain must agree on it, or a tick would be decided
// under settings the operator did not deploy.
type DecisionConfig struct {
	Engine                  string
	ReconProfile            string
	GPUEnvelopeMax          float64
	FlowResidualClasses     []string
	ParameterManifestSHA256 string
}

// SHA256 identifies the configuration. Flow-residual classes are compared as a set.
func (c DecisionConfig) SHA256() string {
	set := map[string]struct{}{}
	for _, class := range c.FlowResidualClasses {
		if class = strings.TrimSpace(class); class != "" {
			set[class] = struct{}{}
		}
	}
	classes := make([]string, 0, len(set))
	for class := range set {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	c.FlowResidualClasses = classes
	raw, err := json.Marshal(c)
	if err != nil {
		panic(err) // the struct holds only strings and a float
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
