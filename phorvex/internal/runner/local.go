package runner

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// LocalServices are the brain, sensor and actuator this process runs itself, for
// each one no endpoint names (ADR-0001). cmd composes them (internal/inprocess); the
// runner reaches them only through their contracts, as it reaches a remote service.
type LocalServices interface {
	// Validate checks the in-process services' startup invariants.
	Validate() error
	Brain() brainapi.Brain
	// Sensor observes the cluster through c and the readers.
	Sensor(c client.Client, ownership, boundary client.Reader, promURL string) sensorapi.Sensor
	// Actuation acts on the cluster, nil when no backend is wired.
	Actuation(boundary client.Reader, operatorNamespace string, access *authz.Checker) actuatorapi.Actuator
}
