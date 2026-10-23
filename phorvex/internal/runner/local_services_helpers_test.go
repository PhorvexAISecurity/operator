package runner

import (
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
)

// localServices is m's in-process services, created empty when m has none.
func localServices(m *Manager) *inprocess.Services {
	if m.Local == nil {
		s := &inprocess.Services{}
		m.Local = s
		return s
	}
	return m.Local.(*inprocess.Services)
}

// newManagerWithBackend composes a manager as cmd does: the default in-process
// services on an already-resolved backend.
func newManagerWithBackend(c client.Client, log logr.Logger, res actuator.BackendResolution) (*Manager, error) {
	services, err := inprocess.New(c, log, res)
	if err != nil {
		return nil, err
	}
	return New(c, log, services), nil
}

// newManager composes a manager on the backend PHORVEX_ACTUATOR names.
func newManager(c client.Client, log logr.Logger) (*Manager, error) {
	res, err := actuator.ResolveBackendFromEnv()
	if err != nil {
		return nil, err
	}
	return newManagerWithBackend(c, log, res)
}
