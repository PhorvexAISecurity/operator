package runner

import (
	"context"
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

func init() {
	m158ConfigureRuntimeVocabulary = func(ctx context.Context, m *Manager, reader client.Reader, now time.Time) error {
		m.VocabularyReader = reader
		observed := m.refreshVocabulary(ctx, now)
		if !observed.Known {
			return fmt.Errorf("runtime action vocabulary remained unverified: %s", observed.Error)
		}
		return nil
	}
}
