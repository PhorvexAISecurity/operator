package runner

import (
	"context"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

func init() {
	m158ConfigureRuntimeVocabulary = func(ctx context.Context, m *Manager, reader client.Reader, now time.Time) error {
		m.VocabularyReader = reader
		return nil
	}
}
