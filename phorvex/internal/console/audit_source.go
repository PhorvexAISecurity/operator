package console

import (
	"context"
	"errors"
	"github.com/phorvex/phorvex/internal/audittransport"
	"strings"
)

// openDecisionSource pins a fresh, authenticated generation/size for one read.
// Local standalone mode retains the existing regular-file safeguards.
func openDecisionSource(ctx context.Context, path string, source *audittransport.Client) (auditHandle, error) {
	if source == nil {
		return openAuditFile(path)
	}
	if !strings.HasPrefix(path, "audit://") {
		return nil, errors.New("remote audit path is not a fixed segment identifier")
	}
	id := strings.TrimPrefix(path, "audit://")
	m, e := source.Manifest(ctx)
	if e != nil {
		return nil, e
	}
	for _, seg := range m.Segments {
		if seg.ID == id {
			return source.Open(ctx, seg), nil
		}
	}
	return nil, errors.New("configured provider audit segment unavailable")
}
