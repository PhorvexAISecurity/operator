package brainsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/brainpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ServerOption func(*Server)

// WithSnapshotSource is set only during construction, before serving requests.
// It shares the recorder's existing store; it does not enable capture itself.
func WithSnapshotSource(source audittransport.MathLabSnapshotSource) ServerOption {
	return func(s *Server) { s.snapshots = source }
}

func (s *Server) ListSnapshots(ctx context.Context, req *brainpb.ListSnapshotsRequest) (*brainpb.ListSnapshotsResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if s.snapshots == nil {
		return nil, status.Error(codes.Unavailable, "math-lab capture is not enabled")
	}
	q := audittransport.MathLabSnapshotQuery{PolicyUID: req.GetPolicyUid(), Namespace: req.GetNamespace(), Policy: req.GetPolicy(), Limit: int(req.GetLimit())}
	for name, pair := range map[string]struct {
		raw string
		dst *time.Time
	}{"since": {req.GetSince(), &q.Since}, "until": {req.GetUntil(), &q.Until}} {
		if pair.raw == "" {
			continue
		}
		value, err := time.Parse(time.RFC3339Nano, pair.raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid %s", name)
		}
		*pair.dst = value
	}
	q, err := audittransport.ValidateMathLabSnapshotQuery(q)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	raw, err := s.snapshots.IndexJSON(q)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "math-lab index unavailable")
	}
	if len(raw) > audittransport.MathLabMaxIndexBytes {
		return nil, status.Error(codes.ResourceExhausted, "math-lab index exceeds transport bound")
	}
	if !json.Valid(raw) {
		return nil, status.Error(codes.DataLoss, "math-lab index is invalid JSON")
	}
	return &brainpb.ListSnapshotsResponse{IndexJson: raw}, nil
}

func (s *Server) ReadSnapshot(req *brainpb.ReadSnapshotRequest, stream brainpb.BrainService_ReadSnapshotServer) error {
	if err := stream.Context().Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	if s.snapshots == nil {
		return status.Error(codes.Unavailable, "math-lab capture is not enabled")
	}
	digest := req.GetDigest()
	if !audittransport.ValidMathLabSnapshotDigest(digest) {
		return status.Error(codes.InvalidArgument, "invalid snapshot digest")
	}
	raw, err := s.snapshots.Read(digest)
	if errors.Is(err, os.ErrNotExist) {
		return status.Error(codes.NotFound, "snapshot unavailable")
	}
	if err != nil {
		return status.Error(codes.Unavailable, "snapshot unavailable")
	}
	if len(raw) > audittransport.MathLabMaxSnapshotBytes {
		return status.Error(codes.ResourceExhausted, "snapshot exceeds transport bound")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return status.Error(codes.DataLoss, "snapshot content address mismatch")
	}
	const chunkBytes = 1 << 20
	for offset := 0; offset < len(raw); offset += chunkBytes {
		end := min(offset+chunkBytes, len(raw))
		if err := stream.Send(&brainpb.ReadSnapshotResponse{Data: raw[offset:end]}); err != nil {
			return err
		}
	}
	return nil
}
