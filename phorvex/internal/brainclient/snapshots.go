package brainclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/brainpb"
	"google.golang.org/grpc"
)

var _ audittransport.MathLabSnapshotSource = (*Client)(nil)

// SnapshotSource is a read-only relay, not a cached capability decision. Each
// request is checked by the serving brain, so an older or capture-disabled
// process fails closed while a later enabled process can serve after reconnect.
func (c *Client) SnapshotSource() audittransport.MathLabSnapshotSource {
	if c == nil {
		return nil
	}
	return c
}

func (c *Client) IndexJSON(q audittransport.MathLabSnapshotQuery) ([]byte, error) {
	if c.SnapshotSource() == nil {
		return nil, fmt.Errorf("remote math-lab capture unavailable")
	}
	q, err := audittransport.ValidateMathLabSnapshotQuery(q)
	if err != nil {
		return nil, err
	}
	req := &brainpb.ListSnapshotsRequest{PolicyUid: q.PolicyUID, Namespace: q.Namespace, Policy: q.Policy, Limit: uint32(q.Limit)}
	if !q.Since.IsZero() {
		req.Since = q.Since.UTC().Format(time.RFC3339Nano)
	}
	if !q.Until.IsZero() {
		req.Until = q.Until.UTC().Format(time.RFC3339Nano)
	}
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.ListSnapshots(ctx, req, grpc.MaxCallRecvMsgSize(audittransport.MathLabMaxIndexBytes+1024))
	if err != nil {
		return nil, err
	}
	raw := resp.GetIndexJson()
	if len(raw) > audittransport.MathLabMaxIndexBytes || !json.Valid(raw) {
		return nil, fmt.Errorf("remote math-lab index is invalid or oversized")
	}
	return raw, nil
}

func (c *Client) Read(digest string) ([]byte, error) {
	if c.SnapshotSource() == nil {
		return nil, fmt.Errorf("remote math-lab capture unavailable")
	}
	if !audittransport.ValidMathLabSnapshotDigest(digest) {
		return nil, fmt.Errorf("invalid snapshot digest")
	}
	ctx, cancel := c.call()
	defer cancel()
	stream, err := c.rpc.ReadSnapshot(ctx, &brainpb.ReadSnapshotRequest{Digest: digest}, grpc.MaxCallRecvMsgSize((1<<20)+1024))
	if err != nil {
		return nil, err
	}
	raw := []byte{}
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data := chunk.GetData()
		if len(data) == 0 || len(data) > 1<<20 || len(raw)+len(data) > audittransport.MathLabMaxSnapshotBytes {
			return nil, fmt.Errorf("remote snapshot exceeds stream bounds")
		}
		raw = append(raw, data...)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("remote snapshot content address mismatch")
	}
	return raw, nil
}
