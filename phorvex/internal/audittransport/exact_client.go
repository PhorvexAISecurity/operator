package audittransport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SelectExact obtains the authenticated producer's complete-interval seal. The
// client checks every returned original row and the response's exact window;
// the scan hash is a source attestation, not a client-side recomputation.
func (c *Client) SelectExact(ctx context.Context, q ExactWindowRequest) (ExactWindowSeal, error) {
	if err := validExactRequest(q); err != nil {
		return ExactWindowSeal{}, err
	}
	if err := validExactCommitment(q); err != nil {
		return ExactWindowSeal{}, err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return ExactWindowSeal{}, err
	}
	resp, err := c.request(ctx, http.MethodPost, "/v1/exact-window", bytes.NewReader(raw), 65*time.Second)
	if err != nil {
		return ExactWindowSeal{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ExactWindowSeal{}, fmt.Errorf("exact audit window unavailable: HTTP %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Audit-Generation") != q.Segment.Generation {
		return ExactWindowSeal{}, errors.New("exact audit generation header differs")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxExactReturnedBytes*2+65536+1))
	if err != nil || len(body) > MaxExactReturnedBytes*2+65536 {
		return ExactWindowSeal{}, errors.New("exact audit response exceeds bound")
	}
	var seal ExactWindowSeal
	if _, err := strictObject(body); err != nil {
		return ExactWindowSeal{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&seal); err != nil {
		return ExactWindowSeal{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ExactWindowSeal{}, errors.New("trailing or oversized exact audit response")
	}
	if err := validateExactSeal(q, seal); err != nil {
		return ExactWindowSeal{}, err
	}
	return seal, nil
}

func validateExactSeal(q ExactWindowRequest, seal ExactWindowSeal) error {
	if seal.Segment != q.Segment || seal.StartOffset != q.StartOffset || seal.EndOffset != q.EndOffset ||
		seal.CoveredThrough != q.EndOffset || seal.Namespace != q.Namespace || seal.PodName != q.PodName || seal.PodUID != q.PodUID ||
		seal.PolicyUID != q.PolicyUID || len(seal.Rows) > MaxExactRows || len(seal.ScanSHA256) != 64 {
		return errors.New("exact audit seal identity or coverage differs")
	}
	if _, err := hex.DecodeString(seal.ScanSHA256); err != nil || strings.ToLower(seal.ScanSHA256) != seal.ScanSHA256 {
		return errors.New("invalid exact scan digest")
	}
	if seal.ScanSHA256 != q.Commitment.WindowSHA256 {
		return errors.New("exact audit scan differs from observation-end commitment")
	}
	previous := q.StartOffset
	returned := 0
	for _, row := range seal.Rows {
		returned += len(row.Raw)
		if row.Offset < previous || row.EndOffset > q.EndOffset || row.EndOffset != row.Offset+int64(len(row.Raw))+1 ||
			len(row.Raw) == 0 || returned > MaxExactReturnedBytes || exactDigest(row.Raw) != row.SHA256 {
			return errors.New("exact audit row bound or digest differs")
		}
		match, err := exactTarget(row.Raw, q)
		if err != nil || !match {
			return errors.New("exact audit row identity differs")
		}
		previous = row.EndOffset
	}
	return nil
}

// CaptureExactWindow must run at the declared observation end. Its authenticated
// result is retained before cleanup and supplied to a later SelectExact call.
func (c *Client) CaptureExactWindow(ctx context.Context, q ExactWindowRequest) (ExactWindowCommitment, error) {
	if err := validExactRequest(q); err != nil || q.Commitment != nil {
		return ExactWindowCommitment{}, errors.New("invalid exact commitment request")
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return ExactWindowCommitment{}, err
	}
	resp, err := c.request(ctx, http.MethodPost, "/v1/exact-commit", bytes.NewReader(raw), 65*time.Second)
	if err != nil {
		return ExactWindowCommitment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ExactWindowCommitment{}, fmt.Errorf("exact audit commitment unavailable: HTTP %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Audit-Generation") != q.Segment.Generation {
		return ExactWindowCommitment{}, errors.New("exact commitment generation differs")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2049))
	if err != nil || len(body) > 2048 {
		return ExactWindowCommitment{}, errors.New("exact commitment response bound")
	}
	if _, err := strictObject(body); err != nil {
		return ExactWindowCommitment{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var commitment ExactWindowCommitment
	if err := dec.Decode(&commitment); err != nil {
		return ExactWindowCommitment{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ExactWindowCommitment{}, errors.New("trailing exact commitment response")
	}
	check := q
	check.Commitment = &commitment
	if err := validExactCommitment(check); err != nil {
		return ExactWindowCommitment{}, err
	}
	if at := time.Unix(0, commitment.CapturedAtUnixNano); at.After(time.Now().Add(2*time.Second)) || time.Since(at) > 2*time.Minute {
		return ExactWindowCommitment{}, errors.New("exact commitment observation time differs")
	}
	return commitment, nil
}
