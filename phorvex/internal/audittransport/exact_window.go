package audittransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

const MaxExactScanBytes int64 = 128 << 20
const MaxExactRows = 256
const MaxExactReturnedBytes = 4 << 20
const maxExactLineBytes = 256 << 10

// ExactWindowRequest is one immutable, newline-aligned interval within one
// manifest generation. Rotation across segments is an audit gap for this API.
type ExactWindowRequest struct {
	Segment     Segment `json:"segment"`
	StartOffset int64   `json:"startOffset"`
	EndOffset   int64   `json:"endOffset"`
	Namespace   string  `json:"namespace"`
	PodName     string  `json:"podName"`
	PodUID      string  `json:"podUID"`
	PolicyUID   string  `json:"policyUID"`
}

type ExactRow struct {
	Offset    int64  `json:"offset"`
	EndOffset int64  `json:"endOffset"`
	SHA256    string `json:"sha256"`
	Raw       []byte `json:"raw"`
}

type ExactWindowSeal struct {
	Segment        Segment    `json:"segment"`
	StartOffset    int64      `json:"startOffset"`
	EndOffset      int64      `json:"endOffset"`
	CoveredThrough int64      `json:"coveredThrough"`
	ScanSHA256     string     `json:"scanSHA256"`
	Namespace      string     `json:"namespace"`
	PodName        string     `json:"podName"`
	PodUID         string     `json:"podUID"`
	PolicyUID      string     `json:"policyUID"`
	Rows           []ExactRow `json:"rows"`
}

func exactDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validExactRequest(q ExactWindowRequest) error {
	if q.Segment.ID == "" || q.Segment.Generation == "" || len(q.Segment.Anchor) != 32 ||
		q.Segment.Size < 0 || q.StartOffset < 0 || q.EndOffset <= q.StartOffset ||
		q.EndOffset > q.Segment.Size || q.EndOffset-q.StartOffset > MaxExactScanBytes ||
		q.Namespace == "" || q.PodName == "" || q.PodUID == "" || q.PolicyUID == "" ||
		len(q.Namespace) > 253 || len(q.PodName) > 253 || len(q.PodUID) > 253 || len(q.PolicyUID) > 253 ||
		strings.ContainsAny(q.Namespace+q.PodName+q.PodUID+q.PolicyUID, "\x00\r\n") {
		return errors.New("invalid exact audit window")
	}
	if _, err := hex.DecodeString(q.Segment.Anchor); err != nil || strings.ToLower(q.Segment.Anchor) != q.Segment.Anchor {
		return errors.New("invalid audit anchor")
	}
	return nil
}

func lineBoundary(f *os.File, off int64) bool {
	if off == 0 {
		return true
	}
	var b [1]byte
	_, err := f.ReadAt(b[:], off-1)
	return err == nil && b[0] == '\n'
}

// strictObject rejects duplicate JSON keys, including nested keys. A malformed
// unrelated row cannot be assumed unrelated and silently excluded.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		if depth > 64 {
			return nil, errors.New("audit JSON nesting exceeds bound")
		}
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch tok {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := key.(string)
				if !ok {
					return nil, errors.New("non-string JSON key")
				}
				if _, exists := m[k]; exists {
					return nil, errors.New("duplicate JSON key")
				}
				v, err := walk(depth + 1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := d.Token()
			return m, err
		case json.Delim('['):
			for d.More() {
				if _, err := walk(depth + 1); err != nil {
					return nil, err
				}
			}
			_, err := d.Token()
			return true, err
		default:
			return tok, nil
		}
	}
	if _, err := walk(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("audit line is not an object")
	}
	return fields, nil
}

func exactString(fields map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(fields[key], &value)
	return value
}

func requiredExactString(fields map[string]json.RawMessage, key string) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", errors.New("audit identity field missing")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", errors.New("audit identity field malformed")
	}
	return value, nil
}

func exactTarget(raw []byte, q ExactWindowRequest) (bool, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return false, err
	}
	kind, err := requiredExactString(fields, "kind")
	if err != nil {
		return false, err
	}
	if kind != "phorvex.decision" {
		return false, nil
	}
	namespace, err := requiredExactString(fields, "namespace")
	if err != nil {
		return false, err
	}
	if namespace != q.Namespace {
		return false, nil
	}
	podName, err := requiredExactString(fields, "pod")
	if err != nil {
		return false, err
	}
	var trace map[string]json.RawMessage
	if err := json.Unmarshal(fields["decisionTrace"], &trace); err != nil || trace == nil {
		return false, errors.New("same-namespace decision lacks exact trace identity")
	}
	assetNS := exactString(trace, "assetNamespace")
	assetUID := exactString(trace, "assetUID")
	policyUID := exactString(trace, "policyUID")
	if assetNS == "" || assetUID == "" || policyUID == "" || assetNS != q.Namespace {
		return false, errors.New("same-namespace decision has ambiguous identity")
	}
	if podName == q.PodName && assetUID != q.PodUID {
		return false, errors.New("same-name replacement in exact audit window")
	}
	if assetUID == q.PodUID && (podName != q.PodName || policyUID != q.PolicyUID) {
		return false, errors.New("target Pod decision has different name or policy UID")
	}
	return podName == q.PodName && assetUID == q.PodUID && policyUID == q.PolicyUID, nil
}

func scanExact(ctx context.Context, f *os.File, q ExactWindowRequest) (ExactWindowSeal, error) {
	if err := validExactRequest(q); err != nil {
		return ExactWindowSeal{}, err
	}
	if !lineBoundary(f, q.StartOffset) || !lineBoundary(f, q.EndOffset) {
		return ExactWindowSeal{}, errors.New("audit window has partial line boundary")
	}
	section := io.NewSectionReader(f, q.StartOffset, q.EndOffset-q.StartOffset)
	scanner := bufio.NewScanner(section)
	scanner.Buffer(make([]byte, 64<<10), maxExactLineBytes)
	seal := ExactWindowSeal{Segment: q.Segment, StartOffset: q.StartOffset, EndOffset: q.EndOffset,
		Namespace: q.Namespace, PodName: q.PodName, PodUID: q.PodUID, PolicyUID: q.PolicyUID, Rows: []ExactRow{}}
	h := sha256.New()
	off := q.StartOffset
	returned := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return ExactWindowSeal{}, err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			return ExactWindowSeal{}, errors.New("empty audit line")
		}
		end := off + int64(len(line)) + 1
		if end > q.EndOffset {
			return ExactWindowSeal{}, errors.New("audit line exceeds window")
		}
		_, _ = h.Write(line)
		_, _ = h.Write([]byte{'\n'})
		match, err := exactTarget(line, q)
		if err != nil {
			return ExactWindowSeal{}, err
		}
		if match {
			returned += len(line)
			if len(seal.Rows) >= MaxExactRows || returned > MaxExactReturnedBytes {
				return ExactWindowSeal{}, errors.New("exact audit rows exceed bound")
			}
			seal.Rows = append(seal.Rows, ExactRow{Offset: off, EndOffset: end, SHA256: exactDigest(line), Raw: bytes.Clone(line)})
		}
		off = end
	}
	if err := scanner.Err(); err != nil {
		return ExactWindowSeal{}, err
	}
	if off != q.EndOffset {
		return ExactWindowSeal{}, errors.New("audit coverage gap")
	}
	seal.CoveredThrough = off
	seal.ScanSHA256 = hex.EncodeToString(h.Sum(nil))
	return seal, nil
}

func verifyExactWindow(ctx context.Context, f *os.File, q ExactWindowRequest, want string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, q.StartOffset, q.EndOffset-q.StartOffset)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("audit bytes changed during exact scan")
	}
	return nil
}
