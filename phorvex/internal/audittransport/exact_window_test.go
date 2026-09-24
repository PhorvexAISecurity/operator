package audittransport

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func exactFixtureRows() (all []byte, target []byte, start, end int64) {
	first := []byte(`{"kind":"phorvex.decision","namespace":"other","pod":"other","decisionTrace":{"assetNamespace":"other","assetUID":"other-uid","policyUID":"policy"}}`)
	target = []byte(`{"schemaVersion":"phorvex.audit.v2","kind":"phorvex.decision","namespace":"voice","pod":"source","decisionTrace":{"decisionID":"decision-1","assetNamespace":"voice","assetUID":"pod-uid","policyUID":"policy-uid"},"action":"noop","selected":true,"dispatchOutcome":"not-attempted"}`)
	last := []byte(`{"kind":"phorvex.decision","namespace":"voice","pod":"peer","decisionTrace":{"assetNamespace":"voice","assetUID":"peer-uid","policyUID":"policy-uid"}}`)
	all = append(append(append(append(append([]byte{}, first...), '\n'), target...), '\n'), last...)
	all = append(all, '\n')
	return all, target, int64(len(first) + 1), int64(len(all))
}

func exactRequest(t *testing.T, path string, start, end int64) ExactWindowRequest {
	t.Helper()
	f, err := regular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gen, size, anchor, err := generation(f)
	if err != nil {
		t.Fatal(err)
	}
	return ExactWindowRequest{Segment: Segment{ID: "live", Generation: gen, Size: size, Anchor: anchor},
		StartOffset: start, EndOffset: end, Namespace: "voice", PodName: "source", PodUID: "pod-uid", PolicyUID: "policy-uid"}
}

func committedExact(t *testing.T, client *Client, q ExactWindowRequest) ExactWindowRequest {
	t.Helper()
	c, err := client.CaptureExactWindow(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	q.Commitment = &c
	return q
}

func TestExactWindowAuthenticatedProducerAndClient(t *testing.T) {
	_, client, path, _, _, _ := fixture(t)
	all, target, start, end := exactFixtureRows()
	if err := os.WriteFile(path, all, 0600); err != nil {
		t.Fatal(err)
	}
	q := committedExact(t, client, exactRequest(t, path, start, end))
	seal, err := client.SelectExact(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if seal.CoveredThrough != end || seal.StartOffset != start || len(seal.Rows) != 1 ||
		seal.Rows[0].Offset != start || !bytes.Equal(seal.Rows[0].Raw, target) ||
		seal.ScanSHA256 != exactDigest(all[start:end]) {
		t.Fatalf("incorrect exact producer/client seal: %+v", seal)
	}
	for _, change := range []func(*ExactWindowSeal){
		func(s *ExactWindowSeal) { s.CoveredThrough-- },
		func(s *ExactWindowSeal) { s.Rows[0].Raw[0] = '!' },
		func(s *ExactWindowSeal) { s.Rows[0].Offset++ },
		func(s *ExactWindowSeal) { s.PodUID = "foreign" },
	} {
		copySeal := seal
		copySeal.Rows = append([]ExactRow(nil), seal.Rows...)
		copySeal.Rows[0].Raw = bytes.Clone(seal.Rows[0].Raw)
		change(&copySeal)
		if err := validateExactSeal(q, copySeal); err == nil {
			t.Fatal("forged exact audit seal accepted")
		}
	}
	partial := q
	partial.Commitment = nil
	partial.StartOffset++
	if _, err := client.CaptureExactWindow(context.Background(), partial); err == nil {
		t.Fatal("partial start boundary accepted")
	}
	partial = q
	partial.Commitment = nil
	partial.EndOffset--
	if _, err := client.CaptureExactWindow(context.Background(), partial); err == nil {
		t.Fatal("partial end boundary accepted")
	}
	if _, err := client.SelectExact(context.Background(), ExactWindowRequest{Segment: q.Segment,
		StartOffset: start, EndOffset: end, Namespace: "voice", PodName: "source", PodUID: "pod-uid", PolicyUID: "policy-uid"}); err == nil {
		t.Fatal("selection without observation-end commitment accepted")
	}
}

func TestExactWindowMalformedAmbiguousAndRotation(t *testing.T) {
	_, client, path, _, _, _ := fixture(t)
	all, _, start, end := exactFixtureRows()
	var q ExactWindowRequest
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"malformed-unrelated", append([]byte("{bad}\n"), all...)},
		{"same-namespace-missing-trace", append([]byte(`{"kind":"phorvex.decision","namespace":"voice"}`+"\n"), all...)},
		{"target-other-policy", bytes.Replace(all, []byte(`"policyUID":"policy-uid"`), []byte(`"policyUID":"foreign"`), 1)},
		{"same-name-replacement", append([]byte(`{"kind":"phorvex.decision","namespace":"voice","pod":"source","decisionTrace":{"assetNamespace":"voice","assetUID":"replacement-uid","policyUID":"policy-uid"}}`+"\n"), all...)},
		{"duplicate-target-identity", bytes.Replace(all, []byte(`"assetUID":"pod-uid"`), []byte(`"assetUID":"pod-uid","assetUID":"peer-uid"`), 1)},
		{"casefold-alias", bytes.Replace(all, []byte(`"namespace":"voice"`), []byte(`"namespace":"voice","Namespace":"other"`), 1)},
		{"unicode-casefold-alias", bytes.Replace(all, []byte(`"namespace":"voice"`), []byte(`"namespace":"voice","nameſpace":"other"`), 1)},
		{"cross-namespace-trace", bytes.Replace(all, []byte(`"namespace":"voice","pod":"source"`), []byte(`"namespace":"other","pod":"source"`), 1)},
		{"foreign-namespace-target-uid", bytes.Replace(all, []byte(`"namespace":"voice","pod":"source","decisionTrace":{"decisionID":"decision-1","assetNamespace":"voice"`), []byte(`"namespace":"other","pod":"source","decisionTrace":{"decisionID":"decision-1","assetNamespace":"other"`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.body, 0600); err != nil {
				t.Fatal(err)
			}
			q = committedExact(t, client, exactRequest(t, path, 0, int64(len(tc.body))))
			if _, err := client.SelectExact(context.Background(), q); err == nil {
				t.Fatal("ambiguous source accepted")
			}
		})
	}
	if err := os.WriteFile(path, all, 0600); err != nil {
		t.Fatal(err)
	}
	q = committedExact(t, client, exactRequest(t, path, start, end))
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SelectExact(context.Background(), q); err == nil {
		t.Fatal("source rewrite accepted")
	}
	if err := os.WriteFile(path, all, 0600); err != nil {
		t.Fatal(err)
	}
	q = committedExact(t, client, exactRequest(t, path, start, end))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, all, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SelectExact(context.Background(), q); err == nil {
		t.Fatal("rotation accepted")
	}
}

func TestExactWindowBoundsAndClientRowValidation(t *testing.T) {
	_, _, path, _, _, _ := fixture(t)
	all, _, start, end := exactFixtureRows()
	if err := os.WriteFile(path, all, 0600); err != nil {
		t.Fatal(err)
	}
	q := exactRequest(t, path, start, end)
	f, err := regular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := scanExact(context.Background(), f, q); err != nil {
		t.Fatal(err)
	}
	q.EndOffset = q.StartOffset + MaxExactScanBytes + 1
	q.Segment.Size = q.EndOffset
	if err := validExactRequest(q); err == nil {
		t.Fatal("oversize scan accepted")
	}
	long := []byte(`{"kind":"phorvex.decision","namespace":"other","x":"` + strings.Repeat("a", maxExactLineBytes) + `"}` + "\n")
	if err := os.WriteFile(path, long, 0600); err != nil {
		t.Fatal(err)
	}
	q = exactRequest(t, path, 0, int64(len(long)))
	if _, err := scanExact(context.Background(), f, q); err == nil {
		t.Fatal("oversize line accepted")
	}
	_, target, _, _ := exactFixtureRows()
	var many bytes.Buffer
	for i := 0; i <= MaxExactRows; i++ {
		many.Write(target)
		many.WriteByte('\n')
	}
	if err := os.WriteFile(path, many.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	q = exactRequest(t, path, 0, int64(many.Len()))
	if _, err := scanExact(context.Background(), f, q); err == nil {
		t.Fatal("target row overflow accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanExact(canceled, f, q); err == nil {
		t.Fatal("canceled scan accepted")
	}
}

func TestExactWindowCommitmentRejectsPrescanRewriteAndAllowsAppend(t *testing.T) {
	_, client, path, _, _, _ := fixture(t)
	_, target, _, _ := exactFixtureRows()
	pad := []byte(`{"kind":"phorvex.maintenance","pad":"` + strings.Repeat("x", 320) + `"}` + "\n")
	original := append(append(bytes.Clone(pad), target...), '\n')
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	q := committedExact(t, client, exactRequest(t, path, int64(len(pad)), int64(len(original))))
	changed := bytes.Replace(original, []byte(`"decisionID":"decision-1"`), []byte(`"decisionID":"decision-2"`), 1)
	if len(changed) != len(original) || bytes.Equal(changed, original) {
		t.Fatal("invalid rewrite fixture")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("rewrite did not preserve inode")
	}
	if _, err := client.SelectExact(context.Background(), q); err == nil {
		t.Fatal("pre-scan same-inode rewrite accepted")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	q = committedExact(t, client, exactRequest(t, path, int64(len(pad)), int64(len(original))))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"kind":"phorvex.maintenance","note":"later"}` + "\n")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SelectExact(context.Background(), q); err != nil {
		t.Fatalf("ordinary append after committed end was rejected: %v", err)
	}
}
