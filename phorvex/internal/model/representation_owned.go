package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// normalizeRepresentationString performs the same invalid-UTF-8 replacement as
// encoding/json before applying the audit redactor. Keeping it here makes the
// structural copy byte-compatible with the former JSON round trip.
func normalizeRepresentationString(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			out.WriteRune(utf8.RuneError)
			s = s[1:]
			continue
		}
		out.WriteString(s[:size])
		s = s[size:]
	}
	return out.String()
}

func representationString(s string, redact bool) string {
	s = normalizeRepresentationString(s)
	if redact {
		return redactTraceString(s)
	}
	return s
}

func representationStrings(in []string, redact bool) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i := range in {
		out[i] = representationString(in[i], redact)
	}
	return out
}

func representationScope(in ProtectedScope, redact bool) ProtectedScope {
	return ProtectedScope{
		Tenant: representationString(in.Tenant, redact), Property: representationString(in.Property, redact),
		Asset: representationString(in.Asset, redact), Version: representationString(in.Version, redact),
	}
}

func representationClaim(in *ClaimScope, redact bool) *ClaimScope {
	if in == nil {
		return nil
	}
	out := *in
	out.Scope = representationString(in.Scope, redact)
	out.DetectorSet = representationStrings(in.DetectorSet, redact)
	out.RecallCap = representationString(in.RecallCap, redact)
	out.Note = representationString(in.Note, redact)
	out.BrainImage = representationString(in.BrainImage, redact)
	out.GitSHA = representationString(in.GitSHA, redact)
	return &out
}

func representationGap(in RepresentationGap, redact bool) RepresentationGap {
	in.Scope = representationScope(in.Scope, redact)
	in.Kind = representationString(in.Kind, redact)
	in.Reason = representationString(in.Reason, redact)
	return in
}

func representationGaps(in []RepresentationGap, redact bool) []RepresentationGap {
	if in == nil {
		return nil
	}
	out := make([]RepresentationGap, len(in))
	for i := range in {
		out[i] = representationGap(in[i], redact)
	}
	return out
}

func representationFact(in RepresentationFact, redact bool) RepresentationFact {
	in.Key = representationString(in.Key, redact)
	in.Kind = representationString(in.Kind, redact)
	in.Scope = representationScope(in.Scope, redact)
	in.RuleVersion = representationString(in.RuleVersion, redact)
	in.ObservationRef = representationString(in.ObservationRef, redact)
	in.ReversibleCondition = representationString(in.ReversibleCondition, redact)
	in.Reason = representationString(in.Reason, redact)
	in.Actionability = representationStrings(in.Actionability, redact)
	return in
}

func representationFacts(in []RepresentationFact, redact bool) []RepresentationFact {
	if in == nil {
		return nil
	}
	out := make([]RepresentationFact, len(in))
	for i := range in {
		out[i] = representationFact(in[i], redact)
	}
	return out
}

func representationWitness(in LossWitness, redact bool) LossWitness {
	in.SchemaVersion = representationString(in.SchemaVersion, redact)
	in.EvidenceID = representationString(in.EvidenceID, redact)
	if in.PolicyEpoch != nil {
		copy := *in.PolicyEpoch
		copy.Namespace = representationString(copy.Namespace, redact)
		copy.Name = representationString(copy.Name, redact)
		copy.UID = representationString(copy.UID, redact)
		in.PolicyEpoch = &copy
	}
	if in.DecisionAsset != nil {
		copy := *in.DecisionAsset
		copy.Namespace = representationString(copy.Namespace, redact)
		copy.Name = representationString(copy.Name, redact)
		copy.TargetUID = representationString(copy.TargetUID, redact)
		in.DecisionAsset = &copy
	}
	if in.ImmediateController != nil {
		copy := representationObjectIdentity(*in.ImmediateController, redact)
		in.ImmediateController = &copy
	}
	if in.StableWorkloadOwner != nil {
		copy := representationObjectIdentity(*in.StableWorkloadOwner, redact)
		in.StableWorkloadOwner = &copy
	}
	if in.Classification != nil {
		copy := *in.Classification
		copy.RuleVersion = representationString(copy.RuleVersion, redact)
		copy.RuleDigest = representationString(copy.RuleDigest, redact)
		copy.ObserverClass = representationString(copy.ObserverClass, redact)
		copy.ObserverIdentity = representationString(copy.ObserverIdentity, redact)
		in.Classification = &copy
	}
	if in.Observation != nil {
		copy := *in.Observation
		copy.ExpectedSHA256 = representationString(copy.ExpectedSHA256, redact)
		copy.ObservedSHA256 = representationString(copy.ObservedSHA256, redact)
		in.Observation = &copy
	}
	in.CanonicalPayloadSHA256 = representationString(in.CanonicalPayloadSHA256, redact)
	in.SecurityEventUID = representationString(in.SecurityEventUID, redact)
	in.Scope = representationScope(in.Scope, redact)
	in.EventRef = representationString(in.EventRef, redact)
	in.EventTime = representationString(in.EventTime, redact)
	in.AdmissionTime = representationString(in.AdmissionTime, redact)
	in.IngestionTime = representationString(in.IngestionTime, redact)
	in.AuthenticatedIdentity = representationString(in.AuthenticatedIdentity, redact)
	in.TrustAtIngestionRef = representationString(in.TrustAtIngestionRef, redact)
	in.RuleVersion = representationString(in.RuleVersion, redact)
	in.PayloadPredicateRef = representationString(in.PayloadPredicateRef, redact)
	in.CompletedUnauthorizedOutcomeRef = representationString(in.CompletedUnauthorizedOutcomeRef, redact)
	in.IrreversibilitySemantics = representationString(in.IrreversibilitySemantics, redact)
	in.ClassificationRef = representationString(in.ClassificationRef, redact)
	return in
}

func representationObjectIdentity(in ObjectIdentity, redact bool) ObjectIdentity {
	in.APIVersion = representationString(in.APIVersion, redact)
	in.Kind = representationString(in.Kind, redact)
	in.Namespace = representationString(in.Namespace, redact)
	in.Name = representationString(in.Name, redact)
	in.UID = representationString(in.UID, redact)
	return in
}

func representationWitnesses(in []LossWitness, redact bool) []LossWitness {
	if in == nil {
		return nil
	}
	out := make([]LossWitness, len(in))
	for i := range in {
		out[i] = representationWitness(in[i], redact)
	}
	return out
}

func representationLosses(in []RetainedLoss, redact bool) []RetainedLoss {
	if in == nil {
		return nil
	}
	out := make([]RetainedLoss, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].ID = representationString(in[i].ID, redact)
		out[i].Scope = representationScope(in[i].Scope, redact)
		out[i].Witnesses = representationWitnesses(in[i].Witnesses, redact)
	}
	return out
}

func representationStringFloatMap(in map[string]float64, normalizeKeys bool) map[string]float64 {
	if in == nil {
		return nil
	}
	out := make(map[string]float64, len(in))
	if !normalizeKeys {
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	keys := make([]string, 0, len(in))
	invalidKey := false
	for k := range in {
		keys = append(keys, k)
		invalidKey = invalidKey || !utf8.ValidString(k)
	}
	if !invalidKey {
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := in[k]
		if normalizeKeys {
			k = normalizeRepresentationString(k)
		}
		out[k] = v
	}
	return out
}

func representationStringStringMap(in map[string]string, redact bool) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	invalidKey := false
	for k := range in {
		keys = append(keys, k)
		invalidKey = invalidKey || !utf8.ValidString(k)
	}
	if !invalidKey {
		for k, v := range in {
			out[k] = representationString(v, redact)
		}
		return out
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[normalizeRepresentationString(k)] = representationString(in[k], redact)
	}
	return out
}

func representationSets(in [][]string, redact bool) [][]string {
	if in == nil {
		return nil
	}
	out := make([][]string, len(in))
	for i := range in {
		out[i] = representationStrings(in[i], redact)
	}
	return out
}

func cloneRepresentationSnapshot(in RepresentationSnapshot, redact bool) RepresentationSnapshot {
	out := in
	out.Ref = representationString(in.Ref, redact)
	out.Scope = representationScope(in.Scope, redact)
	out.Aggregation = representationString(in.Aggregation, redact)
	out.PopulationVersion = representationString(in.PopulationVersion, redact)
	out.Claim = representationClaim(in.Claim, redact)
	out.DetectorBasis = representationString(in.DetectorBasis, redact)
	out.CapabilityStatus = representationString(in.CapabilityStatus, redact)
	out.CapabilityVersion = representationString(in.CapabilityVersion, redact)
	out.UnresolvedEntries = representationGaps(in.UnresolvedEntries, redact)
	out.UnknownKinds = representationGaps(in.UnknownKinds, redact)
	out.Facts = representationFacts(in.Facts, redact)
	out.Weights.SnapshotRef = representationString(in.Weights.SnapshotRef, redact)
	out.Weights.Basis = representationString(in.Weights.Basis, redact)
	out.Weights.ProvenanceRef = representationString(in.Weights.ProvenanceRef, redact)
	out.Weights.InvalidValues = representationStringStringMap(in.Weights.InvalidValues, redact)
	out.Weights.Values = representationStringFloatMap(in.Weights.Values, redact)
	out.ActionBasis = representationString(in.ActionBasis, redact)
	out.Covers.SnapshotRef = representationString(in.Covers.SnapshotRef, redact)
	out.Covers.Sets = representationSets(in.Covers.Sets, redact)
	out.Candidates.SnapshotRef = representationString(in.Candidates.SnapshotRef, redact)
	out.Candidates.Sets = representationSets(in.Candidates.Sets, redact)
	out.HistoryStatus = representationString(in.HistoryStatus, redact)
	out.HistoryPolicyUID = representationString(in.HistoryPolicyUID, redact)
	out.HistoryStableOwnerUID = representationString(in.HistoryStableOwnerUID, redact)
	out.LossMappingVersion = representationString(in.LossMappingVersion, redact)
	out.DispatchEvidence = representationString(in.DispatchEvidence, redact)
	out.LossAssessment = representationString(in.LossAssessment, redact)
	out.History = representationLosses(in.History, redact)
	out.Witnesses = representationWitnesses(in.Witnesses, redact)
	out.Limitations = representationStrings(in.Limitations, redact)
	return out
}

// CloneRepresentationSnapshot owns every mutable member. It is the structural
// equivalent of the former JSON freeze, including invalid-UTF-8 normalization.
func CloneRepresentationSnapshot(in RepresentationSnapshot) RepresentationSnapshot {
	return cloneRepresentationSnapshot(in, false)
}

func representationAmount(in RepresentationAmount, redact bool) RepresentationAmount {
	in.Reason = representationString(in.Reason, redact)
	if in.Value != nil {
		v := *in.Value
		in.Value = &v
	}
	return in
}

func representationCoverage(in RepresentationCoverage, redact bool) RepresentationCoverage {
	out := in
	out.Unit = representationString(in.Unit, redact)
	out.Covered = representationAmount(in.Covered, redact)
	out.Representable = representationAmount(in.Representable, redact)
	out.Coverable = representationAmount(in.Coverable, redact)
	out.Share = representationAmount(in.Share, redact)
	if in.RequiredSetCovered != nil {
		v := *in.RequiredSetCovered
		out.RequiredSetCovered = &v
	}
	return out
}

func representationState(in RepresentationState) RepresentationState {
	switch in {
	case RepresentationAtRisk, RepresentationAlreadyLost:
		return in
	default:
		return RepresentationUnknown
	}
}

func representationReportedFacts(in []ReportedFact, redact bool) []ReportedFact {
	if in == nil {
		return nil
	}
	out := make([]ReportedFact, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].RepresentationFact = representationFact(in[i].RepresentationFact, redact)
		out[i].State = representationState(in[i].State)
		out[i].LossRefs = representationStrings(in[i].LossRefs, redact)
	}
	return out
}

func representationAssets(in []RepresentationAsset, redact bool) []RepresentationAsset {
	if in == nil {
		return nil
	}
	out := make([]RepresentationAsset, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Scope = representationScope(in[i].Scope, redact)
		out[i].Primary = representationState(in[i].Primary)
		out[i].AtRiskKeys = representationStrings(in[i].AtRiskKeys, redact)
		out[i].LossRefs = representationStrings(in[i].LossRefs, redact)
		out[i].Unresolved = representationStrings(in[i].Unresolved, redact)
	}
	return out
}

func cloneRepresentationOwned(in *Representation, redact bool) *Representation {
	if in == nil {
		return nil
	}
	out := *in
	out.Version = representationString(in.Version, redact)
	out.Snapshot = cloneRepresentationSnapshot(in.Snapshot, redact)
	out.CoverageShare = representationCoverage(in.CoverageShare, redact)
	out.FactStates = representationReportedFacts(in.FactStates, redact)
	out.AlreadyLost = representationLosses(in.AlreadyLost, redact)
	out.LossHistoryStatus = representationString(in.LossHistoryStatus, redact)
	out.LossAssessment = representationString(in.LossAssessment, redact)
	out.UnknownEntries = representationGaps(in.UnknownEntries, redact)
	out.UnknownKinds = representationGaps(in.UnknownKinds, redact)
	out.UncoverableEntries = representationStrings(in.UncoverableEntries, redact)
	out.AssetState = representationAssets(in.AssetState, redact)
	out.OutOfBand = representationString(in.OutOfBand, redact)
	out.EffectEvidence = representationString(in.EffectEvidence, redact)
	out.Note = representationString(in.Note, redact)
	return &out
}

func finiteRepresentationAmount(a RepresentationAmount) bool {
	return a.Value == nil || (!math.IsNaN(*a.Value) && !math.IsInf(*a.Value, 0))
}

func finiteRepresentation(in *Representation) bool {
	if in == nil {
		return true
	}
	for _, v := range in.Snapshot.Weights.Values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	c := in.CoverageShare
	return finiteRepresentationAmount(c.Covered) && finiteRepresentationAmount(c.Representable) &&
		finiteRepresentationAmount(c.Coverable) && finiteRepresentationAmount(c.Share)
}

// OwnedRedactedRepresentation returns a complete non-aliasing audit projection.
// It is always redacted; callers cannot mark arbitrary input as already safe.
func OwnedRedactedRepresentation(in *Representation) (*Representation, error) {
	if in == nil {
		return nil, nil
	}
	base := *in
	var removed bool
	base.Snapshot, removed = base.Snapshot.withoutCredentialKeys()
	if removed {
		missing := RepresentationAmount{Reason: "weight-key-binding-unavailable"}
		base.CoverageShare.Covered = missing
		base.CoverageShare.Coverable = missing
		base.CoverageShare.Representable = missing
		base.CoverageShare.Share = missing
	}
	out := cloneRepresentationOwned(&base, true)
	if !finiteRepresentation(out) {
		_, err := json.Marshal(math.NaN())
		return nil, err
	}
	return out, nil
}

// MarshalOwnedRedactedRepresentation prepares the exact safe wire value once.
func MarshalOwnedRedactedRepresentation(in *Representation) (*Representation, json.RawMessage, error) {
	out, err := OwnedRedactedRepresentation(in)
	if err != nil || out == nil {
		return out, nil, err
	}
	type plain Representation
	b, err := json.Marshal(plain(*out))
	if err != nil {
		return out, nil, err
	}
	b, err = canonicalRepresentationJSON(b)
	return out, b, err
}

type representationJSONField struct {
	nameStart, nameEnd int
	valueStart         int
	decodedName        string
}

func representationJSONFieldName(in []byte, field representationJSONField) string {
	if field.decodedName != "" {
		return field.decodedName
	}
	return string(in[field.nameStart+1 : field.nameEnd-1])
}

// canonicalRepresentationJSON preserves the former interface-tree encoder's
// recursive object-key order without decoding values or allocating an
// interface tree. Input is always compact, validated encoding/json output.
func canonicalRepresentationJSON(in []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(in))
	next, err := writeCanonicalRepresentationJSONValue(&out, in, 0)
	if err != nil {
		return nil, err
	}
	if next != len(in) {
		return nil, fmt.Errorf("representation encoder returned trailing data")
	}
	return out.Bytes(), nil
}

func canonicalRepresentationJSONStringEnd(in []byte, start int) (int, error) {
	if start >= len(in) || in[start] != '"' {
		return 0, fmt.Errorf("representation encoder returned an invalid string")
	}
	escaped := false
	for i := start + 1; i < len(in); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch in[i] {
		case '\\':
			escaped = true
		case '"':
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("representation encoder returned an unterminated string")
}

func representationJSONValueEnd(in []byte, start int) (int, error) {
	if start >= len(in) {
		return 0, fmt.Errorf("representation encoder returned a missing value")
	}
	switch in[start] {
	case '"':
		return canonicalRepresentationJSONStringEnd(in, start)
	case '{', '[':
		open, close := in[start], byte('}')
		if open == '[' {
			close = ']'
		}
		depth, inString, escaped := 1, false, false
		for i := start + 1; i < len(in); i++ {
			if inString {
				if escaped {
					escaped = false
				} else if in[i] == '\\' {
					escaped = true
				} else if in[i] == '"' {
					inString = false
				}
				continue
			}
			switch in[i] {
			case '"':
				inString = true
			case open:
				depth++
			case close:
				depth--
				if depth == 0 {
					return i + 1, nil
				}
			}
		}
		return 0, fmt.Errorf("representation encoder returned an unterminated collection")
	default:
		end := start
		for end < len(in) && in[end] != ',' && in[end] != '}' && in[end] != ']' {
			end++
		}
		if end == start {
			return 0, fmt.Errorf("representation encoder returned an invalid scalar")
		}
		return end, nil
	}
}

func writeCanonicalRepresentationJSONValue(out *bytes.Buffer, in []byte, start int) (int, error) {
	if start >= len(in) {
		return 0, fmt.Errorf("representation encoder returned a missing value")
	}
	switch in[start] {
	case '"':
		end, err := canonicalRepresentationJSONStringEnd(in, start)
		if err == nil {
			out.Write(in[start:end])
		}
		return end, err
	case '{':
		var fieldStorage [32]representationJSONField
		fields := fieldStorage[:0]
		i := start + 1
		if i < len(in) && in[i] == '}' {
			out.WriteString("{}")
			return i + 1, nil
		}
		end := 0
		for {
			nameEnd, err := canonicalRepresentationJSONStringEnd(in, i)
			if err != nil {
				return 0, err
			}
			decodedName := ""
			if bytes.IndexByte(in[i+1:nameEnd-1], '\\') >= 0 {
				if err := json.Unmarshal(in[i:nameEnd], &decodedName); err != nil {
					return 0, err
				}
			}
			if nameEnd >= len(in) || in[nameEnd] != ':' {
				return 0, fmt.Errorf("representation encoder returned an invalid object")
			}
			valueStart := nameEnd + 1
			valueEnd, err := representationJSONValueEnd(in, valueStart)
			if err != nil {
				return 0, err
			}
			fields = append(fields, representationJSONField{nameStart: i, nameEnd: nameEnd, valueStart: valueStart, decodedName: decodedName})
			if valueEnd >= len(in) {
				return 0, fmt.Errorf("representation encoder returned an unterminated object")
			}
			switch in[valueEnd] {
			case ',':
				i = valueEnd + 1
			case '}':
				end = valueEnd + 1
				goto objectComplete
			default:
				return 0, fmt.Errorf("representation encoder returned an invalid object separator")
			}
		}
	objectComplete:
		slices.SortFunc(fields, func(a, b representationJSONField) int {
			if a.decodedName == "" && b.decodedName == "" {
				return bytes.Compare(in[a.nameStart+1:a.nameEnd-1], in[b.nameStart+1:b.nameEnd-1])
			}
			return strings.Compare(representationJSONFieldName(in, a), representationJSONFieldName(in, b))
		})
		out.WriteByte('{')
		for i, field := range fields {
			if i > 0 {
				out.WriteByte(',')
			}
			out.Write(in[field.nameStart:field.nameEnd])
			out.WriteByte(':')
			if _, err := writeCanonicalRepresentationJSONValue(out, in, field.valueStart); err != nil {
				return 0, err
			}
		}
		out.WriteByte('}')
		return end, nil
	case '[':
		out.WriteByte('[')
		i := start + 1
		if i < len(in) && in[i] == ']' {
			out.WriteByte(']')
			return i + 1, nil
		}
		for index := 0; ; index++ {
			if index > 0 {
				out.WriteByte(',')
			}
			next, err := writeCanonicalRepresentationJSONValue(out, in, i)
			if err != nil {
				return 0, err
			}
			if next >= len(in) {
				return 0, fmt.Errorf("representation encoder returned an unterminated array")
			}
			switch in[next] {
			case ',':
				i = next + 1
			case ']':
				out.WriteByte(']')
				return next + 1, nil
			default:
				return 0, fmt.Errorf("representation encoder returned an invalid array separator")
			}
		}
	default:
		end, err := representationJSONValueEnd(in, start)
		if err != nil {
			return 0, err
		}
		raw := in[start:end]
		if raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9') {
			// The former interface-tree round trip represented every JSON number as
			// float64. Retain its edge-case formatting and integer rounding.
			var number float64
			if err := json.Unmarshal(raw, &number); err != nil {
				return 0, err
			}
			normalized, err := json.Marshal(number)
			if err != nil {
				return 0, err
			}
			out.Write(normalized)
		} else {
			out.Write(raw)
		}
		return end, nil
	}
}
