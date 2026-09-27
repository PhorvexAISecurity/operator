package console

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// The effect action has its own mounted digest and exact active-variant pin.
// Reusing the availability fixture's identity fields does not reuse its pgv1
// eligibility rule, run status, or claim.
func loadGuardrailEffectProfile(cfg Config) (guardrailAvailabilityProfile, []byte, error) {
	var p guardrailAvailabilityProfile
	if !cfg.GuardrailEffectEnabled || !staticSHA256.MatchString(cfg.GuardrailEffectProfileSHA256) ||
		cfg.GuardrailEffectProfilePath == "" || !filepath.IsAbs(cfg.GuardrailEffectProfilePath) ||
		filepath.Clean(cfg.GuardrailEffectProfilePath) != cfg.GuardrailEffectProfilePath {
		return p, nil, errors.New("reviewed guardrail effect profile is disabled or unpinned")
	}
	raw, err := readPinnedNamedProfile(cfg.GuardrailEffectProfilePath, cfg.GuardrailEffectProfileSHA256)
	if err != nil {
		return p, nil, errors.New("reviewed guardrail effect profile bytes unavailable")
	}
	p, err = parseGuardrailAvailabilityProfile(raw)
	validVariant := (p.Fixture.CaptureCurrentJournal && p.Fixture.ActiveVariant == "") ||
		(!p.Fixture.CaptureCurrentJournal && (p.Fixture.ActiveVariant == "pgv1" || p.Fixture.ActiveVariant == "pgv2"))
	if err != nil || !validVariant ||
		!staticSHA256.MatchString(p.Fixture.BoundarySourceSHA256) {
		return p, nil, errors.New("guardrail effect fixture lacks an exact known active variant or dual-listener source")
	}
	if cfg.AuditSource == nil || cfg.AuditSourceIdentity != p.Fixture.AuditURL+"|"+p.Fixture.AuditServerName {
		return p, nil, errors.New("reviewed guardrail effect audit transport unavailable")
	}
	return p, raw, nil
}

func guardrailEffectCatalogueAvailable(cfg Config) bool {
	_, _, err := loadGuardrailEffectProfile(cfg)
	return err == nil
}

func guardrailEffectCatalogueReason(cfg Config) string {
	if guardrailEffectCatalogueAvailable(cfg) {
		return "Configured only; launch rechecks exact target, source, active variant, journal and authenticated audit before any injected event"
	}
	return "Separate reviewed guardrail effect profile or authenticated audit authority is disabled or unavailable"
}

func guardrailEffectProtected(s availabilitySnapshot, p guardrailAvailabilityProfile) error {
	f := p.Fixture
	expectedVariant := f.ActiveVariant
	if f.CaptureCurrentJournal {
		expectedVariant = s.ActiveVariant
	}
	if expectedVariant != "pgv1" && expectedVariant != "pgv2" {
		return errors.New("current guardrail variant is not in the reviewed roster")
	}
	if s.JournalAbsent {
		var absence map[string]any
		if (!f.JournalInitiallyAbsent && !f.CaptureCurrentJournal) || s.JournalUID != "" || s.JournalResourceVersion != "" ||
			s.ActiveVariant != expectedVariant || s.PodVariant != expectedVariant ||
			s.GuardrailEpoch != "" || availabilityDecode(s.Receipt, &absence) != nil ||
			!availabilityIsJournalAbsence(absence, p.Context, f.GuardrailJournalName) {
			return errors.New("reviewed first-operation guardrail absence or baseline differs")
		}
		return nil
	}
	if f.JournalInitiallyAbsent {
		return errors.New("explicit first-operation profile encountered a preexisting journal")
	}
	n, phase, prior, next, op, tick, err := availabilityReceiptFields(s.Receipt)
	if err != nil {
		return err
	}
	var r map[string]any
	if err = availabilityDecode(s.Receipt, &r); err != nil {
		return err
	}
	if s.ActiveVariant != expectedVariant || s.PodVariant != expectedVariant ||
		(s.ActiveVariant != "pgv1" && s.ActiveVariant != "pgv2") ||
		n < 1 || phase != "terminal-full" || (prior != "pgv1" && prior != "pgv2") || prior == next || next != s.ActiveVariant ||
		r["version"] != float64(9) || r["kind"] != "guardrail-rotate" ||
		r["effectDomain"] != "guardrail-variant-v1" || r["policyNamespace"] != "vllm" ||
		r["policyName"] != f.PolicyName || r["policyUID"] != f.PolicyUID ||
		r["targetName"] != f.PodName || r["targetUID"] != f.PodUID ||
		tick == "" || op != availabilityOperationID(tick, f.PolicyUID, "vllm", f.PodUID) ||
		availabilityMap(r["expectedGuardrail"])["present"] != true ||
		availabilityMap(r["expectedGuardrail"])["value"] != availabilityEpoch(op) ||
		s.GuardrailEpoch != availabilityEpoch(op) {
		return errors.New("reviewed protected guardrail baseline differs")
	}
	return nil
}

// Only an exact selected decision tick may explain a terminal-full successor.
// In particular, a spontaneous variant change cannot become a response result.
func guardrailEffectTransition(before, after availabilitySnapshot, selected availabilityDecision, p guardrailAvailabilityProfile) (string, error) {
	if !availabilitySameSource(before, after, true) {
		return "", errors.New("guardrail source or target drift across operation")
	}
	var bn int64
	var bop string
	if before.JournalAbsent {
		if (!p.Fixture.JournalInitiallyAbsent && !p.Fixture.CaptureCurrentJournal) || guardrailEffectProtected(before, p) != nil {
			return "", errors.New("first-operation source lacks reviewed absence")
		}
	} else {
		var err error
		bn, _, _, _, bop, _, err = availabilityReceiptFields(before.Receipt)
		if err != nil {
			return "", err
		}
	}
	an, phase, prior, next, op, tick, err := availabilityReceiptFields(after.Receipt)
	if err != nil {
		return "", err
	}
	var receipt map[string]any
	if err = availabilityDecode(after.Receipt, &receipt); err != nil {
		return "", err
	}
	if after.JournalAbsent || after.JournalUID == "" || an != bn+1 || phase != "terminal-full" || prior != before.ActiveVariant ||
		next == prior || (next != "pgv1" && next != "pgv2") || next != after.ActiveVariant ||
		next != after.PodVariant || op == bop || tick == "" || tick != selected.TickID ||
		op != availabilityOperationID(selected.TickID, before.PolicyUID, "vllm", before.TargetPodUID) ||
		after.GuardrailEpoch != availabilityEpoch(op) ||
		receipt["version"] != float64(9) || receipt["kind"] != "guardrail-rotate" ||
		receipt["effectDomain"] != "guardrail-variant-v1" ||
		receipt["policyNamespace"] != "vllm" || receipt["policyName"] != p.Fixture.PolicyName ||
		receipt["policyUID"] != before.PolicyUID || receipt["targetName"] != p.Fixture.PodName ||
		receipt["targetUID"] != before.TargetPodUID ||
		availabilityMap(receipt["expectedGuardrail"])["present"] != true ||
		availabilityMap(receipt["expectedGuardrail"])["value"] != availabilityEpoch(op) {
		return "", fmt.Errorf("selected decision is not the protected opposite-variant operation")
	}
	return op, nil
}

func guardrailEffectSafeIssue(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "CNR_") {
		return "GUARDRAIL_EFFECT_PRIVATE_MARKER_REDACTED"
	}
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
