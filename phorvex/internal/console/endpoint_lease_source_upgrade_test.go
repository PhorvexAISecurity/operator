package console

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func upgradeCanonical(v any) []byte {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	b, _ = json.Marshal(out)
	return b
}

func upgradeFixture(t *testing.T) (endpointLeaseProfile, endpointLeaseState, endpointLeaseJournal) {
	t.Helper()
	p := leaseTestProfile()
	before := endpointLeaseState{Version: 1, ServiceUID: p.ServiceUID, ProxySourceSHA256: p.ProxySourceSHA256,
		SecretUID: p.TenantSecretUID, SeedSHA256: p.SeedSHA256,
		AllowedClientHMACs: []string{p.ClientAHMAC, p.ClientBHMAC}, RevokedClientHMACs: []string{}}
	prior, err := endpointLeaseDesired(before, p, strings.Repeat("f", 32))
	if err != nil {
		t.Fatal(err)
	}
	row := endpointLeaseJournalReceipt{Phase: "terminal-full", OldRevision: 0, NewRevision: 1,
		OldStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(before)), NewStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(prior)),
		OperationID: prior.LastOperationID, PolicyUID: p.PolicyUID, PolicyConfigMapUID: p.PolicyConfigMapUID,
		SecretUID: p.TenantSecretUID, ServiceUID: p.ServiceUID, SeedSHA256: p.SeedSHA256,
		ProxySourceSHA256: p.ProxySourceSHA256, RetainedClientHMAC: p.ClientBHMAC, RevokedClientHMAC: p.ClientAHMAC}
	j := endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{row}}
	if !retainedCallerAllowed(prior, j, p) {
		t.Fatal("normal old profile refused")
	}
	oldUID := p.SourceConfigMapUID
	p.SourceConfigMapUID = "88888888-8888-4888-8888-888888888888"
	p.ProxySourceSHA256 = leaseHex('9')
	current := prior
	current.Revision++
	current.ProxySourceSHA256 = p.ProxySourceSHA256
	p.SourceUpgrade = &endpointLeaseSourceUpgrade{Version: 1, PriorStateJSON: string(endpointLeaseStateBytes(prior)),
		PriorStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(prior)), PriorJournalSHA256: endpointLeaseSHA(endpointLeaseJournalBytes(j)),
		CurrentStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(current)), PriorSourceConfigMapUID: oldUID}
	return p, current, j
}

func TestRetainedCallerSourceUpgradeRealCanonicalParse(t *testing.T) {
	p, current, j := upgradeFixture(t)
	parsed, err := parseEndpointLeaseProfile(upgradeCanonical(p))
	if err != nil {
		t.Fatal(err)
	}
	state, err := parseEndpointLeaseState(endpointLeaseStateBytes(current), parsed)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := parseEndpointLeaseJournal(endpointLeaseJournalBytes(j))
	if err != nil || !retainedCallerAllowed(state, journal, parsed) {
		t.Fatal("exact preserving upgrade refused", err)
	}
	before := state
	before.Revision = 0
	before.AllowedClientHMACs = []string{p.ClientAHMAC, p.ClientBHMAC}
	before.RevokedClientHMACs = []string{}
	before.LastOperationID = ""
	if endpointLeaseBefore(before, parsed) || retainedCallerAllowed(before, journal, parsed) {
		t.Fatal("witness rearmed first-loss")
	}
	if _, err := endpointLeaseDesired(before, parsed, strings.Repeat("a", 32)); err == nil {
		t.Fatal("fresh revocation admitted")
	}
}

func TestRetainedCallerSourceUpgradeRefusesChangedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*endpointLeaseProfile, *endpointLeaseState, *endpointLeaseJournal){
		"skipped revision": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) { s.Revision++ },
		"last operation": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) {
			s.LastOperationID = strings.Repeat("a", 32)
		},
		"seed": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) {
			s.SeedSHA256 = leaseHex('0')
		},
		"secret":  func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) { s.SecretUID = "other" },
		"service": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) { s.ServiceUID = "other" },
		"source": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) {
			s.ProxySourceSHA256 = leaseHex('0')
		},
		"B revoked": func(_ *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) {
			s.RevokedClientHMACs = []string{s.AllowedClientHMACs[0]}
		},
		"A rearmed": func(p *endpointLeaseProfile, s *endpointLeaseState, _ *endpointLeaseJournal) {
			s.AllowedClientHMACs = []string{p.ClientAHMAC, p.ClientBHMAC}
			s.RevokedClientHMACs = []string{}
		},
		"new terminal": func(_ *endpointLeaseProfile, _ *endpointLeaseState, j *endpointLeaseJournal) {
			j.Receipts = append(j.Receipts, j.Receipts[0])
		},
		"prepared": func(p *endpointLeaseProfile, _ *endpointLeaseState, j *endpointLeaseJournal) {
			j.Receipts = append(j.Receipts, endpointLeaseJournalReceipt{Phase: "prepared"})
			p.SourceUpgrade.PriorJournalSHA256 = endpointLeaseSHA(endpointLeaseJournalBytes(*j))
		},
		"false terminal": func(p *endpointLeaseProfile, _ *endpointLeaseState, j *endpointLeaseJournal) {
			j.Receipts[0].RevokedClientHMAC = p.ClientBHMAC
			p.SourceUpgrade.PriorJournalSHA256 = endpointLeaseSHA(endpointLeaseJournalBytes(*j))
		},
		"archive UID": func(p *endpointLeaseProfile, _ *endpointLeaseState, _ *endpointLeaseJournal) {
			p.SourceUpgrade.PriorSourceConfigMapUID = p.SourceConfigMapUID
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, s, j := upgradeFixture(t)
			mutate(&p, &s, &j)
			if retainedCallerAllowed(s, j, p) {
				t.Fatal("changed authority admitted")
			}
		})
	}
}

func TestSourceUpgradeProfileStrictSchema(t *testing.T) {
	p, _, _ := upgradeFixture(t)
	var m map[string]any
	_ = json.Unmarshal(upgradeCanonical(p), &m)
	w := m["sourceUpgrade"].(map[string]any)
	w["unknown"] = true
	if _, err := parseEndpointLeaseProfile(upgradeCanonical(m)); err == nil {
		t.Fatal("unknown witness key accepted")
	}
	delete(w, "unknown")
	w["priorStateJSON"] = p.SourceUpgrade.PriorStateJSON + "\n"
	if _, err := parseEndpointLeaseProfile(upgradeCanonical(m)); err == nil {
		t.Fatal("noncanonical prior state accepted")
	}
	w["priorStateJSON"] = p.SourceUpgrade.PriorStateJSON
	w["version"] = 2
	if _, err := parseEndpointLeaseProfile(upgradeCanonical(m)); err == nil {
		t.Fatal("unknown witness version accepted")
	}
	w["version"] = 1
	w["currentStateSHA256"] = leaseHex('0')
	if _, err := parseEndpointLeaseProfile(upgradeCanonical(m)); err == nil {
		t.Fatal("unrelated current state accepted")
	}
	m["sourceUpgrade"] = nil
	if _, err := parseEndpointLeaseProfile(upgradeCanonical(m)); err == nil {
		t.Fatal("explicit null witness accepted as legacy profile")
	}
}

func TestSourceUpgradeArchivedProductionStateAndTerminal(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/endpoint-lease-source-upgrade/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	oldRaw, priorRaw, journalRaw := read("prior-profile.json"), read("prior-state.json"), read("prior-journal.json")
	if endpointLeaseSHA(oldRaw) != "69efe329171ef1c4b739b7c4a21706120efc4e0cdef762695603f20cc38f1b1d" ||
		endpointLeaseSHA(journalRaw) != "1c4784d41c51d939b54af49bf372514343601664c0a54277cc07554bcd4cd668" {
		t.Fatal("archived source/terminal bytes changed")
	}
	p, err := parseEndpointLeaseProfile(oldRaw)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := parseEndpointLeaseState(priorRaw, p)
	if err != nil {
		t.Fatal(err)
	}
	j, err := parseEndpointLeaseJournal(journalRaw)
	if err != nil || !retainedCallerAllowed(prior, j, p) {
		t.Fatal("archived retained B refused", err)
	}
	current := prior
	current.Revision++
	current.ProxySourceSHA256 = leaseHex('9') // explicitly synthetic offline current source
	oldUID := p.SourceConfigMapUID
	p.SourceConfigMapUID = "88888888-8888-4888-8888-888888888888" // no live UID claim
	p.ProxySourceSHA256 = current.ProxySourceSHA256
	p.SourceUpgrade = &endpointLeaseSourceUpgrade{Version: 1, PriorStateJSON: string(priorRaw),
		PriorStateSHA256: endpointLeaseSHA(priorRaw), PriorJournalSHA256: endpointLeaseSHA(journalRaw),
		CurrentStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(current)), PriorSourceConfigMapUID: oldUID}
	p, err = parseEndpointLeaseProfile(upgradeCanonical(p))
	if err != nil || !retainedCallerAllowed(current, j, p) {
		t.Fatal("preserving archived transition refused", err)
	}
	if !strings.EqualFold(endpointLeaseSHA(endpointLeaseJournalBytes(j)), endpointLeaseSHA(journalRaw)) {
		t.Fatal("typed canonical journal differs from exact archived bytes")
	}
}
