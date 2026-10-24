/*
 * Phorvex — M-21: the published per-action/per-route repertoire is DERIVED, not written.
 *
 * The matrix in docs/actuator-repertoire.md is generated from the same predicates dispatch
 * and SupportsAction read, and this test regenerates it and fails on any difference. A
 * hand-maintained table would drift from the code the first time an action was added;
 * this one cannot. Regenerate with:
 *
 *	go test ./internal/actuator/ -run TestRepertoireDocumentIsCurrent -update
 */

package actuator

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

var updateRepertoire = flag.Bool("update", false, "rewrite docs/actuator-repertoire.md from the code")

const repertoireDocPath = "../../docs/actuator-repertoire.md"

// renderRepertoire builds the published document from the live inventory.
func renderRepertoire() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Phorvex actuator repertoire (v%d)\n\n", RepertoireVersion)
	b.WriteString("GENERATED — do not edit by hand. Regenerate with:\n\n")
	b.WriteString("```sh\ngo test ./internal/actuator/ -run TestRepertoireDocumentIsCurrent -update\n```\n\n")
	b.WriteString("`" + BackendEnvVar + "` selects the backend. Accepted values: ")
	b.WriteString("`" + strings.ReplaceAll(backendList(), ", ", "`, `") + "`. ")
	b.WriteString("Unset or empty selects the default `" + string(DefaultBackend) + "`; ")
	b.WriteString("every other value is rejected at startup — no trimming, no case folding, no fallback.\n\n")
	b.WriteString("## What the columns mean\n\n")
	b.WriteString("These are four DIFFERENT properties and the table keeps them apart on purpose:\n\n")
	b.WriteString("- **Route** — the backend that actually receives the dispatch. For `hybrid` this is\n")
	b.WriteString("  the same predicate `Actuate` routes on, never a union of both backends.\n")
	b.WriteString("- **Adapter acceptance** — this route implements the action. It is NOT authorization,\n")
	b.WriteString("  NOT target readiness, and NOT proof that anything executed.\n")
	b.WriteString("- **Prerequisite** — a runtime precondition this route additionally checks before it\n")
	b.WriteString("  reports support.\n")
	b.WriteString("- **Unverified** — what acceptance explicitly does not establish. Confirmed effect is\n")
	b.WriteString("  tracked separately (M-9); RBAC, CRD admission and per-target capability are\n")
	b.WriteString("  enforced by their own layers and are not implied by any row here.\n\n")
	b.WriteString("A historical live result (for example the 2026-08-21 Phoenix rotate observation under\n")
	b.WriteString("M-9) is evidence about ONE build, target and configuration. Current pure Phoenix\n")
	b.WriteString("refuses bounded rotate because its Delete strategy cannot carry the policy cap;\n")
	b.WriteString("select `native` or `hybrid` for bounded rotate. Historical evidence is not a standing\n")
	b.WriteString("guarantee for any other deployment and is deliberately absent from this table.\n")
	b.WriteString("`identity-rotate` implements LIGHT dedicated-ServiceAccount UID rotation for external\n")
	b.WriteString("bearer theft. Targetless rows cannot establish its exact Pod/SA/policy prerequisites;\n")
	b.WriteString("runtime admission requires the validated observation and affirmative scoped RBAC.\n")
	b.WriteString("The Pod remains; process compromise and federated credentials are outside scope.\n")
	b.WriteString("`route-rotate` is a real Service-selector restitch;\n")
	b.WriteString("the per-target capability gate requires its declared Service to select the target\n")
	b.WriteString("route-key with the target Ready and at least two Ready backends.\n")
	for _, backend := range Backends() {
		fmt.Fprintf(&b, "\n## %s\n\n", backend)
		b.WriteString("| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, e := range Repertoire(backend) {
			accepted := "no"
			if e.Accepted {
				accepted = "yes"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n",
				e.Action, e.Route, accepted, cell(e.Why), cell(e.Prerequisite), cell(e.UnverifiedEffect))
		}
	}
	return b.String()
}

func cell(v string) string {
	if v == "" {
		return "—"
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, "|", "\\|"), "\n", " ")
}

func TestRepertoireDocumentIsCurrent(t *testing.T) {
	want := renderRepertoire()
	if *updateRepertoire {
		if err := os.MkdirAll(filepath.Dir(repertoireDocPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(repertoireDocPath, []byte(want), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("regenerated %s", repertoireDocPath)
		return
	}
	got, err := os.ReadFile(repertoireDocPath)
	if err != nil {
		t.Fatalf("the published repertoire is missing (%v); regenerate with -update", err)
	}
	if string(got) != want {
		t.Fatalf("docs/actuator-repertoire.md has drifted from the code.\n"+
			"Regenerate: go test ./internal/actuator/ -run TestRepertoireDocumentIsCurrent -update\n"+
			"want %d bytes, got %d bytes", len(want), len(got))
	}
}

// TestRepertoireCoversEveryAction: the inventory is derived from the action vocabulary, so
// adding an action without deciding its repertoire is impossible.
func TestRepertoireCoversEveryAction(t *testing.T) {
	all := append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...)
	for _, backend := range Backends() {
		seen := map[model.Action]bool{}
		for _, e := range Repertoire(backend) {
			if seen[e.Action] {
				t.Fatalf("%s: duplicate repertoire row for %s", backend, e.Action)
			}
			seen[e.Action] = true
		}
		for _, a := range all {
			if !seen[a] {
				t.Fatalf("%s: action %s has no repertoire row", backend, a)
			}
		}
		if len(seen) != len(all) {
			t.Fatalf("%s: repertoire has %d rows for %d actions", backend, len(seen), len(all))
		}
	}
}

// TestRepertoireAgreesWithSupportsAction is the anti-drift bolt: every published row must
// match what the REAL actuator answers. A doc that disagreed with the running code would
// be worse than no doc at all.
func TestRepertoireAgreesWithSupportsAction(t *testing.T) {
	for _, backend := range Backends() {
		act, err := New(backend, nil)
		if err != nil {
			t.Fatalf("New(%s): %v", backend, err)
		}
		switch configured := act.(type) {
		case *NativeActuator:
			configured.SetServingSecurity(legacyServingSecurityForTest(t))
			configured.SetBoundaryReader(fakeC())
			configured.JournalNamespace = "operator"
		case *HybridActuator:
			configured.SetServingSecurity(legacyServingSecurityForTest(t))
			configured.ConfigureNativeJournal(fakeC(), "operator")
		}
		for _, e := range Repertoire(backend) {
			ok, why := act.SupportsAction(t.Context(), e.Action, Target{Namespace: "ns", Pod: "p", UID: "target-uid"})
			// The static row describes handler acceptance. This empty fake client has
			// no exact Pod, policy, or preinstalled rule source for a live capability.
			if e.Action == model.ActionRequestDrain && e.Accepted {
				if ok || !strings.HasPrefix(why, "request-drain-capability:") {
					t.Fatalf("missing authenticated current drain capability accepted: %s/%s %v %q", backend, e.Action, ok, why)
				}
				continue
			}
			if e.Action == model.ActionSensitiveOutputPolicyActivate && e.Accepted {
				if ok || why != "output-policy-pod-read-failed" || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing output-policy authority must be an explicit prerequisite refusal: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionVoiceMemoryNoteRevoke && e.Accepted {
				if ok || !strings.HasPrefix(why, "voice-memory-scope-unavailable:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing Voice authority must be explicit: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionVoiceRefundPairDeny && e.Accepted {
				if ok || !strings.HasPrefix(why, "voice-refund-scope-unavailable:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing Voice refund authority must be explicit: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionVoiceOutputPolicyActivate && e.Accepted {
				if ok || !strings.HasPrefix(why, "voice-output-scope-unavailable:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing Voice output authority must be explicit: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionVoiceMCPToolPin && e.Accepted {
				if ok || why != "voice-mcp-approved-image-unavailable" || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing reviewed MCP image must be explicit: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionLiteLLMClientRevoke && e.Accepted {
				if ok || !strings.Contains(why, "litellm-client-revoke:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing owned-client gateway authority must refuse: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionVoiceSessionAdmissionEnforce && e.Accepted {
				if ok || why != "voice-admission-feature-disabled" || e.Prerequisite == "" {
					t.Fatalf("admission explicit installation gate absent: ok=%v why=%q", ok, why)
				}
				continue
			}
			if e.Action == model.ActionEndpointLeaseRevoke && e.Accepted {
				if ok || !strings.Contains(why, "endpoint-lease-revoke:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing reviewed lease source, image, journal or target authority must refuse: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			if e.Action == model.ActionCRMRefundRevoke && e.Accepted {
				if ok || !strings.HasPrefix(why, "crm-refund-revoke:") || e.Prerequisite == "" {
					t.Fatalf("%s/%s: missing reader or exact CRM target must refuse: ok=%v why=%q prerequisite=%q", backend, e.Action, ok, why, e.Prerequisite)
				}
				continue
			}
			// The native route fails closed until a connector attests remote migration.
			if e.Action == model.ActionKVMigrateInvalidate && e.Accepted && !ok {
				if why != ReasonKVMigrationConnectorUnavailable {
					t.Fatalf("%s/%s: an unavailable KV connector must refuse with its reason, got %q", backend, e.Action, why)
				}
				continue
			}
			// mig-rebind on a native route has a runtime prerequisite the static table
			// records separately; everywhere else acceptance and support must agree.
			if e.Prerequisite != "" && !ok {
				if why != ReasonTransportUnwired {
					t.Fatalf("%s/%s: prerequisite failure must use the retained vocabulary, got %q", backend, e.Action, why)
				}
				continue
			}
			if ok != e.Accepted {
				t.Fatalf("%s/%s: repertoire says accepted=%v but SupportsAction says %v (%s)",
					backend, e.Action, e.Accepted, ok, why)
			}
			if why != e.Why {
				t.Fatalf("%s/%s: repertoire why %q != SupportsAction why %q", backend, e.Action, e.Why, why)
			}
		}
	}
}
