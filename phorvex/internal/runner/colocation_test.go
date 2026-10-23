package runner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

func TestColocationJoinsPolicySelectorAndKeepsDecisionBytes(t *testing.T) {
	e := &policyEntry{tenant: "A", uid: "pa", key: types.NamespacedName{Namespace: "a", Name: "policy"}}
	p := model.Pod{Namespace: "a", Name: "pod", UID: "p", Node: "node", Labels: map[string]string{"app": "a"}}
	q := model.Pod{Namespace: "b", Name: "neighbor", UID: "q", Node: "node", Labels: map[string]string{"app": "b"}}
	snap := &ingest.Snapshot{Now: time.Unix(123, 0), Pods: []model.Pod{p, q}, PodInventoryComplete: true, PolicyInventoryComplete: true, EventInventoryComplete: true,
		NamespaceLabels: map[string]map[string]string{"a": {}, "b": {}}, Policies: []v1alpha1.PhorvexPolicy{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "a"}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "A", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "b"}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "B", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "b"}}}},
		}}
	in := colocationInput(observationOf(snap), e)
	in.Target = p
	in.TargetKnown = true
	if a := model.AssessColocation(in); a.State != "present" {
		t.Fatalf("joined inventory: %+v", a)
	}
	e.spec.Trust.PeerPolicies = []string{"B"}
	in = colocationInput(observationOf(snap), e)
	in.Target = p
	in.TargetKnown = true
	if a := model.AssessColocation(in); a.State != "absent" {
		t.Fatalf("peer declaration: %+v", a)
	}
	var legacy bytes.Buffer
	var logs []string
	logger := funcr.New(func(_, args string) { logs = append(logs, args) }, funcr.Options{})
	m := &Manager{Local: &inprocess.Services{}, Audit: audit.New(logger, &legacy)}
	d := model.Decision{Namespace: "a", Pod: "pod", Tenant: "A", Trace: &model.DecisionTraceV2{DecisionID: "existing-id"}}
	before, _ := json.Marshal(audit.ToRecord(d))
	m.recordColocation(in, d, model.Policy{TickID: "tick", GitSHA: "sha", BrainImage: "image"})
	after, _ := json.Marshal(audit.ToRecord(d))
	if !bytes.Equal(before, after) || legacy.Len() != 0 {
		t.Fatal("sidecar changed legacy decision or JSONL")
	}
	text := strings.Join(logs, "\n")
	if !strings.Contains(text, "existing-id") || !strings.Contains(text, "UNRESOLVED") || !strings.Contains(text, "phorvex.colocation.v1") {
		t.Fatal(text)
	}
}
