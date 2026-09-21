package startupauthz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
)

type recordingSSAR struct {
	attributes []authorizationv1.ResourceAttributes
	deny       func(authorizationv1.ResourceAttributes) bool
	malformed  bool
}

func (r *recordingSSAR) Create(_ context.Context, review *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	attributes := *review.Spec.ResourceAttributes
	r.attributes = append(r.attributes, attributes)
	if r.malformed {
		return nil, nil
	}
	review.Status.Allowed = r.deny == nil || !r.deny(attributes)
	review.Status.Denied = !review.Status.Allowed
	return review, nil
}

func policy(namespace, name, mode string, actions ...v1alpha1.ActionType) *v1alpha1.PhorvexPolicy {
	return &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: mode,
		Budget: v1alpha1.BudgetSpec{
			TickInterval:           metav1.Duration{Duration: 20 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: actions},
	}}
}

func policyReader(t *testing.T, policies ...*v1alpha1.PhorvexPolicy) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := make([]client.Object, len(policies))
	for i := range policies {
		objects[i] = policies[i]
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestCheckNoPolicyAndDryRunNeedNoActuationReview(t *testing.T) {
	for name, reader := range map[string]client.Reader{
		"none":   policyReader(t),
		"dryRun": policyReader(t, policy("tenant", "p", v1alpha1.ModeDryRun, v1alpha1.ActionRotate)),
	} {
		t.Run(name, func(t *testing.T) {
			report, err := Check(t.Context(), reader, nil, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
			if err != nil {
				t.Fatal(err)
			}
			if report.ActivePolicies != 0 || report.Requirements != 0 {
				t.Fatalf("unexpected actuation verification: %+v", report)
			}
		})
	}
}

func TestCheckFollowsNativeAndHybridRoutingAndClusterScope(t *testing.T) {
	reader := policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate))
	for _, test := range []struct {
		name           string
		backend        actuator.Backend
		wantResource   string
		wantNamespace  string
		forbidResource string
	}{
		{name: "native", backend: actuator.BackendNative, wantResource: "pods", wantNamespace: "tenant", forbidResource: "securityevents"},
		{name: "hybrid", backend: actuator.BackendHybrid, wantResource: "pods", wantNamespace: "tenant", forbidResource: "securityevents"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reviews := &recordingSSAR{}
			if _, err := Check(t.Context(), reader, reviews, Config{Backend: test.backend, OperatorNamespace: "operator"}); err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, attributes := range reviews.attributes {
				if attributes.Resource == test.forbidResource {
					t.Fatalf("%s acquired wrong-route permission: %+v", test.backend, attributes)
				}
				if attributes.Resource == test.wantResource && attributes.Namespace == test.wantNamespace {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing %s in scope %q: %+v", test.wantResource, test.wantNamespace, reviews.attributes)
			}
		})
	}
}

func TestCheckQuarantineIncludesCapacityAndRecoveryPermissions(t *testing.T) {
	reviews := &recordingSSAR{}
	_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionQuarantine)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"|/namespaces:get":                         false,
		"tenant|/pods:list":                        false,
		"|amtd.r6security.com/securityevents:list": false,
		"operator|/configmaps:create":              false,
		"operator|/configmaps:update":              false,
		"operator|/configmaps:delete":              false,
	}
	for _, attributes := range reviews.attributes {
		key := attributes.Namespace + "|" + attributes.Group + "/" + attributes.Resource + ":" + attributes.Verb
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for requirement, found := range want {
		if !found {
			t.Errorf("missing %s", requirement)
		}
	}
}

func TestM103CheckRequiresSharedAvailabilityInventoryAndLedgerCAS(t *testing.T) {
	reader := policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate))
	for _, tc := range []struct {
		name, namespace, group, resource, verb string
	}{
		{name: "service inventory", namespace: "tenant", resource: "services", verb: "list"},
		{name: "endpoint membership", namespace: "tenant", group: "discovery.k8s.io", resource: "endpointslices", verb: "list"},
		{name: "durable ledger update", namespace: "operator", resource: "configmaps", verb: "update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reviews := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
				return attributes.Namespace == tc.namespace && attributes.Group == tc.group && attributes.Resource == tc.resource && attributes.Verb == tc.verb
			}}
			_, err := Check(t.Context(), reader, reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
			if err == nil || !strings.Contains(err.Error(), "shared") {
				t.Fatalf("missing %s permission was accepted: %v", tc.name, err)
			}
		})
	}
}

func TestCheckNativeAndHybridRequireRecoveryJournalInventory(t *testing.T) {
	reader := policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate))
	for _, backend := range []actuator.Backend{actuator.BackendNative, actuator.BackendHybrid} {
		t.Run(string(backend), func(t *testing.T) {
			reviews := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
				return attributes.Namespace == "operator" && attributes.Resource == "configmaps" && attributes.Verb == "list"
			}}
			if _, err := Check(t.Context(), reader, reviews, Config{Backend: backend, OperatorNamespace: "operator"}); err == nil || !strings.Contains(err.Error(), "native protected recovery journal") {
				t.Fatalf("missing recovery journal list was accepted: %v", err)
			}
		})
	}
}

func TestM124CheckRequiresCommonNamespaceAndPodAuthorityReads(t *testing.T) {
	reader := policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate))
	for _, backend := range []actuator.Backend{actuator.BackendPhoenix, actuator.BackendNative, actuator.BackendHybrid} {
		for _, deniedResource := range []string{"namespaces", "pods"} {
			t.Run(string(backend)+"/"+deniedResource, func(t *testing.T) {
				reviews := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
					return attributes.Resource == deniedResource && attributes.Verb == "get"
				}}
				_, err := Check(t.Context(), reader, reviews, Config{Backend: backend, OperatorNamespace: "operator"})
				if err == nil || !strings.Contains(err.Error(), "actuation brake") {
					t.Fatalf("denied common %s read was accepted: %v", deniedResource, err)
				}
				var saw bool
				for _, attributes := range reviews.attributes {
					if attributes.Resource == deniedResource && attributes.Verb == "get" {
						saw = true
						if deniedResource == "namespaces" && (attributes.Namespace != "" || attributes.Name != "tenant") {
							t.Fatalf("namespace authority used wrong scope: %+v", attributes)
						}
						if deniedResource == "pods" && attributes.Namespace != "tenant" {
							t.Fatalf("Pod authority used wrong scope: %+v", attributes)
						}
					}
				}
				if !saw {
					t.Fatalf("missing %s review: %+v", deniedResource, reviews.attributes)
				}
			})
		}
	}
}

func TestCheckOptionalMIGAgentUsesExactDaemonSetAndExecSubresource(t *testing.T) {
	reviews := &recordingSSAR{}
	_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionMIGRebind)), reviews, Config{
		Backend: actuator.BackendNative, OperatorNamespace: "operator",
		MIGAgent: &MIGAgentAccess{Namespace: "gpu-system", DaemonSet: "phorvex-mig-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var namedDaemonSet, podExec bool
	for _, attributes := range reviews.attributes {
		if attributes.Group == "apps" && attributes.Resource == "daemonsets" && attributes.Name == "phorvex-mig-agent" && attributes.Namespace == "gpu-system" && attributes.Verb == "get" {
			namedDaemonSet = true
		}
		if attributes.Resource == "pods" && attributes.Subresource == "exec" && attributes.Namespace == "gpu-system" && attributes.Verb == "create" {
			podExec = true
		}
	}
	if !namedDaemonSet || !podExec {
		t.Fatalf("MIG requirements missing exact owner/exec scope: %+v", reviews.attributes)
	}
}

func TestCheckRefusesDeniedUnknownAndIncompleteInventory(t *testing.T) {
	active := policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate))
	denied := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
		return attributes.Group == "" && attributes.Resource == "pods" && attributes.Subresource == "eviction" && attributes.Verb == "create"
	}}
	if _, err := Check(t.Context(), active, denied, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denial error = %v", err)
	}
	if _, err := Check(t.Context(), active, &recordingSSAR{malformed: true}, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("malformed response error = %v", err)
	}
	broken := errorReader{Reader: active, err: errors.New("inventory unavailable")}
	if _, err := Check(t.Context(), broken, &recordingSSAR{}, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("inventory error = %v", err)
	}
}

func TestBootRefusalPrecedesControllerMutation(t *testing.T) {
	mutations := 0
	reviews := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
		return attributes.Group == "" && attributes.Resource == "pods" && attributes.Subresource == "eviction" && attributes.Verb == "create"
	}}
	_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
	if err == nil {
		mutations++ // represents the controller registration/start branch in main
	}
	if err == nil || mutations != 0 {
		t.Fatalf("boot err=%v mutations=%d", err, mutations)
	}
}

func TestCheckRefusesOmittedReadPermissionsByAction(t *testing.T) {
	tests := []struct {
		name     string
		action   v1alpha1.ActionType
		group    string
		resource string
		verb     string
	}{
		{name: "quarantine network policy identity", action: v1alpha1.ActionQuarantine, group: "networking.k8s.io", resource: "networkpolicies", verb: "get"},
		{name: "quarantine policy authority", action: v1alpha1.ActionQuarantine, group: "phorvex.ai", resource: "phorvexpolicies", verb: "get"},
		{name: "quarantine StatefulSet owner", action: v1alpha1.ActionQuarantine, group: "apps", resource: "statefulsets", verb: "get"},
		{name: "quarantine DaemonSet owner", action: v1alpha1.ActionQuarantine, group: "apps", resource: "daemonsets", verb: "get"},
		{name: "quarantine Job owner", action: v1alpha1.ActionQuarantine, group: "batch", resource: "jobs", verb: "get"},
		{name: "warm pool inventory", action: v1alpha1.ActionWarmSwap, resource: "pods", verb: "list"},
		{name: "warm controller binding", action: v1alpha1.ActionWarmSwap, group: "apps", resource: "replicasets", verb: "get"},
		{name: "route backend inventory", action: v1alpha1.ActionRouteRotate, resource: "pods", verb: "list"},
		{name: "endpoint service", action: v1alpha1.ActionEndpointRotate, resource: "services", verb: "get"},
		{name: "request drain endpoint inventory", action: v1alpha1.ActionRequestDrain, group: "discovery.k8s.io", resource: "endpointslices", verb: "list"},
		{name: "request drain Pod patch", action: v1alpha1.ActionRequestDrain, resource: "pods", verb: "patch"},
		{name: "adapter Pod patch", action: v1alpha1.ActionAdapterRotate, resource: "pods", verb: "patch"},
		{name: "adapter detector authority", action: v1alpha1.ActionAdapterRotate, group: "amtd.r6security.com", resource: "securityevents", verb: "get"},
		{name: "adapter policy authority", action: v1alpha1.ActionAdapterRotate, group: "phorvex.ai", resource: "phorvexpolicies", verb: "get"},
		{name: "adapter journal update", action: v1alpha1.ActionAdapterRotate, resource: "configmaps", verb: "update"},
		{name: "MIG current policy", action: v1alpha1.ActionMIGRebind, group: "phorvex.ai", resource: "phorvexpolicies", verb: "get"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reviews := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool {
				return attributes.Group == test.group && attributes.Resource == test.resource && attributes.Verb == test.verb
			}}
			_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, test.action)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
			if err == nil || !strings.Contains(err.Error(), "denied") {
				t.Fatalf("omitted read was accepted: %v", err)
			}
		})
	}
}

func TestM040CheckRequestsPodPatchAndPassesWhenGranted(t *testing.T) {
	reviews := &recordingSSAR{}
	if _, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRequestDrain)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"}); err != nil {
		t.Fatal(err)
	}
	var patch, update bool
	for _, attributes := range reviews.attributes {
		if attributes.Namespace == "tenant" && attributes.Resource == "pods" {
			patch = patch || attributes.Verb == "patch"
			update = update || attributes.Verb == "update"
		}
	}
	if !patch || update {
		t.Fatalf("request-drain startup inventory patch=%t update=%t: %+v", patch, update, reviews.attributes)
	}
}

type errorReader struct {
	client.Reader
	err error
}

func (r errorReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return r.err
}

func TestRouteCutoverStartupAuthorizationMatchesExactLifecycle(t *testing.T) {
	for _, action := range []v1alpha1.ActionType{v1alpha1.ActionRouteRotate, v1alpha1.ActionEndpointRotate} {
		t.Run(string(action), func(t *testing.T) {
			reviews := &recordingSSAR{}
			_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, action)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator"})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{
				"tenant|/pods:get": false, "tenant|/pods:list": false, "tenant|/pods:patch": false,
				"tenant|/services:get": false, "tenant|/services:list": false, "tenant|/services:update": false,
				"tenant|discovery.k8s.io/endpointslices:list": false,
				"tenant|phorvex.ai/phorvexpolicies:get":       false,
				"|/namespaces:get":                            false,
				"operator|/configmaps:get":                    false, "operator|/configmaps:list": false, "operator|/configmaps:create": false, "operator|/configmaps:update": false, "operator|/configmaps:delete": false,
			}
			for _, attributes := range reviews.attributes {
				key := attributes.Namespace + "|" + attributes.Group + "/" + attributes.Resource + ":" + attributes.Verb
				if _, ok := want[key]; ok {
					want[key] = true
				}
			}
			for requirement, found := range want {
				if !found {
					t.Errorf("missing %s", requirement)
				}
			}
		})
	}
}
