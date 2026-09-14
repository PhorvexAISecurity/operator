package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type m126CountingClient struct {
	client.Client
	creates, updates int
	createErr        error
	updateErr        error
	getErr           error
}

func (c *m126CountingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.getErr != nil {
		return c.getErr
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *m126CountingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.creates++
	if c.createErr != nil {
		return c.createErr
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *m126CountingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if c.updateErr != nil {
		return c.updateErr
	}
	return c.Client.Update(ctx, obj, opts...)
}

func m126Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func m126Target(namespace, tenant string) TenantTarget {
	return TenantTarget{Namespace: namespace, Tenant: tenant, MatchLabels: map[string]string{"app": "new"}}
}

func TestM126EnsurePolicyProducesBoundedMetadataFromFullIdentity(t *testing.T) {
	tests := []struct {
		name, namespace, tenant, wantLegacyName, wantLegacyLabel string
	}{
		{name: "short unchanged", namespace: "ns", tenant: "team-a", wantLegacyName: "phorvex-ns-team-a", wantLegacyLabel: "team-a"},
		{name: "valid noncanonical bytes unchanged", namespace: "ns", tenant: "Team_A", wantLegacyName: "phorvex-ns-team-a", wantLegacyLabel: "team-a"},
		{name: "70 byte tenant", namespace: "vllm", tenant: strings.Repeat("t", 70), wantLegacyName: "phorvex-vllm-" + strings.Repeat("t", 70)},
		{name: "maximum namespace and long tenant", namespace: strings.Repeat("n", 63), tenant: strings.Repeat("t", 250)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()
			pa := NewPhoenixActuator(base)
			if err := pa.EnsurePolicy(context.Background(), m126Target(tc.namespace, tc.tenant)); err != nil {
				t.Fatalf("EnsurePolicy: %v", err)
			}
			var list amtdv1beta1.AdaptiveMovingTargetDefenseList
			if err := base.List(context.Background(), &list); err != nil || len(list.Items) != 1 {
				t.Fatalf("List: %v, items=%d", err, len(list.Items))
			}
			got := &list.Items[0]
			if errs := validation.IsDNS1123Subdomain(got.Name); len(errs) != 0 || len(got.Name) > 253 {
				t.Fatalf("invalid name len=%d: %v", len(got.Name), errs)
			}
			label := got.Labels["phorvex.ai/tenant"]
			if errs := validation.IsValidLabelValue(label); len(errs) != 0 || len(label) > 63 {
				t.Fatalf("invalid label len=%d: %v", len(label), errs)
			}
			if tc.wantLegacyName != "" && got.Name != tc.wantLegacyName {
				t.Errorf("name=%q want unchanged %q", got.Name, tc.wantLegacyName)
			}
			if tc.wantLegacyLabel != "" && label != tc.wantLegacyLabel {
				t.Errorf("label=%q want unchanged %q", label, tc.wantLegacyLabel)
			}
			if got.Annotations[identityVersionAnnotation] != metadataIdentityVersion || got.Annotations[rawNamespaceAnnotation] != tc.namespace || got.Annotations[rawTenantAnnotation] != tc.tenant {
				t.Errorf("raw identity not preserved: %#v", got.Annotations)
			}
		})
	}
}

func TestM126EncodersHashFullRawIdentityDeterministically(t *testing.T) {
	prefix := strings.Repeat("a", 220)
	a, b := prefix+"x", prefix+"y"
	if tenantLabel(a) == tenantLabel(b) || amtdName(strings.Repeat("n", 63), a) == amtdName(strings.Repeat("n", 63), b) {
		t.Fatal("different full raw identities collapsed to the same bounded output")
	}
	if tenantLabel(a) != tenantLabel(a) || amtdName(strings.Repeat("n", 63), a) != amtdName(strings.Repeat("n", 63), a) {
		t.Fatal("bounded encoders are nondeterministic")
	}
}

func TestM126ActuatePreservesIdentityAndCoverageAnnotations(t *testing.T) {
	base := fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()
	value := 0.75
	tenant := strings.Repeat("t", 70)
	res, err := NewPhoenixActuator(base).Actuate(context.Background(), Request{Namespace: "ns", Tenant: tenant, Pod: "pod", Action: model.ActionRotate, CoverageValue: &value})
	if err != nil || !res.Emitted {
		t.Fatalf("Actuate result=%+v err=%v", res, err)
	}
	var list amtdv1beta1.SecurityEventList
	if err := base.List(context.Background(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("List: %v items=%d", err, len(list.Items))
	}
	got := list.Items[0]
	if got.Annotations[rawTenantAnnotation] != tenant || got.Annotations[rawNamespaceAnnotation] != "ns" || got.Annotations[identityVersionAnnotation] != metadataIdentityVersion {
		t.Errorf("identity annotations=%#v", got.Annotations)
	}
	if got.Annotations["phorvex.ai/coverage-contract"] == "" || got.Annotations["phorvex.ai/coverage-status"] != "present" || got.Spec.Metrics["coverageValue"] != "0.75" {
		t.Errorf("coverage metadata lost: annotations=%#v metrics=%#v", got.Annotations, got.Spec.Metrics)
	}
	if errs := validation.IsValidLabelValue(got.Labels["phorvex.ai/tenant"]); len(errs) != 0 {
		t.Errorf("tenant label invalid: %v", errs)
	}
}

func TestM126EnsurePolicyOwnershipChecks(t *testing.T) {
	tests := []struct {
		name        string
		tenant      string
		labels      map[string]string
		annotations map[string]string
		wantErr     bool
	}{
		{name: "matching stamped", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}, annotations: identityAnnotations("ns", "team-a")},
		{name: "canonical legacy adoption", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}},
		{name: "noncanonical legacy ambiguous", tenant: "Team_A", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}, wantErr: true},
		{name: "foreign marker", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "customer", "phorvex.ai/tenant": "team-a"}, annotations: identityAnnotations("ns", "team-a"), wantErr: true},
		{name: "wrong identity", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}, annotations: identityAnnotations("ns", "other"), wantErr: true},
		{name: "partial identity", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}, annotations: map[string]string{identityVersionAnnotation: metadataIdentityVersion}, wantErr: true},
		{name: "unknown identity", tenant: "team-a", labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "team-a"}, annotations: map[string]string{identityVersionAnnotation: "v2", rawNamespaceAnnotation: "ns", rawTenantAnnotation: "team-a"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			annotations := mergeAnnotations(map[string]string{"example.com/unrelated": "keep"}, tc.annotations)
			old := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: amtdName("ns", tc.tenant), Labels: tc.labels, Annotations: annotations}, Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{PodSelector: map[string]string{"app": "old"}}}
			base := fake.NewClientBuilder().WithScheme(m126Scheme(t)).WithObjects(old).Build()
			counting := &m126CountingClient{Client: base}
			err := NewPhoenixActuator(counting).EnsurePolicy(context.Background(), m126Target("ns", tc.tenant))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			var got amtdv1beta1.AdaptiveMovingTargetDefense
			if err := base.Get(context.Background(), client.ObjectKeyFromObject(old), &got); err != nil {
				t.Fatal(err)
			}
			if tc.wantErr {
				if counting.updates != 0 || got.Spec.PodSelector["app"] != "old" {
					t.Fatalf("refusal wrote object: updates=%d selector=%v", counting.updates, got.Spec.PodSelector)
				}
			} else if counting.updates != 1 || got.Annotations[rawTenantAnnotation] != tc.tenant || got.Annotations["example.com/unrelated"] != "keep" || got.Spec.PodSelector["app"] != "new" {
				t.Fatalf("successful update missing: updates=%d annotations=%v selector=%v", counting.updates, got.Annotations, got.Spec.PodSelector)
			}
		})
	}
}

func TestM126RejectsInvalidOrOversizedIdentityBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name, namespace, tenant string
	}{
		{name: "invalid namespace", namespace: "Not_A_Namespace", tenant: "tenant"},
		{name: "oversized annotations", namespace: "ns", tenant: strings.Repeat("t", 300000)},
		{name: "invalid utf8", namespace: "ns", tenant: string([]byte{0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()}
			pa := NewPhoenixActuator(base)
			if err := pa.EnsurePolicy(context.Background(), m126Target(tc.namespace, tc.tenant)); err == nil || base.creates != 0 || base.updates != 0 {
				t.Fatalf("EnsurePolicy err=%v creates=%d updates=%d", err, base.creates, base.updates)
			}
			if _, err := pa.Actuate(context.Background(), Request{Namespace: tc.namespace, Tenant: tc.tenant, Pod: "pod", Action: model.ActionRotate}); err == nil || base.creates != 0 {
				t.Fatalf("Actuate err=%v creates=%d", err, base.creates)
			}
		})
	}
}

func TestM126ClientCreateErrorsRemainVisible(t *testing.T) {
	want := errors.New("injected create failure")
	base := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build(), createErr: want}
	if err := NewPhoenixActuator(base).EnsurePolicy(context.Background(), m126Target("ns", "tenant")); !errors.Is(err, want) {
		t.Fatalf("EnsurePolicy error=%v, want wrapped create error", err)
	}
	if _, err := NewPhoenixActuator(base).Actuate(context.Background(), Request{Namespace: "ns", Tenant: "tenant", Pod: "pod", Action: model.ActionRotate}); !errors.Is(err, want) {
		t.Fatalf("Actuate error=%v, want wrapped create error", err)
	}
}

func TestM126ClientGetAndUpdateErrorsRemainVisible(t *testing.T) {
	wantGet := errors.New("injected get failure")
	getClient := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build(), getErr: wantGet}
	if err := NewPhoenixActuator(getClient).EnsurePolicy(context.Background(), m126Target("ns", "tenant")); !errors.Is(err, wantGet) {
		t.Fatalf("EnsurePolicy get error=%v", err)
	}

	old := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: amtdName("ns", "tenant"), Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": "tenant"}, Annotations: identityAnnotations("ns", "tenant")}}
	wantUpdate := errors.New("injected update failure")
	updateClient := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).WithObjects(old).Build(), updateErr: wantUpdate}
	if err := NewPhoenixActuator(updateClient).EnsurePolicy(context.Background(), m126Target("ns", "tenant")); !errors.Is(err, wantUpdate) {
		t.Fatalf("EnsurePolicy update error=%v", err)
	}
}
