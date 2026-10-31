package console

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// identityRotationCatalogueBinding reuses the one reviewed, deployment-owned
// identity fixture and its physical credential oracle. It does not change the
// original AML.T0012 adapter. The only additive behavior is accepting the other
// exact catalogue IDs already pinned to the same family/event/action profile.
type identityRotationCatalogueBinding struct {
	server       *Server
	cfg          Config
	fixedCluster identityCatalogCluster
}

type identityRotationPrivatePreparation struct {
	cluster   identityCatalogCluster
	fixture   identityCatalogFixture
	markerUID string
	signal    identityCatalogSignal
}

func (b *identityRotationCatalogueBinding) Availability(profile identityCatalogueProfile) AttackCatalogAdapterAvailability {
	availability := AttackCatalogAdapterAvailability{
		TargetLabel:       "This cluster (server-fixed)",
		UnavailableReason: profile.ID + " reviewed identity-fixture profile is unavailable or invalid.",
	}
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueRotation {
		availability.UnavailableReason = "identity-rotation catalogue metadata binding is invalid."
		return availability
	}
	if !b.cfg.AttackCatalogEnabled {
		availability.UnavailableReason = profile.ID + " launch adapter is not enabled by this deployment."
		return availability
	}
	if b.cfg.Service == ServiceConsole {
		availability.UnavailableReason = profile.ID + " is served by the attacks service; no attacks-service runtime is active here."
		return availability
	}
	if b.cfg.AuditSource == nil {
		availability.UnavailableReason = profile.ID + " requires the authenticated manager audit source."
		return availability
	}
	fixtureProfile, err := identityfixture.LoadFile(b.cfg.AttackCatalogIdentityProfilePath)
	if err != nil || b.cfg.AttackCatalogAuthorizationTenant == "" || b.cfg.AttackCatalogIdentityTenant == "" ||
		fixtureProfile.Namespace != b.cfg.AttackCatalogIdentityTenant {
		return availability
	}
	availability.Available = true
	availability.UnavailableReason = ""
	availability.RunnableNote = "Server-fixed identity-rotation validation; authoritative fixture and policy admission are repeated at launch."
	availability.RuntimeContext = defaultTargetID
	availability.FixtureTenant = fixtureProfile.Namespace
	return availability
}

func (b *identityRotationCatalogueBinding) Destination(profile identityCatalogueProfile) (runDestination, error) {
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueRotation {
		return runDestination{}, errors.New("identity-rotation catalogue metadata binding is invalid")
	}
	if b.cfg.Service == ServiceConsole {
		if b.cfg.AttacksURL == "" || b.cfg.AttackCatalogAuthorizationTenant == "" {
			return runDestination{}, errors.New("identity-rotation attacks-service proxy destination is unavailable")
		}
		return identityRotationDestination(b.cfg), nil
	}
	if !b.Availability(profile).Available {
		return runDestination{}, errors.New("identity-rotation launch adapter is unavailable in this attacks-service deployment")
	}
	return identityRotationDestination(b.cfg), nil
}

func identityRotationDestination(cfg Config) runDestination {
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: cfg.AttackCatalogAuthorizationTenant}
}

func (b *identityRotationCatalogueBinding) Preflight(ctx context.Context, profile identityCatalogueProfile) (*identityCatalogueBindingPreparation, error) {
	if !b.Availability(profile).Available {
		return nil, errors.New("reviewed identity-rotation binding is unavailable")
	}
	cluster := b.fixedCluster
	if cluster == nil {
		if b.server == nil {
			return nil, errors.New("identity-rotation server runtime is unavailable")
		}
		fixtureProfile, err := identityfixture.LoadFile(b.cfg.AttackCatalogIdentityProfilePath)
		if err != nil || fixtureProfile.Namespace != b.cfg.AttackCatalogIdentityTenant {
			return nil, errors.New("reviewed identity fixture profile is unavailable")
		}
		cluster, err = b.server.attackCatalogCluster(fixtureProfile)
		if err != nil {
			return nil, err
		}
	}
	fixture, err := cluster.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	trigger := AttackCatalogTriggerProactiveReactive
	if fixture.ReactiveOnly {
		trigger = AttackCatalogTriggerReactive
	}
	private := &identityRotationPrivatePreparation{cluster: cluster, fixture: fixture}
	return &identityCatalogueBindingPreparation{
		Execution: AttackCatalogExecutionActive, Trigger: trigger, EvidenceTenant: fixture.Namespace,
		Namespace: fixture.Namespace, PodName: fixture.PodName, TargetUID: fixture.PodUID,
		PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration,
		ReceiptObject: identityServiceAccountObject(fixture), private: private,
	}, nil
}

func (b *identityRotationCatalogueBinding) Launch(ctx context.Context, profile identityCatalogueProfile, run AttackCatalogRunContext, prepared *identityCatalogueBindingPreparation) (identityCatalogueBindingSignal, bool, error) {
	private, ok := identityRotationPrivate(prepared)
	if !ok || run.CatalogueID != profile.ID || run.ExpectedAction != profile.ExpectedAction {
		return identityCatalogueBindingSignal{}, false, errors.New("identity-rotation launch preparation changed")
	}
	markerUID, err := private.cluster.CreateMarker(ctx, private.fixture, time.Now().UTC())
	if err != nil {
		return identityCatalogueBindingSignal{}, false, err
	}
	private.markerUID = markerUID
	entry, ok := attackcatalog.Lookup(profile.ID)
	if !ok || validateIdentityCatalogueProfile(profile) != nil || entry.ID != run.CatalogueID {
		return identityCatalogueBindingSignal{}, true, errors.New("identity-rotation catalogue entry changed before launch")
	}
	signal, err := createIdentityRotationFamilySignal(ctx, private.cluster, entry, private.fixture, run.RunID)
	private.signal = signal
	bound := identityCatalogueBindingSignal{Name: signal.Name, UID: signal.UID, Creator: signal.Creator, CreatedAt: signal.CreatedAt}
	if err != nil {
		return bound, true, err
	}
	return bound, true, nil
}

func (b *identityRotationCatalogueBinding) Physical(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation) (identityCataloguePhysicalObservation, error) {
	private, ok := identityRotationPrivate(prepared)
	if !ok || profile.Family != identityCatalogueRotation {
		return identityCataloguePhysicalObservation{}, errors.New("identity-rotation physical preparation changed")
	}
	physical, err := private.cluster.Physical(ctx, private.fixture)
	if err != nil {
		return identityCataloguePhysicalObservation{}, err
	}
	return identityCataloguePhysicalObservation{
		OldServiceAccountUID: physical.OldServiceAccountUID, NewServiceAccountUID: physical.NewServiceAccountUID,
		PodUID: physical.PodUID, CredentialAuthenticatedBefore: physical.CredentialAuthenticatedBefore,
		CredentialAuthenticatedAfter: physical.CredentialAuthenticatedAfter, PodRetained: physical.PodRetained,
	}, nil
}

func (b *identityRotationCatalogueBinding) Cleanup(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) (identityCatalogueCleanupObservation, error) {
	private, ok := identityRotationPrivate(prepared)
	if !ok || profile.Family != identityCatalogueRotation {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("identity-rotation cleanup preparation changed")
	}
	// Use only the signal retained by the binding. A substituted caller value
	// cannot redirect cleanup to another event.
	if signal.Name != private.signal.Name || signal.UID != private.signal.UID || signal.Creator != private.signal.Creator {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("identity-rotation cleanup signal binding changed")
	}
	cleaned := private.cluster.Cleanup(ctx, private.fixture, private.signal, private.markerUID)
	return identityCatalogueCleanupObservation{Attempted: cleaned.Attempted,
		EventAbsent: cleaned.EventDeleted, FixtureRestored: cleaned.MarkerDeleted}, nil
}

func identityRotationPrivate(prepared *identityCatalogueBindingPreparation) (*identityRotationPrivatePreparation, bool) {
	if prepared == nil {
		return nil, false
	}
	private, ok := prepared.private.(*identityRotationPrivatePreparation)
	return private, ok && private != nil && private.cluster != nil
}

func createIdentityRotationFamilySignal(ctx context.Context, cluster identityCatalogCluster, entry attackcatalog.Entry, fixture identityCatalogFixture, runID string) (identityCatalogSignal, error) {
	if entry.ID == attackcatalog.FirstID || entry.Family != string(identityCatalogueRotation) ||
		entry.EventType != model.AttackVectorPodBoundAPIAuth || entry.ExpectedAction != string(model.ActionIdentityRotate) {
		return identityCatalogSignal{}, errors.New("catalogue entry has no additive identity-rotation signal adapter")
	}
	if kube, ok := cluster.(*kubernetesIdentityCatalogCluster); ok {
		return kube.createIdentityRotationFamilySignal(ctx, entry, fixture, runID)
	}
	// Package-local test clusters may implement the generic entry directly. The
	// production Kubernetes implementation above never takes this fallback.
	return cluster.CreateSignal(ctx, entry, fixture, runID)
}

func (k *kubernetesIdentityCatalogCluster) createIdentityRotationFamilySignal(ctx context.Context, entry attackcatalog.Entry, fixture identityCatalogFixture, runID string) (identityCatalogSignal, error) {
	random := make([]byte, 6)
	if _, err := cryptorand.Read(random); err != nil {
		return identityCatalogSignal{}, errors.New("identity-rotation signal identity generation failed")
	}
	name := "catalog-identity-" + hex.EncodeToString(random)
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{
			"name":   name,
			"labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": catalogueIDLabelValue(entry.ID)},
			"annotations": map[string]any{model.ConsoleTargetPodUIDAnnotation: fixture.PodUID,
				attackCatalogCorrelationAnnotation: runID, catalogueIDAnnotationKey: entry.ID},
		},
		"spec": map[string]any{
			"description": entry.Description, "targets": []any{fixture.Namespace + "/" + fixture.PodName},
			"rule": map[string]any{"type": entry.EventType, "threatLevel": "critical", "source": "console-catalogue"},
		},
	}}
	created, err := k.dynamic.Resource(securityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		return identityCatalogSignal{Name: name}, errors.New("identity-rotation catalogue signal admission failed")
	}
	if created.GetUID() == "" {
		return identityCatalogSignal{Name: name}, errors.New("identity-rotation catalogue signal admission returned no stable identity")
	}
	creator := created.GetAnnotations()["phorvex.ai/creator-identity"]
	admitted := identityCatalogSignal{Name: name, UID: string(created.GetUID()), Creator: creator,
		CreatedAt: created.GetCreationTimestamp().Time}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	ruleType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	if admitted.CreatedAt.IsZero() || created.GetName() != name || creator != eventtrust.Injector() ||
		created.GetLabels()["phorvex.ai/catalogue-id"] != catalogueIDLabelValue(entry.ID) ||
		created.GetAnnotations()[catalogueIDAnnotationKey] != entry.ID ||
		created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != fixture.PodUID ||
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] != runID ||
		!slices.Equal(targets, []string{fixture.Namespace + "/" + fixture.PodName}) || ruleType != entry.EventType {
		uid := created.GetUID()
		_ = k.dynamic.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return admitted, errors.New("identity-rotation catalogue signal identity or target admission differs")
	}
	return admitted, nil
}

var _ identityCatalogueFamilyBinding = (*identityRotationCatalogueBinding)(nil)
