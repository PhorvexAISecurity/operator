/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 */

package codeexec

import (
	"context"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	admissionGroup  = "admissionregistration.k8s.io"
	policyResource  = "validatingadmissionpolicies"
	bindingResource = "validatingadmissionpolicybindings"
)

// k8sReader is the production PolicyReader: GET-by-resourceName over the typed
// admissionregistration/v1 client, resourceName-scoped SSARs, and a by-name namespace GET.
// It performs NO list/watch — exactly the minimal get-only grant the contract requires. It
// returns the FULL typed objects (no projection), so content verification sees every field.
type k8sReader struct {
	cs kubernetes.Interface
}

// NewK8sReader builds the production reader over a cluster clientset.
func NewK8sReader(cs kubernetes.Interface) PolicyReader { return &k8sReader{cs: cs} }

func (r *k8sReader) GetPolicy(ctx context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	p, err := r.cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, PolicyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *k8sReader) GetBinding(ctx context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	b, err := r.cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, PolicyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GetNamespaceLabels reads the CURRENT labels of one namespace by name (uncached).
func (r *k8sReader) GetNamespaceLabels(ctx context.Context, namespace string) (map[string]string, bool, error) {
	ns, err := r.cs.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return ns.Labels, true, nil
}

// CanRead confirms, via SelfSubjectAccessReview, that the operator may `get` BOTH named
// admission objects by resourceName. Both must be allowed; an SSAR error is unknown=true.
func (r *k8sReader) CanRead(ctx context.Context) (allowed, unknown bool, err error) {
	for _, res := range []string{policyResource, bindingResource} {
		ok, unk, e := r.ssarGet(ctx, res, PolicyName)
		if unk {
			return false, true, e
		}
		if !ok {
			return false, false, nil
		}
	}
	return true, false, nil
}

func (r *k8sReader) ssarGet(ctx context.Context, resource, name string) (allowed, unknown bool, err error) {
	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:    admissionGroup,
				Resource: resource,
				Verb:     "get",
				Name:     name,
			},
		},
	}
	res, err := r.cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, true, err
	}
	return res.Status.Allowed, false, nil
}

// unavailableReader is a PolicyReader whose every read fails — used at boot when a cluster
// clientset cannot be built, so the verifier is non-nil but permanently UNAVAILABLE.
type unavailableReader struct{ reason string }

// NewUnavailableReader builds a reader that always fails verification with the given reason.
func NewUnavailableReader(reason string) PolicyReader { return unavailableReader{reason: reason} }

func (r unavailableReader) GetPolicy(context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	return nil, verifyError(r.reason)
}
func (r unavailableReader) GetBinding(context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	return nil, verifyError(r.reason)
}
func (r unavailableReader) CanRead(context.Context) (bool, bool, error) {
	return false, true, verifyError(r.reason)
}
func (r unavailableReader) GetNamespaceLabels(context.Context, string) (map[string]string, bool, error) {
	return nil, false, verifyError(r.reason)
}
