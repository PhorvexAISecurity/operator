/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * credential-revoke: invalidate a STOLEN ServiceAccount bearer credential. After a trusted
 * observation that a pod's legacy service-account-token Secret was exfiltrated and is being
 * reused, this deletes exactly that detector-named token Secret for the named ServiceAccount
 * (and drops the stale reference from the SA). The kube-apiserver's service-account-lookup then
 * stops authenticating that bearer token. It is the one defense rotate/quarantine/network-isolate
 * cannot give — an external attacker already HOLDS the token, so acting on the pod does nothing.
 * FORWARD-ONLY: a revoked credential is not un-revoked; a fresh token is issued instead. The pod
 * is never touched (its own projected/bound token keeps working), so it stays Ready + in-service.
 */

package actuator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type credentialRevokeHandler struct{}

func (credentialRevokeHandler) Name() string { return string(model.ActionCredentialRevoke) }

func (credentialRevokeHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	if ec.Reader == nil || ec.Client == nil {
		return HandlerResult{}, fmt.Errorf("credential-revoke: authoritative client unavailable")
	}
	o := req.CredentialRevokeObservation
	if o == nil || o.ServiceAccountName == "" || len(o.CredentialSecrets) == 0 {
		return HandlerResult{}, fmt.Errorf("credential-revoke: no bound stolen-credential observation on the request")
	}

	// Enact-time authority re-check: the selection-time observation must still bind THIS exact
	// live Pod UID. The SA + Secret set is operator/detector-declared and never attacker-widened.
	p := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, p); err != nil {
		return HandlerResult{}, err
	}
	if p.UID == "" || o.TargetPodUID != string(p.UID) || (req.TargetUID != "" && req.TargetUID != string(p.UID)) {
		return HandlerResult{}, fmt.Errorf("credential-revoke: target UID unavailable or mismatched")
	}

	touched := make([]string, 0, len(o.CredentialSecrets)+1)
	deleted := make([]string, 0, len(o.CredentialSecrets))
	alreadyGone := 0
	for _, name := range o.CredentialSecrets {
		sec := &corev1.Secret{}
		err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: name}, sec)
		if apierrors.IsNotFound(err) {
			alreadyGone++
			continue
		}
		if err != nil {
			return HandlerResult{}, fmt.Errorf("credential-revoke: read secret %s/%s: %w", req.Namespace, name, err)
		}
		// SAFETY: delete ONLY a genuine service-account-token Secret bound to the named SA. The
		// trusted event can never widen the revocation to an arbitrary Secret (TLS/app data, etc.).
		if sec.Type != corev1.SecretTypeServiceAccountToken ||
			sec.Annotations[corev1.ServiceAccountNameKey] != o.ServiceAccountName {
			return HandlerResult{}, fmt.Errorf("credential-revoke: secret %s/%s is not a service-account-token for %q; refusing to delete",
				req.Namespace, name, o.ServiceAccountName)
		}
		del := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: req.Namespace}}
		if err := ec.Client.Delete(ctx, del); err != nil && !apierrors.IsNotFound(err) {
			return HandlerResult{}, fmt.Errorf("credential-revoke: delete secret %s/%s: %w", req.Namespace, name, err)
		}
		deleted = append(deleted, name)
		touched = append(touched, objRef("Secret", req.Namespace, name))
	}

	// Drop the stale secret reference(s) from the ServiceAccount so a reader never re-associates
	// the revoked credential. Best-effort + idempotent: a missing SA means the identity is already
	// gone (all its tokens are dead), so there is nothing left to detach.
	saPatched := false
	sa := &corev1.ServiceAccount{}
	saErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: o.ServiceAccountName}, sa)
	if saErr == nil {
		revoked := map[string]bool{}
		for _, n := range o.CredentialSecrets {
			revoked[n] = true
		}
		kept := make([]corev1.ObjectReference, 0, len(sa.Secrets))
		for _, ref := range sa.Secrets {
			if !revoked[ref.Name] {
				kept = append(kept, ref)
			}
		}
		if len(kept) != len(sa.Secrets) {
			after := sa.DeepCopy()
			after.Secrets = kept
			if err := ec.Client.Update(ctx, after); err != nil {
				// The credential Secret(s) are already deleted (the token is dead); only the
				// cosmetic SA reference strip is unconfirmed. Report but do not fail the revoke.
				touched = append(touched, objRef("ServiceAccount", req.Namespace, o.ServiceAccountName))
				return HandlerResult{ObjectsTouched: touched, MutationKind: "forward-only", Emitted: len(deleted) > 0,
					Note: fmt.Sprintf("credential-revoke: revoked token secret(s) %v for SA %q; SA reference-strip unconfirmed: %v", deleted, o.ServiceAccountName, err)}, nil
			}
			saPatched = true
			touched = append(touched, objRef("ServiceAccount", req.Namespace, o.ServiceAccountName))
		}
	} else if !apierrors.IsNotFound(saErr) {
		return HandlerResult{}, fmt.Errorf("credential-revoke: read serviceaccount %s/%s: %w", req.Namespace, o.ServiceAccountName, saErr)
	}

	if len(deleted) == 0 && !saPatched {
		// Nothing to do: every named token Secret was already gone and the SA carried no stale
		// reference. The credential is already revoked — a closed, reviewed no-effect. A reconciled
		// no-op must carry NO mutation evidence (MutationKind "none", no ObjectsTouched), or the
		// manager's result-consistency check (noEffectDisposition) reduces it to Unknown and flags
		// a contradictory result on every idempotent repeat fire.
		return HandlerResult{MutationKind: "none", NoEffect: NoEffectReconciled,
			Note: fmt.Sprintf("credential-revoke: credential for SA %q already revoked (%d token secret(s) absent); reconciled", o.ServiceAccountName, alreadyGone)}, nil
	}

	return HandlerResult{
		ObjectsTouched: touched,
		MutationKind:   "forward-only",
		Emitted:        true,
		Note: fmt.Sprintf("credential-revoke: revoked token secret(s) %v for SA %q (UID=%s); apiserver service-account-lookup now rejects those bearer tokens; pod untouched and in-service",
			deleted, o.ServiceAccountName, string(p.UID)),
	}, nil
}

func init() { HandlerRegistry.Register(credentialRevokeHandler{}) }
