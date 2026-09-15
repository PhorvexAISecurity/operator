package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

const policyCRDName = "phorvexpolicies.phorvex.ai"
const vocabularyRefreshInterval = 30 * time.Second
const vocabularyReadTimeout = 5 * time.Second

// ActionVocabulary is an immutable observation. A failed read retains only the
// previous identity as historical evidence; it never supplies a current exclusion.
type ActionVocabulary struct {
	Known           bool
	UID             types.UID
	ResourceVersion string
	ObservedAt      time.Time
	AttemptedAt     time.Time
	Error           string
	NotInstallable  model.InstallSet
}

func (v ActionVocabulary) clone() ActionVocabulary {
	out := v
	if v.NotInstallable != nil {
		out.NotInstallable = make(model.InstallSet, len(v.NotInstallable))
		for action := range v.NotInstallable {
			out.NotInstallable[action] = struct{}{}
		}
	}
	return out
}

func (v ActionVocabulary) diagnostic() (metav1.ConditionStatus, string, string) {
	if v.Known {
		return metav1.ConditionTrue, "SchemaObserved", fmt.Sprintf("PhorvexPolicy action enum observed at %s (CRD UID %s, resourceVersion %s); %d known actions absent", v.ObservedAt.UTC().Format(time.RFC3339), v.UID, v.ResourceVersion, len(v.NotInstallable))
	}
	if v.Error == "" {
		return metav1.ConditionUnknown, "Unobserved", "PhorvexPolicy action enum has not been observed; installability unverified"
	}
	msg := "PhorvexPolicy action enum unverified: " + v.Error
	if !v.ObservedAt.IsZero() {
		msg += fmt.Sprintf("; last known CRD UID %s resourceVersion %s observed at %s is historical only", v.UID, v.ResourceVersion, v.ObservedAt.UTC().Format(time.RFC3339))
	}
	return metav1.ConditionUnknown, "DiscoveryUnavailable", msg
}

func (v ActionVocabulary) traceEvidence() *model.PolicyActionVocabularyObservation {
	result := &model.PolicyActionVocabularyObservation{Known: v.Known, UID: string(v.UID), ResourceVersion: v.ResourceVersion, Error: v.Error}
	if !v.ObservedAt.IsZero() {
		result.ObservedAt = v.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if !v.AttemptedAt.IsZero() {
		result.AttemptedAt = v.AttemptedAt.UTC().Format(time.RFC3339Nano)
	}
	return result
}

// VocabularySnapshot returns a defensive copy so callers cannot mutate the
// manager's published map. A nil reader leaves the state explicitly unobserved.
func (m *Manager) VocabularySnapshot() ActionVocabulary {
	if p := m.vocabulary.Load(); p != nil {
		return p.clone()
	}
	return ActionVocabulary{}
}

func (m *Manager) refreshVocabulary(ctx context.Context, now time.Time) ActionVocabulary {
	previous := m.VocabularySnapshot()
	if !previous.AttemptedAt.IsZero() && now.Sub(previous.AttemptedAt) < vocabularyRefreshInterval {
		return previous
	}
	next := ActionVocabulary{AttemptedAt: now, UID: previous.UID, ResourceVersion: previous.ResourceVersion, ObservedAt: previous.ObservedAt}
	if m.VocabularyReader == nil {
		next.Error = "uncached CRD reader unavailable"
	} else {
		readCtx, cancel := context.WithTimeout(ctx, vocabularyReadTimeout)
		defer cancel()
		var crd apiextv1.CustomResourceDefinition
		if err := m.VocabularyReader.Get(readCtx, client.ObjectKey{Name: policyCRDName}, &crd); err != nil {
			next.Error = err.Error()
		} else if actions, err := installedPolicyActions(&crd); err != nil {
			next.Error = err.Error()
		} else {
			next.Known, next.UID, next.ResourceVersion, next.ObservedAt = true, crd.UID, crd.ResourceVersion, now
			next.NotInstallable = model.ComputeNotInstallable(actions)
		}
	}
	m.vocabulary.Store(&next)
	if !next.Known {
		m.Log.Info("PhorvexPolicy action vocabulary unverified", "reason", next.Error, "lastObservedAt", next.ObservedAt)
	}
	return next.clone()
}

// installedPolicyActions checks the served policy schema, not Phoenix actuator
// schemas. Multiple served versions must agree; ambiguity is an unknown read.
func installedPolicyActions(crd *apiextv1.CustomResourceDefinition) ([]model.Action, error) {
	if crd.Name != policyCRDName || crd.Spec.Group != v1alpha1.GroupVersion.Group || crd.Spec.Names.Kind != "PhorvexPolicy" || crd.Spec.Names.Plural != "phorvexpolicies" {
		return nil, fmt.Errorf("unexpected PhorvexPolicy CRD identity")
	}
	if crd.UID == "" || crd.ResourceVersion == "" || crd.DeletionTimestamp != nil {
		return nil, fmt.Errorf("PhorvexPolicy CRD has no current UID/resourceVersion or is deleting")
	}
	var selected []model.Action
	seenCurrent := false
	for _, version := range crd.Spec.Versions {
		if !version.Served {
			continue
		}
		if version.Name == v1alpha1.GroupVersion.Version {
			seenCurrent = true
		}
		if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			return nil, fmt.Errorf("served version %s lacks schema", version.Name)
		}
		schema := version.Schema.OpenAPIV3Schema
		spec, ok := schema.Properties["spec"]
		if !ok || spec.Type != "object" {
			return nil, fmt.Errorf("served version %s lacks spec object", version.Name)
		}
		actions, ok := spec.Properties["actions"]
		if !ok || actions.Type != "object" {
			return nil, fmt.Errorf("served version %s lacks actions object", version.Name)
		}
		enabled, ok := actions.Properties["enabled"]
		if !ok || enabled.Type != "array" || enabled.Items == nil || enabled.Items.Schema == nil || enabled.Items.Schema.Type != "string" {
			return nil, fmt.Errorf("served version %s lacks actions.enabled string items", version.Name)
		}
		enum := enabled.Items.Schema.Enum
		if len(enum) == 0 {
			return nil, fmt.Errorf("served version %s has no actions.enabled enum", version.Name)
		}
		values := make([]model.Action, 0, len(enum))
		unique := map[model.Action]bool{}
		for _, raw := range enum {
			var name string
			if err := json.Unmarshal(raw.Raw, &name); err != nil || strings.TrimSpace(name) == "" || unique[model.Action(name)] {
				return nil, fmt.Errorf("served version %s has malformed actions.enabled enum", version.Name)
			}
			unique[model.Action(name)] = true
			values = append(values, model.Action(name))
		}
		slices.Sort(values)
		if selected != nil && !slices.Equal(selected, values) {
			return nil, fmt.Errorf("served PhorvexPolicy versions have conflicting action enums")
		}
		selected = values
	}
	if !seenCurrent || selected == nil {
		return nil, fmt.Errorf("runtime PhorvexPolicy API version is not served")
	}
	return selected, nil
}
