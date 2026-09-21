package capability

import (
	"context"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

type m001CaptureSSAR struct {
	attributes []authorizationv1.ResourceAttributes
}

func (c *m001CaptureSSAR) Create(_ context.Context, review *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	c.attributes = append(c.attributes, *review.Spec.ResourceAttributes)
	review.Status.Allowed = true
	return review, nil
}

func TestM001NativeRuntimeReviewsNativeRotatePermission(t *testing.T) {
	reviews := &m001CaptureSSAR{}
	checker := authz.NewCheckerWithClient(reviews, time.Minute)
	witness := BuildWitness(t.Context(), BuildIndex(nil, nil, nil), nil, checker, actuator.NewNativeActuator(nil))
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "tenant", Name: "target"}}
	if reason := witness.Eligible(view, model.ActionRotate, []string{"cover"}); reason != nil {
		t.Fatalf("native rotate excluded: %+v", reason)
	}
	if len(reviews.attributes) != 1 {
		t.Fatalf("reviews=%+v", reviews.attributes)
	}
	got := reviews.attributes[0]
	if got.Namespace != "tenant" || got.Group != "" || got.Resource != "pods" || got.Subresource != "eviction" || got.Verb != "create" {
		t.Fatalf("native runtime reviewed wrong route: %+v", got)
	}
}
