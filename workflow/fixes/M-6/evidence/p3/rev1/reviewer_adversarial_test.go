package codeexec

import (
 "context"
 "os"
 "strings"
 "testing"

 admissionv1 "k8s.io/api/admissionregistration/v1"
 authorizationv1 "k8s.io/api/authorization/v1"
 corev1 "k8s.io/api/core/v1"
 metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
 "k8s.io/apimachinery/pkg/runtime"
 "k8s.io/client-go/kubernetes/fake"
 ktesting "k8s.io/client-go/testing"
 "sigs.k8s.io/yaml"
)

// Transport fixture only: the actual K8sReader projection and Verifier run unchanged.
// This does not simulate API admission, RBAC enforcement, or prove CEL semantics.
func reviewFixture(t *testing.T) (*admissionv1.ValidatingAdmissionPolicy, *admissionv1.ValidatingAdmissionPolicyBinding) {
 t.Helper()
 raw, err := os.ReadFile("../../config/admission/codeexec-ephemeral-vap.yaml")
 if err != nil { t.Fatal(err) }
 docs := strings.Split(string(raw), "\n---\n")
 if len(docs) != 2 { t.Fatalf("expected policy + binding, got %d", len(docs)) }
 p := &admissionv1.ValidatingAdmissionPolicy{}
 b := &admissionv1.ValidatingAdmissionPolicyBinding{}
 if err := yaml.Unmarshal([]byte(docs[0]), p); err != nil { t.Fatal(err) }
 if err := yaml.Unmarshal([]byte(docs[1]), b); err != nil { t.Fatal(err) }
 if len(p.Spec.Validations) != 8 || len(p.Spec.Variables) != 3 { t.Fatal("fixture is not reviewed production manifest") }
 return p,b
}

func reviewClient(p *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding, objs ...runtime.Object) *fake.Clientset {
 objs = append(objs,p,b)
 cs := fake.NewSimpleClientset(objs...)
 cs.PrependReactor("create", "selfsubjectaccessreviews", func(a ktesting.Action) (bool,runtime.Object,error) {
  return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed:true}},nil
 })
 return cs
}

func TestReviewerRejectsEnforcementDrift(t *testing.T) {
 cases := []struct{
  name string
  mutate func(*admissionv1.ValidatingAdmissionPolicy,*admissionv1.ValidatingAdmissionPolicyBinding)
 }{
  {"CEL-replaced-by-true",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){p.Spec.Validations=[]admissionv1.Validation{{Expression:"true"}}}},
  {"all-new-containers-hidden",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){p.Spec.Variables[2].Expression="[]"}},
  {"policy-match-condition-false",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){p.Spec.MatchConditions=[]admissionv1.MatchCondition{{Name:"skip",Expression:"false"}}}},
  {"wrong-resource-api-group",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){p.Spec.MatchConstraints.ResourceRules[0].APIGroups=[]string{"example.invalid"}}},
  {"binding-excludes-subresource",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){b.Spec.MatchResources.ExcludeResourceRules=p.Spec.MatchConstraints.ResourceRules}},
  {"binding-namespace-expression-excludes-target",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){b.Spec.MatchResources.NamespaceSelector.MatchExpressions=[]metav1.LabelSelectorRequirement{{Key:"team",Operator:metav1.LabelSelectorOpIn,Values:[]string{"restricted"}}}}},
  {"binding-object-selector-excludes-target",func(p *admissionv1.ValidatingAdmissionPolicy,b *admissionv1.ValidatingAdmissionPolicyBinding){b.Spec.MatchResources.ObjectSelector=&metav1.LabelSelector{MatchLabels:map[string]string{"only":"other-pods"}}}},
 }
 for _,tc := range cases {t.Run(tc.name,func(t *testing.T){
  p,b:=reviewFixture(t)
  tc.mutate(p,b)
  v:=New(NewK8sReader(reviewClient(p,b)),Config{})
  err:=v.Verify(context.Background())
  ok,why:=v.Available(map[string]string{ManagedLabelKey:ManagedLabelVal})
  if err==nil || ok {t.Fatalf("unsafe enforcement accepted: Verify=%v Available=%v reason=%q",err,ok,why)}
 })}
}

func TestReviewerProductionManifestPositiveControl(t *testing.T) {
 p,b:=reviewFixture(t)
 v:=New(NewK8sReader(reviewClient(p,b)),Config{})
 if err:=v.Verify(context.Background()); err!=nil {t.Fatal(err)}
 if ok,why:=v.Available(map[string]string{ManagedLabelKey:ManagedLabelVal}); !ok {t.Fatal(why)}
}

func TestReviewerFinalCheckRejectsNamespaceRemovedSinceSnapshot(t *testing.T) {
 ctx:=context.Background()
 p,b:=reviewFixture(t)
 ns:=&corev1.Namespace{ObjectMeta:metav1.ObjectMeta{Name:"managed-fixture",Labels:map[string]string{ManagedLabelKey:ManagedLabelVal}}}
 cs:=reviewClient(p,b,ns)
 snapshot,err:=cs.CoreV1().Namespaces().Get(ctx,ns.Name,metav1.GetOptions{})
 if err!=nil {t.Fatal(err)}
 v:=New(NewK8sReader(cs),Config{})
 if ok,why:=v.FinalCheck(ctx,snapshot.Labels); !ok {t.Fatalf("initial legitimate control: %s",why)}
 ns.Labels=map[string]string{}
 if _,err:=cs.CoreV1().Namespaces().Update(ctx,ns,metav1.UpdateOptions{}); err!=nil {t.Fatal(err)}
 current,err:=cs.CoreV1().Namespaces().Get(ctx,ns.Name,metav1.GetOptions{})
 if err!=nil || current.Labels[ManagedLabelKey]==ManagedLabelVal {t.Fatal("fixture did not remove managed scope")}
 cs.ClearActions()
 ok,why:=v.FinalCheck(ctx,snapshot.Labels)
 reads:=0
 for _,a:=range cs.Actions(){if a.GetVerb()=="get" && a.GetResource().Resource=="namespaces" {reads++}}
 if ok {t.Fatalf("stale snapshot authorized submit after label removed: ok=%v reason=%q fresh namespace GETs=%d",ok,why,reads)}
}
