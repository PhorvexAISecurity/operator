package codeexec

import (
 "context"
 "encoding/json"
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
 if len(p.Spec.Validations) != 9 || len(p.Spec.Variables) != 3 { t.Fatal("fixture is not reviewed production manifest") }
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
 if snapshot.Labels[ManagedLabelKey]!=ManagedLabelVal {t.Fatal("initial snapshot not managed")}
 v:=New(NewK8sReader(cs),Config{})
 if ok,why:=v.FinalCheck(ctx,ns.Name); !ok {t.Fatalf("initial legitimate control: %s",why)}
 ns.Labels=map[string]string{}
 if _,err:=cs.CoreV1().Namespaces().Update(ctx,ns,metav1.UpdateOptions{}); err!=nil {t.Fatal(err)}
 current,err:=cs.CoreV1().Namespaces().Get(ctx,ns.Name,metav1.GetOptions{})
 if err!=nil || current.Labels[ManagedLabelKey]==ManagedLabelVal {t.Fatal("fixture did not remove managed scope")}
 cs.ClearActions()
 ok,why:=v.FinalCheck(ctx,ns.Name)
 reads:=0
 for _,a:=range cs.Actions(){if a.GetVerb()=="get" && a.GetResource().Resource=="namespaces" {reads++}}
 if ok {t.Fatalf("stale snapshot authorized submit after label removed: ok=%v reason=%q fresh namespace GETs=%d",ok,why,reads)}
}

func TestReviewerRejectsClusterOnlyScope(t *testing.T) {
 p,b:=reviewFixture(t)
 scope:=admissionv1.ClusterScope
 p.Spec.MatchConstraints.ResourceRules[0].Scope=&scope
 v:=New(NewK8sReader(reviewClient(p,b)),Config{})
 err:=v.Verify(context.Background())
 ok,why:=v.Available(map[string]string{ManagedLabelKey:ManagedLabelVal})
 if err==nil || ok {t.Fatalf("Cluster-only scope cannot protect namespaced pods: Verify=%v Available=%v reason=%q",err,ok,why)}
}

func TestReviewerInvalidationDuringFinalScopeReadStopsSubmit(t *testing.T) {
 p,b:=reviewFixture(t)
 ns:=&corev1.Namespace{ObjectMeta:metav1.ObjectMeta{Name:"managed-fixture",Labels:map[string]string{ManagedLabelKey:ManagedLabelVal}}}
 cs:=reviewClient(p,b,ns)
 v:=New(NewK8sReader(cs),Config{})
 cs.PrependReactor("get","namespaces",func(a ktesting.Action)(bool,runtime.Object,error){
  v.Invalidate("concurrent poll observed policy removed during final namespace read")
  return false,nil,nil
 })
 ok,why:=v.FinalCheck(context.Background(),ns.Name)
 available,detail:=v.Status()
 if ok {t.Fatalf("FinalCheck authorized despite observed invalidation: ok=%v reason=%q globalAvailable=%v detail=%q",ok,why,available,detail)}
}

func TestReviewerAllowsActualAPIDefaultedContract(t *testing.T) {
 raw,err:=os.ReadFile("/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/p3/rev2/api-defaulted-objects.json")
 if err!=nil {t.Fatal(err)}
 var docs []json.RawMessage
 if err:=json.Unmarshal(raw,&docs); err!=nil {t.Fatal(err)}
 if len(docs)!=2 {t.Fatal("expected both server dry-run responses")}
 p,b:=&admissionv1.ValidatingAdmissionPolicy{},&admissionv1.ValidatingAdmissionPolicyBinding{}
 if err:=json.Unmarshal(docs[0],p); err!=nil {t.Fatal(err)}
 if err:=json.Unmarshal(docs[1],b); err!=nil {t.Fatal(err)}
 if p.Spec.MatchConstraints.ObjectSelector==nil || b.Spec.MatchResources.ObjectSelector==nil {t.Fatal("fixture must contain actual API defaults")}
 t.Run("policy",func(t *testing.T){if why:=validatePolicyContent(p); why!="" {t.Fatalf("valid server-defaulted policy rejected: %s",why)}})
 t.Run("binding",func(t *testing.T){if why:=validateBindingContent(b); why!="" {t.Fatalf("valid server-defaulted binding rejected: %s",why)}})
 v:=New(NewK8sReader(reviewClient(p,b)),Config{})
 if err:=v.Verify(context.Background()); err!=nil {t.Fatalf("actual server-defaulted install cannot become available: %v",err)}
}

func TestReviewerNamespaceReadFailureInvalidates(t *testing.T) {
 p,b:=reviewFixture(t)
 cs:=reviewClient(p,b)
 v:=New(NewK8sReader(cs),Config{})
 cs.PrependReactor("get","namespaces",func(a ktesting.Action)(bool,runtime.Object,error){return true,nil,context.DeadlineExceeded})
 before:=v.epoch.Load()
 ok,_:=v.FinalCheck(context.Background(),"managed-fixture")
 available,detail:=v.Status()
 if ok || available || v.epoch.Load()==before {t.Fatalf("partial read failure did not invalidate: FinalCheck=%v Available=%v detail=%q epochBefore=%d epochAfter=%d",ok,available,detail,before,v.epoch.Load())}
}
