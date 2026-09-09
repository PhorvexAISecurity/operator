package actuator

import (
 "context"
 "encoding/json"
 "fmt"
 "os"
 "strings"
 "testing"
 "time"

 admissionv1 "k8s.io/api/admissionregistration/v1"
 corev1 "k8s.io/api/core/v1"
 rbacv1 "k8s.io/api/rbac/v1"
 metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
 "k8s.io/apimachinery/pkg/runtime"
 "k8s.io/client-go/kubernetes"
 "k8s.io/client-go/rest"
 "sigs.k8s.io/controller-runtime/pkg/client"
 "sigs.k8s.io/controller-runtime/pkg/envtest"
 "sigs.k8s.io/yaml"
 "github.com/phorvex/phorvex/internal/model"
)

const incidentManager = "system:serviceaccount:phorvex-system:phorvex-phorvex-manager"
const incidentImage = "busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"

type incidentCapture struct {client.Client; captured *corev1.Pod}
type incidentSubresource struct {client.SubResourceClient; owner *incidentCapture}
func (c *incidentCapture) SubResource(s string) client.SubResourceClient {return &incidentSubresource{SubResourceClient:c.Client.SubResource(s),owner:c}}
func (s *incidentSubresource) Update(ctx context.Context,obj client.Object,opts ...client.SubResourceUpdateOption) error {
 s.owner.captured=obj.(*corev1.Pod).DeepCopy()
 return s.SubResourceClient.Update(ctx,obj,opts...)
}

func TestReviewerRealAPIIncident(t *testing.T) {
 ctx:=context.Background()
 existing:=false
 env:=&envtest.Environment{UseExistingCluster:&existing,BinaryAssetsDirectory:"/tmp/phorvex-m6-envtest/controller-tools/envtest",ControlPlaneStartTimeout:45*time.Second,ControlPlaneStopTimeout:20*time.Second}
 cfg,err:=env.Start();if err!=nil {t.Fatal(err)}
 defer func(){if err:=env.Stop();err!=nil {t.Errorf("stop isolated control plane: %v",err)}}()
 if !strings.Contains(cfg.Host,"127.0.0.1") && !strings.Contains(cfg.Host,"localhost") {t.Fatal("refuse non-loopback test API")}
 admin,err:=kubernetes.NewForConfig(cfg);if err!=nil {t.Fatal(err)}
 version,err:=admin.Discovery().ServerVersion();if err!=nil {t.Fatal(err)}
 t.Logf("ISOLATED API %s; service-account admission disabled by envtest; no nodes/runtime, all ephemeral submissions dryRun=All",version.GitVersion)
 schema:=runtime.NewScheme();corev1.AddToScheme(schema)
 for _,ns:=range []string{"managed-fixture","unmanaged-fixture"} {
  labels:=map[string]string{};if ns=="managed-fixture" {labels["phorvex.ai/codeexec-managed"]="true"}
  if _,err:=admin.CoreV1().Namespaces().Create(ctx,&corev1.Namespace{ObjectMeta:metav1.ObjectMeta{Name:ns,Labels:labels}},metav1.CreateOptions{});err!=nil {t.Fatal(err)}
  if _,err:=admin.CoreV1().Pods(ns).Create(ctx,&corev1.Pod{ObjectMeta:metav1.ObjectMeta{Name:"victim",Labels:map[string]string{"app":"fixture"}},Spec:corev1.PodSpec{Containers:[]corev1.Container{{Name:"app",Image:incidentImage}}}},metav1.CreateOptions{});err!=nil {t.Fatal(err)}
  role:=&rbacv1.Role{ObjectMeta:metav1.ObjectMeta{Name:"fixture-exec",Namespace:ns},Rules:[]rbacv1.PolicyRule{{APIGroups:[]string{""},Resources:[]string{"pods"},Verbs:[]string{"get"}},{APIGroups:[]string{""},Resources:[]string{"pods/ephemeralcontainers"},Verbs:[]string{"update"}}}}
  if _,err:=admin.RbacV1().Roles(ns).Create(ctx,role,metav1.CreateOptions{});err!=nil {t.Fatal(err)}
  binding:=&rbacv1.RoleBinding{ObjectMeta:metav1.ObjectMeta{Name:"fixture-exec",Namespace:ns},RoleRef:rbacv1.RoleRef{APIGroup:rbacv1.GroupName,Kind:"Role",Name:role.Name},Subjects:[]rbacv1.Subject{{Kind:"User",APIGroup:rbacv1.GroupName,Name:incidentManager},{Kind:"User",APIGroup:rbacv1.GroupName,Name:"fixture-human"}}}
  if _,err:=admin.RbacV1().RoleBindings(ns).Create(ctx,binding,metav1.CreateOptions{});err!=nil {t.Fatal(err)}
 }
 principal:=func(name string) client.Client {
  c:=rest.CopyConfig(cfg);c.Impersonate=rest.ImpersonationConfig{UserName:name,Groups:[]string{"system:authenticated"}}
  cl,err:=client.New(c,client.Options{Scheme:schema});if err!=nil {t.Fatal(err)}
  return client.NewDryRunClient(cl)
 }
 manager:=principal(incidentManager)
 emit:=func(action model.Action,ns string)(*corev1.Pod,error){
  c:=&incidentCapture{Client:manager}
  _,err:=dispatch(ctx,EnactCtx{Client:c},Request{Tenant:"fixture",Namespace:ns,Pod:"victim",Action:action})
  if c.captured==nil {t.Fatalf("real producer never reached subresource: %v",err)}
  return c.captured,err
 }
 secure:=func(p *corev1.Pod) bool {ec:=p.Spec.EphemeralContainers[0];return ec.Image==incidentImage && ec.SecurityContext!=nil && ec.SecurityContext.RunAsNonRoot!=nil && *ec.SecurityContext.RunAsNonRoot}
 var producer *corev1.Pod
 t.Run("OriginalProducerProfile",func(t *testing.T){
  for _,a:=range []model.Action{model.ActionDebugger,model.ActionCustomInject} {
   p,err:=emit(a,"managed-fixture");if err!=nil {t.Fatalf("unprotected real producer %s denied: %v",a,err)}
   raw,_:=json.Marshal(p.Spec.EphemeralContainers[0]);t.Logf("unprotected %s API accepted payload=%s",a,raw)
   if a==model.ActionDebugger {producer=p}
   if !secure(p) {t.Errorf("baseline security assertion: API accepted producer %s without pinned hardened profile",a)}
  }
 })
 if producer==nil {t.Fatal("missing captured producer")}
 // Seed a compliant request for cross-source admission controls. It originates from
 // the real producer; the below profile correction is explicit, not producer evidence.
 compliant:=producer.DeepCopy();ec:=&compliant.Spec.EphemeralContainers[0]
 ec.Image=incidentImage;f,tr,id:=false,true,int64(65534)
 ec.SecurityContext=&corev1.SecurityContext{Privileged:&f,AllowPrivilegeEscalation:&f,RunAsNonRoot:&tr,RunAsUser:&id,RunAsGroup:&id,ReadOnlyRootFilesystem:&tr,Capabilities:&corev1.Capabilities{Drop:[]corev1.Capability{"ALL"}},SeccompProfile:&corev1.SeccompProfile{Type:corev1.SeccompProfileTypeRuntimeDefault}}
 ec.Command=nil;ec.Args=nil
 raw,err:=os.ReadFile("/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/incident-local/policy.yaml");if err!=nil {t.Fatal(err)}
 docs:=strings.Split(string(raw),"\n---\n");p,b:=&admissionv1.ValidatingAdmissionPolicy{},&admissionv1.ValidatingAdmissionPolicyBinding{}
 if err:=yaml.Unmarshal([]byte(docs[0]),p);err!=nil {t.Fatal(err)};if err:=yaml.Unmarshal([]byte(docs[1]),b);err!=nil {t.Fatal(err)}
 if _,err:=admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx,p,metav1.CreateOptions{});err!=nil {t.Fatal(err)}
 if _,err:=admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx,b,metav1.CreateOptions{});err!=nil {t.Fatal(err)}
 submit:=func(c client.Client,pod *corev1.Pod)error{return c.SubResource("ephemeralcontainers").Update(ctx,pod.DeepCopy())}
 bad:=compliant.DeepCopy();bad.Spec.EphemeralContainers[0].Image="busybox:1.36"
 deadline:=time.Now().Add(12*time.Second)
 for {
  err=submit(manager,bad)
  if err!=nil && strings.Contains(err.Error(),"code-exec/image") {break}
  if time.Now().After(deadline) {t.Fatalf("policy never enforced attributable image rule: %v",err)}
  time.Sleep(100*time.Millisecond)
 }
 t.Log("enforcement active: actual subresource denied by code-exec/image")
 t.Run("ProtectedRealProducers",func(t *testing.T){
  for _,a:=range []model.Action{model.ActionDebugger,model.ActionCustomInject} {
   payload,err:=emit(a,"managed-fixture")
   if !secure(payload) {
    if err==nil || !strings.Contains(err.Error(),"code-exec/") {t.Errorf("baseline producer must be denied by installed contract: %v",err)}
    t.Logf("baseline incompatible producer %s denied: %v",a,err)
   }else if err!=nil {t.Errorf("hardened real producer %s denied: %v",a,err)} else {t.Logf("hardened real producer %s allowed by real API",a)}
  }
 })
 t.Run("AdmissionControls",func(t *testing.T){
  if err:=submit(manager,compliant);err!=nil {t.Fatalf("compliant control denied: %v",err)}
  for _,tc:=range []struct{name,rule string; mutate func(*corev1.EphemeralContainer)}{
   {"image","image",func(e *corev1.EphemeralContainer){e.Image="busybox:1.36"}},
   {"name","name",func(e *corev1.EphemeralContainer){e.Name="other-debugger"}},
   {"privileged","securityContext",func(e *corev1.EphemeralContainer){*e.SecurityContext.Privileged=true; *e.SecurityContext.AllowPrivilegeEscalation=true}},
   {"root-user","securityContext",func(e *corev1.EphemeralContainer){*e.SecurityContext.RunAsUser=0}},
   {"capabilities","capabilities",func(e *corev1.EphemeralContainer){e.SecurityContext.Capabilities.Add=[]corev1.Capability{"NET_ADMIN"}}},
   {"seccomp","seccomp",func(e *corev1.EphemeralContainer){e.SecurityContext.SeccompProfile.Type=corev1.SeccompProfileTypeUnconfined}},
   {"custom-args","command",func(e *corev1.EphemeralContainer){e.Name="phorvex-custom";e.Command=[]string{"sh","-c"};e.Args=[]string{"echo unapproved"}}},
   {"apparmor","securityContext-extra",func(e *corev1.EphemeralContainer){e.SecurityContext.AppArmorProfile=&corev1.AppArmorProfile{Type:corev1.AppArmorProfileTypeUnconfined}}},
   {"command","command",func(e *corev1.EphemeralContainer){e.Command=[]string{"sh"}}},
   {"stdin","fields",func(e *corev1.EphemeralContainer){e.Stdin=true}},
  } {
   q:=compliant.DeepCopy();tc.mutate(&q.Spec.EphemeralContainers[0]);err:=submit(manager,q)
   if err==nil || !strings.Contains(err.Error(),"code-exec/"+tc.rule) {t.Errorf("%s denial not attributable to expected VAP rule: %v",tc.name,err)}else{t.Logf("%s -> %s",tc.name,err)}
  }
  if err:=submit(principal("fixture-human"),compliant);err==nil || !strings.Contains(err.Error(),"code-exec/identity") {t.Errorf("non-allowlisted identity not denied by VAP: %v",err)}
  unmanaged,err:=admin.CoreV1().Pods("unmanaged-fixture").Get(ctx,"victim",metav1.GetOptions{});if err!=nil {t.Fatal(err)}
  unmanaged.Spec.EphemeralContainers=bad.Spec.EphemeralContainers
  if err:=submit(principal("fixture-human"),unmanaged);err!=nil {t.Errorf("unlabelled legitimate human debug control unexpectedly denied: %v",err)}
 })
 for _,ns:=range []string{"managed-fixture","unmanaged-fixture"} {
  pod,err:=admin.CoreV1().Pods(ns).Get(ctx,"victim",metav1.GetOptions{});if err!=nil {t.Fatal(err)}
  if len(pod.Spec.EphemeralContainers)!=0 {t.Fatal("dry-run persisted ephemeral injection")}
 }
 t.Log(fmt.Sprintf("all ephemeral submissions remained non-persistent; test server %s destroyed on return",version.GitVersion))
}
