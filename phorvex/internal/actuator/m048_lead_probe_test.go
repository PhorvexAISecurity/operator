package actuator
import (
 "context"
 "testing"
 corev1 "k8s.io/api/core/v1"
 networkingv1 "k8s.io/api/networking/v1"
 metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
 "sigs.k8s.io/controller-runtime/pkg/client"
)
func TestM048LeadIncarnation(t *testing.T) {
 ctx:=context.Background()
 p:=ownedPod("ns","same",map[string]string{"app":"x"},metav1.OwnerReference{})
 c:=qtnClient(p)
 r,e:=dispatch(ctx,EnactCtx{Client:c,Reader:c},Request{Namespace:p.Namespace,Pod:p.Name,TargetUID:string(p.UID),Action:"quarantine"})
 if e!=nil || !r.Emitted {t.Fatalf("positive control initial quarantine: %+v %v",r,e)}
 var old corev1.Pod
 if e=c.Get(ctx,client.ObjectKeyFromObject(p),&old);e!=nil {t.Fatal(e)}
 if e=c.Delete(ctx,&old);e!=nil {t.Fatal(e)}
 next:=p.DeepCopy();next.UID="uid-new";next.ResourceVersion=""
 if e=c.Create(ctx,next);e!=nil {t.Fatal(e)}
 r,e=dispatch(ctx,EnactCtx{Client:c,Reader:c},Request{Namespace:p.Namespace,Pod:p.Name,TargetUID:string(next.UID),Action:"quarantine"})
 if e!=nil || !r.Emitted {t.Fatalf("new authorized incarnation must reconcile: %+v %v",r,e)}
 var policies networkingv1.NetworkPolicyList
 if e=c.List(ctx,&policies);e!=nil {t.Fatal(e)}
 found:=false
 for _,np:=range policies.Items {if np.Spec.PodSelector.MatchLabels[quarantineLabel]==string(next.UID) {for _,o:=range np.OwnerReferences {if o.Kind=="Pod" && o.UID==next.UID {found=true}}}}
 if !found {t.Fatal("no policy owned by and selecting new UID")}
}
