package ingest

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// Offline actual-Python-producer envelope through the unmodified manager binder.
func TestAdapterInventoryProducerBindsOnlyAuthenticatedExactPod(t *testing.T) {
	trustEvents(t, "owned/adapter-detector")
	var fixture struct {
		Body     json.RawMessage `json:"body"`
		Admitted json.RawMessage `json:"admitted"`
	}
	fixturePath := os.Getenv("ADAPTER_PRODUCER_FIXTURE")
	if fixturePath == "" {
		fixturePath = "../../../deploy/detectors/adapter-inventory/producer_envelope.json"
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil { t.Fatal(err) }
	if err := json.Unmarshal(raw, &fixture); err != nil { t.Fatal(err) }
	now := time.Date(2026, 9, 24, 3, 21, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		change func(*amtdv1beta1.SecurityEvent)
		want bool
	}{
		{name:"admitted producer envelope", want:true},
		{name:"wrong Pod UID", change:func(e *amtdv1beta1.SecurityEvent){e.Annotations[AdapterTargetUIDAnnotation]="other-uid"}},
		{name:"missing authenticated stamp", change:func(e *amtdv1beta1.SecurityEvent){delete(e.Annotations,CreatorIdentityAnnotation)}},
		{name:"wrong rule type", change:func(e *amtdv1beta1.SecurityEvent){e.Spec.Rule.Type="lora.unauthorized_adapter"}},
		{name:"stale API creation", change:func(e *amtdv1beta1.SecurityEvent){e.CreationTimestamp=metav1.NewTime(now.Add(-16*time.Minute))}},
	} {
		t.Run(tc.name,func(t *testing.T){
			var event amtdv1beta1.SecurityEvent
			if err:=json.Unmarshal(fixture.Admitted,&event); err!=nil {t.Fatal(err)}
			if tc.change!=nil {tc.change(&event)}
			scheme:=runtime.NewScheme()
			if err:=amtdv1beta1.AddToScheme(scheme); err!=nil {t.Fatal(err)}
			c:=fake.NewClientBuilder().WithScheme(scheme).WithObjects(&event).Build()
			all,byPod,_,err:=collectEventsAndReceipts(context.Background(),c,now,map[string]string{"owned/engine-0":"pod-uid-1"})
			if err!=nil {t.Fatal(err)}
			if len(all)!=1 {t.Fatalf("event projection count=%d",len(all))}
			pod:=model.Pod{Namespace:"owned",Name:"engine-0",UID:"pod-uid-1"}
			bindAdapterObservation(&pod,byPod["owned/engine-0"])
			got:=pod.AdapterObservation!=nil
			if got!=tc.want {t.Fatalf("bound=%v want=%v trust=%s",got,tc.want,all[0].Trust)}
			if got && (pod.SuspectAdapter!="owned-neutral-adapter" || pod.AdapterObservation.EventUID!="api-uid-1") {t.Fatalf("wrong adapter binding: %+v",pod.AdapterObservation)}
		})
	}
}
