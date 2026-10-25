package main

import (
	"context"
	"flag"
	"fmt"
	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	b "github.com/phorvex/phorvex/internal/servingbudget"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"time"
)

func main() {
	mode := flag.String("mode", "status", "status, calibrate, arm or rollback")
	operator := flag.String("operator-namespace", "phorvex-system", "protected journal namespace")
	operation := flag.String("operation", "", "exact rollback operation ID")
	policyUID := flag.String("policy-uid", "", "exact selecting policy UID for rollback")
	flag.Parse()
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	_ = api.AddToScheme(s)
	c, e := client.New(config.GetConfigOrDie(), client.Options{Scheme: s})
	if e != nil {
		log.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	switch *mode {
	case "rollback":
		e = actuator.RollbackThrottle(ctx, c, *operator, *operation, *policyUID)
	case "status":
		var st b.Status
		st, e = b.ReadStatus(ctx, c, "costbench-opus")
		fmt.Println(b.Encode(st))
	case "calibrate":
		var cm core.ConfigMap
		e = c.Get(ctx, client.ObjectKey{Namespace: "costbench-opus", Name: b.ConfigName}, &cm)
		if e != nil {
			break
		}
		var contract b.Contract
		contract, e = b.Parse(cm.Data[b.Key])
		if e != nil {
			break
		}
		if contract.Enabled || !b.Approved(contract) {
			log.Fatal("cannot calibrate an enabled/unapproved contract")
		}
		if contract.Calibrating {
			log.Fatal("calibration already active; arm before starting a new quiet reference")
		}
		contract.Calibrating = true
		contract.Revision++
		cm.Data[b.Key] = b.Encode(contract)
		e = c.Update(ctx, &cm)
	case "arm":
		var st b.Status
		st, e = b.ReadStatus(ctx, c, "costbench-opus")
		if e != nil {
			break
		}
		if !st.Fresh(time.Now()) || !b.Positive(st.Baseline) || !b.Positive(st.Reserved) || st.CalibrationEnd.Sub(st.CalibrationStart) < b.Horizon {
			log.Fatal("fresh nonzero measured quiet calibration required")
		}
		var cm core.ConfigMap
		e = c.Get(ctx, client.ObjectKey{Namespace: "costbench-opus", Name: b.ConfigName}, &cm)
		if e != nil {
			break
		}
		var contract b.Contract
		contract, e = b.Parse(cm.Data[b.Key])
		if e != nil {
			break
		}
		if contract != st.Contract || !contract.Calibrating || contract.Enabled || !b.Approved(contract) {
			log.Fatal("exact calibrating source/epoch required")
		}
		contract.Calibrating = false
		contract.Revision++
		cm.Data[b.Key] = b.Encode(contract)
		e = c.Update(ctx, &cm)
	default:
		log.Fatal("unknown mode")
	}
	if e != nil {
		log.Fatal(e)
	}
}
