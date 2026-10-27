package main

import (
	"context"
	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/servingbudget"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"time"
)

func main() {
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	_ = apps.AddToScheme(s)
	_ = discovery.AddToScheme(s)
	_ = api.AddToScheme(s)
	_ = amtd.AddToScheme(s)
	c, e := client.New(config.GetConfigOrDie(), client.Options{Scheme: s})
	if e != nil {
		log.Fatal(e)
	}
	d := &servingbudget.Detector{}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		e = servingbudget.DetectOnce(ctx, c, d, "costbench-opus", "cost-defense")
		cancel()
		if e != nil {
			log.Printf("cost detector: %v", e)
		}
		time.Sleep(5 * time.Second)
	}
}
