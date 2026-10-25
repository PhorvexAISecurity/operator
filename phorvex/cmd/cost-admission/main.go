package main

import (
	"context"
	"github.com/phorvex/phorvex/internal/servingbudget"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"net/http"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"time"
)

func main() {
	ns := os.Getenv("POD_NAMESPACE")
	uid := os.Getenv("POD_UID")
	if ns != "costbench-opus" || uid == "" {
		log.Fatal("exact namespace and downward Pod UID required")
	}
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	c, e := client.New(config.GetConfigOrDie(), client.Options{Scheme: s})
	if e != nil {
		log.Fatal(e)
	}
	p, e := servingbudget.NewProxy("http://cost-target-backend.costbench-opus.svc:8080", uid)
	if e != nil {
		log.Fatal(e)
	}
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e := p.Sync(ctx, c, ns)
			cancel()
			if e != nil {
				log.Printf("admission sync: %v", e)
			}
			time.Sleep(time.Second)
		}
	}()
	server := &http.Server{Addr: ":8080", Handler: p, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	log.Fatal(server.ListenAndServe())
}
