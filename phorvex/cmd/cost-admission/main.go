package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/servingbudget"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// dns1123Label matches a single Kubernetes namespace / Service name label.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func validLabel(s string) bool {
	return len(s) > 0 && len(s) <= 63 && dns1123Label.MatchString(s)
}

// admissionConfig resolves the validated tenant namespace, forward backend and downward
// Pod UID from the environment. It fails closed on a missing or malformed namespace or
// Pod UID, and on any backend that is not a plain in-namespace cluster Service URL — a
// cross-namespace, external or non-http backend is refused so the proxy can never be
// pointed at another tenant's workload. When PHORVEX_THROTTLE_BACKEND is absent the
// backend defaults to the reviewed cost-target-backend Service in the pod's own
// namespace, which for the costbench-opus benchmark tenant is byte-for-byte the
// historical fixed http://cost-target-backend.costbench-opus.svc:8080.
func admissionConfig(getenv func(string) string) (namespace, backend, podUID string, err error) {
	namespace = getenv("POD_NAMESPACE")
	podUID = getenv("POD_UID")
	if !validLabel(namespace) {
		return "", "", "", errors.New("POD_NAMESPACE must be a valid downward-API namespace")
	}
	if podUID == "" {
		return "", "", "", errors.New("POD_UID (downward Pod UID) is required")
	}
	backend = getenv("PHORVEX_THROTTLE_BACKEND")
	if backend == "" {
		backend = "http://" + servingbudget.BackendName + "." + namespace + ".svc:8080"
	}
	if err = validateBackend(backend, namespace); err != nil {
		return "", "", "", err
	}
	return namespace, backend, podUID, nil
}

// validateBackend refuses anything but a plain in-namespace cluster Service URL:
// http scheme only, no userinfo/query/fragment, no request path, and a host of the form
// <service>.<pod-namespace>.svc with an optional cluster.local domain. This is the
// fail-closed cross-namespace guard: the admission proxy forwards only to a Service in
// the exact namespace it runs in.
func validateBackend(backend, namespace string) error {
	u, parseErr := url.Parse(backend)
	if parseErr != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return errors.New("PHORVEX_THROTTLE_BACKEND must be a plain http://<service>.<namespace>.svc[:port] URL")
	}
	labels := strings.Split(u.Hostname(), ".")
	if len(labels) < 3 || !validLabel(labels[0]) || labels[1] != namespace || labels[2] != "svc" {
		return errors.New("PHORVEX_THROTTLE_BACKEND must address a Service in the pod namespace")
	}
	if len(labels) > 3 && strings.Join(labels[3:], ".") != "cluster.local" {
		return errors.New("PHORVEX_THROTTLE_BACKEND cluster domain must be cluster.local")
	}
	return nil
}

func main() {
	namespace, backend, podUID, err := admissionConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	c, e := client.New(config.GetConfigOrDie(), client.Options{Scheme: s})
	if e != nil {
		log.Fatal(e)
	}
	p, e := servingbudget.NewProxy(backend, podUID)
	if e != nil {
		log.Fatal(e)
	}
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e := p.Sync(ctx, c, namespace)
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
