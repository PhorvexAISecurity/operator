// ragstore-fixture is the lane fixture for the datastore-restore actuator: a tiny datastore
// (RAG index / agent persistent-memory / tool-data store) workload. Its persistent content lives
// in an operator-owned ConfigMap (the datastore), which the app re-reads LIVE from the Kubernetes
// API on every request — so a restore is reflected instantly (no projected-volume kubelet lag)
// and the "store hash == trusted snapshot" readback is honest. Because the content lives in the
// ConfigMap (not the pod), the poison PERSISTS across a pod rotate, which is exactly why only a
// datastore-restore — not rotate/quarantine — remediates it. The app never writes the store; the
// attack poisons the ConfigMap and the brain restores it. The hash is computed with the SAME
// canonical algorithm the actuator uses (internal/datastore), so the two agree byte-for-byte.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/phorvex/phorvex/internal/datastore"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}
	ns := getenv("POD_NAMESPACE", "default")
	cmName := getenv("STORE_CONFIGMAP", datastore.StoreConfigMapName)
	key := getenv("STORE_KEY", datastore.StoreKey)

	// readStore does a FRESH API Get per call (never a cached informer) so the served content
	// always reflects the authoritative ConfigMap the actuator CASes.
	readStore := func(ctx context.Context) ([]byte, error) {
		cm, e := clientset.CoreV1().ConfigMaps(ns).Get(ctx, cmName, metav1.GetOptions{})
		if e != nil {
			return nil, e
		}
		return []byte(cm.Data[key]), nil
	}

	srv := &http.Server{Addr: getenv("LISTEN", ":8080"), Handler: newStoreMux(readStore), ReadHeaderTimeout: 3 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}

// newStoreMux builds the fixture's HTTP surface over an injectable store reader so the
// readiness probe (/healthz) and the datastore oracle endpoints can be exercised in a
// unit test without an in-cluster Kubernetes API. The chart's rag-store readinessProbe
// targets /healthz on the http (8080) port.
func newStoreMux(readStore func(ctx context.Context) ([]byte, error)) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// The oracle endpoint the actuator polls: the canonical sha256 of the live store content.
	mux.HandleFunc(datastore.ReadbackPath, func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		raw, e := readStore(ctx)
		if e != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
			return
		}
		sha, e := datastore.CanonicalSHA(raw)
		if e != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "store unparseable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"sha256": sha})
	})
	// Two-sided demo: fetch one record by id (404 once a poisoned record is restored away).
	mux.HandleFunc(datastore.GetPath, func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		raw, e := readStore(ctx)
		if e != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
			return
		}
		st, e := datastore.ParseStore(raw)
		if e != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "store unparseable"})
			return
		}
		for _, rec := range st.Records {
			if rec.ID == id {
				writeJSON(w, http.StatusOK, map[string]string{"id": rec.ID, "content": rec.Content})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"id": id, "found": "false"})
	})
	// Full dump: the ids currently served + the canonical hash.
	mux.HandleFunc(datastore.DumpPath, func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		raw, e := readStore(ctx)
		if e != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
			return
		}
		st, e := datastore.ParseStore(raw)
		if e != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "store unparseable"})
			return
		}
		sha, _ := datastore.CanonicalSHA(raw)
		writeJSON(w, http.StatusOK, map[string]any{"ids": st.IDs(), "sha256": sha, "count": len(st.Records)})
	})
	return mux
}
