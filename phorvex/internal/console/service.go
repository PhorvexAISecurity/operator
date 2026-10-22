package console

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Service is the part of the console API one process serves (ADR-0001, phase 6). The
// attacks service holds attack firing, the harness runs and their evidence; the
// console holds the UI and every other route.
type Service string

const (
	// ServiceAll serves every route in one process, as the console did before the
	// attacks service existed.
	ServiceAll Service = ""
	// ServiceConsole serves the UI and the console's routes, and forwards the attack
	// routes to the attacks service at Config.AttacksURL.
	ServiceConsole Service = "console"
	// ServiceAttacks serves only the attack routes.
	ServiceAttacks Service = "attacks"
)

// serves reports whether this process answers a route itself.
func (c Config) serves(rt route) bool {
	switch c.Service {
	case ServiceConsole:
		return !rt.spec.attacks
	case ServiceAttacks:
		return rt.spec.attacks
	}
	return true
}

// servesAttacks reports whether this process holds the runs and the attack records.
func (c Config) servesAttacks() bool { return c.Service != ServiceConsole }

// ValidateService refuses a service the process cannot run: a console that forwards
// needs the attacks service's origin, and nothing else may name one.
func (c Config) ValidateService() error {
	switch c.Service {
	case ServiceAll, ServiceAttacks:
		if c.AttacksURL != "" {
			return fmt.Errorf("only a console that forwards to the attacks service takes an attacks URL")
		}
		return nil
	case ServiceConsole:
		u, err := url.Parse(c.AttacksURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return fmt.Errorf("attacks URL %q must be an http(s) origin", c.AttacksURL)
		}
		return nil
	}
	return fmt.Errorf("unknown console service %q", c.Service)
}

// newAttacksProxy forwards a request to the attacks service with the headers the caller
// sent, the signed ALB identity and the Origin among them, so the attacks service
// authenticates and authorizes it itself. Run streams are server-sent events, so
// every write is flushed.
func newAttacksProxy(origin string) http.Handler {
	target, _ := url.Parse(origin) // ValidateService checked it
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("attacks service unavailable", "path", r.URL.Path, "err", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the attacks service is unavailable"})
		},
	}
}

// forward serves an attack route of a console that runs beside the attacks service.
// The console admits the caller as it admits its own routes; the attacks service, which
// holds the runs and attack records the scope checks read, applies the whole boundary
// again before it acts.
func (s *Server) forward(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.admit(rt, w, r); !ok {
			return
		}
		s.attacks.ServeHTTP(w, r)
	}
}
