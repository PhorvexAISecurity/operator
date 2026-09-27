package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actuator"
)

func TestKVMigrationFireRefusesBeforeProducerOrEvent(t *testing.T) {
	calls := 0
	s := &Server{cfg: Config{Exec: func(time.Duration, string, ...string) (string, error) { calls++; return "", nil }}}
	response := httptest.NewRecorder()
	s.vllmAttack(response, httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"kv-migrate-invalidate"}`)))
	if response.Code != http.StatusConflict || calls != 0 || !strings.Contains(response.Body.String(), actuator.ReasonKVMigrationConnectorUnavailable) {
		t.Fatalf("unavailable migration fire = code %d, exec calls %d, body %s", response.Code, calls, response.Body.String())
	}
	rows := compatibleLive(appStack{Namespace: "vllm", VLLM: true, Armed: true})
	for _, row := range rows {
		if row.ID != "kv-migrate-invalidate" {
			continue
		}
		if !row.Compatible || row.Armed || row.Reason != actuator.ReasonKVMigrationConnectorUnavailable {
			t.Fatalf("migration was advertised armed: %+v", row)
		}
		return
	}
	t.Fatal("migration compatibility row disappeared")
}
