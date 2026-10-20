package capability

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/model"
)

// SupportUnobserved prefixes the exclusion detail of a counterfactual evaluation
// that reached the backend support leg for a target and action the tick's
// reviewing passes never asked the actuator about.
const SupportUnobserved = "capability-unobserved"

// supportAnswers records the tick's backend support answers. SupportsAction may
// read the cluster, read protected journals and probe the workload, so only the
// reviewing paths (the real gate and the ActionsSupported status) ask the
// actuator; each records what it was told. A counterfactual evaluation answers
// from these records alone and so has no externally visible effect (M-163).
type supportAnswers struct {
	mu      sync.Mutex
	answers map[string]supportAnswer
}

type supportAnswer struct {
	ok  bool
	why string
}

func newSupportAnswers() *supportAnswers {
	return &supportAnswers{answers: map[string]supportAnswer{}}
}

func (s *supportAnswers) record(key string, ok bool, why string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[key] = supportAnswer{ok: ok, why: why}
}

func (s *supportAnswers) lookup(key string) (supportAnswer, bool) {
	if s == nil {
		return supportAnswer{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	answer, ok := s.answers[key]
	return answer, ok
}

// supportKey identifies one support question by every fact the actuator is
// given, so a recorded answer is reused only for exactly the same question.
func supportKey(a model.Action, t actuatorapi.Target) string {
	labels := make([]string, 0, len(t.Labels))
	for k, v := range t.Labels {
		labels = append(labels, k+"\x01"+v)
	}
	sort.Strings(labels)
	return strings.Join([]string{string(a), t.Namespace, t.Pod, t.UID, t.NodeName, strconv.FormatBool(t.HasGPU),
		t.MIGResource, t.PolicyName, t.PolicyUID, t.ServiceAccount, strings.Join(labels, "\x02")}, "\x00")
}

// support answers the backend support leg. A reviewing evaluation asks the
// actuator and records the answer; an observing one answers from the answers
// recorded this tick and never asks.
func (w Witness) support(a model.Action, t actuatorapi.Target, review bool) (bool, string) {
	key := supportKey(a, t)
	if !review {
		if answer, ok := w.supports.lookup(key); ok {
			return answer.ok, answer.why
		}
		return false, SupportUnobserved + ": the actuator was not asked about this target and action this tick"
	}
	ok, why := w.act.SupportsAction(w.ctx, a, t)
	w.supports.record(key, ok, why)
	return ok, why
}
