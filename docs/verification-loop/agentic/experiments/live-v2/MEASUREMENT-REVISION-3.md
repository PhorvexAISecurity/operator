# Prospective measurement revision 3

Preregistered on 10 October 2026 before physical episodes 3 and 4. Independent
scope review accepts this bounded proposal subject to executable code and
adverse-check review. It does not accept a runtime result.

## Retained failures and the sampling hypothesis

Episodes 1 and 2 remain INCOMPLETE. Episode 2 demonstrated the installed brain's
native adapter removal, the specific owned-route HTTP404, and six repeated
owned-route denials paired with successful ordinary base-model inference over
the required hold. Its availability gate failed: no one ordinary request
contained the entire conservative native-effect bracket widened by 200 ms.

The widened interval was 14:06:31.407474–14:06:32.563631 UTC. The ordinary
request ending 14:06:32.274224 missed the end; the next request began after the
interval's start. All six 128-token ordinary requests succeeded and lasted
4.094–4.246 seconds. Sequential requests can leave a containment gap at a
request boundary even while the service continues responding.

Two staggered ordinary streams are a prospective sampling hypothesis. They do
not establish availability until one real successful request contains the
whole widened interval. No partial overlap, aggregate union, or retrospective
reinterpretation is accepted.

## Fixed execution profile

- Two ordinary base-model streams, each with eleven fixed request plans.
- At most 22 requests combined, each reserving 128 output tokens: 2,816 tokens
  for this measurement and the unchanged 2,928 whole-episode reservation.
- At most two ordinary requests in flight. This explicitly increases the
  concurrent ordinary-request bound from one to two.
- Stream 2 starts from stream 1's actual remote HTTP monotonic start plus
  2,000 ms on the same node clock. A local acknowledgment or process-launch
  timestamp is insufficient. One resident helper owns two fixed threads;
  actual start is recorded immediately at the reviewed HTTP call boundary.
  Stream 2 must never start early and must start no more than 100 ms after its
  exact due time. This prospective bound is not a measured feasibility claim.
- Each stream, request and nonce has a unique preregistered identity. Preserve
  every response, actual start/end, requested/generated tokens, resident clock
  measurement, and terminal operation state.
- Check aggregate counts and maximum concurrency from actual evidence. Validate
  all attempted responses across both streams; a failed or ambiguous flight
  cannot be hidden by another successful flight.
- Stop and drain both streams after native completion or any error. Preserve
  uncertainty if a terminal acknowledgment or response is missing.

Both streams must actually issue at least one request. Stopped unused suffix
plans remain reservations, not completed requests. Every actually started
request needs its drained response or an explicit terminal-ambiguity finding.

The ten-second legitimate-request latency limit, minimum eight generated
tokens, full conservative-bracket containment plus 200 ms, clock bounds,
strict baseline controls, six varied denial re-probes, paired ordinary controls,
ten-second precleanup hold and exact guarded cleanup remain unchanged.

## Scope, independence and stop conditions

This revises measurement tools only. Policy, brain, scoring, stimulus, native
actuator and shared deployment configuration remain unchanged. Authors repair
the runner and gate; an independent reviewer checks the stationary source and
adverse controls before any new physical execution.

There are two remaining episodes within the already approved four-total ceiling:
episode 3 by the independent reviewer and episode 4 by the independent verifier,
using the same final reviewed sampling profile and fresh run, adapter, event
and request identities. Neither executes before the previous episode's safe
cleanup has been independently reviewed and its exclusive lease released.

Each episode retains 180 seconds execution plus a separate 60-second guarded
cleanup reservation, one owned fixture below 8 MiB and no new paid
infrastructure. The existing deadline is 15:11 UTC. No blind retry or extra
physical episode follows an exhausted bound. Two accepted independent fresh
results are required for live architecture acceptance; otherwise report the
precise unresolved stage and preserve all evidence.
