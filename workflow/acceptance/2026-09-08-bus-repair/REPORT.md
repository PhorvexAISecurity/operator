# Bus repair — 2026-09-08

## Incident

File delivery worked. Claude's completion-only shell watcher did not surface incremental stdout, and its initial newest-filename cursor skipped pending mail. Codex's detached monitor could not resume an ended model turn. Earlier claims of a complete fix were premature.

## Implemented

- bus.py monitor includes pending messages by default; --new-only is explicit.
- bus.py wait completes on pending mail or within at most 60 seconds, for runners that surface tool completion rather than streaming stdout. No automatic acknowledgement.
- bridge.py scans the canonical inbox and queues path-only peer notifications to one explicitly bound existing Codex thread using the installed CLI's queue command. No new agent, role change or model override.
- Queue success receipts survive service restarts; failed/ambiguous attempts retry; recipient acknowledgement remains separate. Ambiguous failures can duplicate notifications, requiring idempotent handling.
- Local user service phorvex-bus-codex-m006.service is enabled with Restart=on-failure. Runtime state is ignored under coordination/.runtime; exact thread binding refuses silent redirection. Stop with systemctl --user stop phorvex-bus-codex-m006.service; disable to end supervision.
- BUS.md and the agent entrypoint document runner requirements and finite-wait fallback.

## Evidence

- Eight transport regressions passed: existing mail, timeout, default monitor, queue restart deduplication, retries, ambiguous timeout, recipient/archive isolation and delivery after inbox shrink.
- Real CLI probe accepted into the existing thread (receipt 01a0825c-8a54-7bb3-9ba6-2fcd159ce8dd).
- Challenge #18 BUS-M006-20260908-B produced Claude reply #19. Claude explicitly reports the Monitor facility resumed his turn without a user prompt. Both messages are archived in the canonical bus.
- Adapter queued #15 and #19; restart preserved both queue receipts without redelivery. Captured runtime JSON is queue acceptance evidence only.
- Deep doctor: 0 errors, 13 existing migration/anatomy warnings.
- First full suite: 64/65 passed; new entrypoint prose exceeded context budget by 10 words. Shortened prose; final full suite passed all 65 tests (tests-final.txt).

## Idle resumption: PASS

After the repair turn ended, the next turn was triggered by the exact queued
bus-probe-20260908-A message. No additional human prompt was needed. The CLI
receipt is no longer in the thread queue and the supervised bridge remains
active. See idle-resume.json for the observed timestamp and queue identifiers.
The Claude challenge/reply, real bridge queue receipts, restart check and this
idle continuation establish the handoff path in the current running clients.

Next, continue the already-owned M6 rev4 review and requested image digest/metadata capture from bus #15. Its message remains unacknowledged until handled; a duplicate queued notice for an archived challenge requires no repeated action. Product implementation remains gated by the recorded design/security decisions.

## Sources and limitations

Installed Codex CLI queue --help confirms targeting a thread; the installed VS Code turn coordinator has an idle queue executor. Official app-server docs describe start/steer and turn completion: https://learn.chatgpt.com/docs/app-server . Neither source substitutes for the idle-resumption test in this runner. The bridge needs the local user service and a capable Codex runner; heartbeat or queue acceptance alone is not model execution. Historical file-bus evidence is retained unchanged.
