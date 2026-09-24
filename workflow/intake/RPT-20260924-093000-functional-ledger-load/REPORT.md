# Fixed-suite launch after unreadable retained run history

The real `StartFunctional` path checks unsafe runs from the in-memory map but does not check `RunManager.loadErr`. A malformed retained `run-events.jsonl` after restart therefore permits a new run although the prior retry state is unknown.

Worker and lead independently reproduced allocation of `v1run-1` and an append to the malformed ledger through `NewRunManager` then `StartFunctional`, using a valid fixed profile and an inert local executable. The lead baseline is integration `bbce251b565429939cb945e3fd6f36e65147c0f9`. No cluster call, provider call or deployed-state claim is involved. Expected behavior is refusal before any sequence, directory, job or ledger change.

This is separate from the observed fsGroup compatibility issue and does not authorize clearing any historical unsafe run.
