# Independently reproduced — source defect verified

At merged main47c22857 (identical relevant production bytes in checkpoint source8690791b), the production availabilityFloor accepts Rotate at Ready2/desired3/policyMin1 while discovered Physics carries PDBMin2/disruptionsAllowed0. The stricter policyMin2 and nonremoving-action positive controls both pass. Raw overlay and intended failing assertion are in evidence/result.log.

A second independent probe uses an isolated Kubernetes1.34 API server, real CRDs, ReplicaSet-owned Ready Pod, selecting active PhorvexPolicy and a matching PDB. Because envtest has no disruption controller, PDB status is explicitly seeded to the observed dev condition (currentHealthy2/desiredHealthy2/expectedPods3/allowed0/current generation). The real API Eviction subresource refuses with TooManyRequests; native dispatch subsequently emits direct Pod Delete and the exact Pod gains deletionTimestamp. This is the intended failing assertion, not a transport/test setup failure. The local test-only finalizer is released after observing the result. No shared workload was mutated.

Commands: Go1.26.3, GOMAXPROCS2, GOFLAGS-p1, KUBECONFIG/dev/null, USE_EXISTING_CLUSTER=false, local envtest1.34; go test -overlay=api-overlay.json ./internal/actuator -run TestLeadVoicePDBActualAPIRefusal -count=1 -v. Raw api-result.log and full producer test retained.

The real dev voice PDB/current policy snapshot supplies the motivating shape but does not establish that a particular observed dev Pod loss was caused by this defect. This verification proves local actual-API budget bypass plus the planning predicate gap. It does not prove WebSocket session continuity or production safety.

Contract reference: https://kubernetes.io/docs/concepts/scheduling-eviction/api-eviction/ documents budget refusal by the Eviction subresource. Planned repair must preserve policy/UID/resourceVersion/grace binding and never fall back from a denied or ambiguous eviction to direct deletion.
