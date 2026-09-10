# Verification — lead evidence, peer challenge pending

This intake consolidates earlier read-only observations and local tests. It does
not retroactively claim those local tests were pre-registered by this intake.

Claim: the primary container is identified from spec, but its running digest is
selected from the first nonempty status entry without matching the container name.
Falsifier: the actual producer returns the spec primary container running digest
regardless of status ordering, or the consumer intentionally selects that sidecar.
Control: identical Pod with status entries aligned with spec. Producer projection
and real fake-Kubernetes-client -> CollectSnapshot -> Derive both exercised.

Source: dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca. Live image/digest and scope are
in STATUS.yaml and the assessment's LIVE-FINDINGS.md. The test fixture contains
observed image names/digests; no secret environment or credential was collected.

Evidence in ../../assessments/20260910-readiness/evidence/:
- live-vllm-image-projection.json (sanitized observed Pod identity/containers)
- lead_live_image_test.go, lead-live-image-overlay.json, lead-live-image.log
- lead_live_image_consumer_test.go, lead-live-image-consumer-overlay.json,
  lead-live-image-consumer.log

The wrong digest and consumer cache miss reproduce. Aligned ordering passes.
The exact digest cache used by the consumer test is hypothetical; this does not
claim the deployed cache score or a specific vulnerability/attack outcome.
Local fake clients only, no live mutation or cleanup requirement beyond ending
read-only observation. Independent review and root-cause dedup pending; no
canonical issue or repair is authorized by this intake state alone.

## Independent review completed

Independent R3 section2.2 confirms real CollectSnapshot -> Derive -> EPSS discriminator: aligned/exact hits, aligned/stale falls back, observed ordering misses under both caches. Scope includes sidecar-first status permutations; primary-only versus all-container modeling remains separate.

Lead accepted this bounded finding; see ../../assessments/20260910-readiness/fresh-integration/LEAD-REVIEW-R3.md and sealed r3/REPORT-R3.md with SHA256SUMS-R3. Positive control PASS. The source/deployment pins in STATUS.yaml are unchanged.
