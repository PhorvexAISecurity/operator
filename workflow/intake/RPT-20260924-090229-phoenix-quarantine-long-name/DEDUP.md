# Root-cause comparison

Determination: DUPLICATE of M-53.

M-53 covers label values assembled from valid Kubernetes identity strings that overflow the 63-character label limit. Its earlier fixes addressed other producers; this remaining Phoenix SecurityEvent quarantine producer concatenates namespace, full Pod name and policy suffix, then uses that string as the Pod and NetworkPolicy selector label. It violates the same invariant and needs the same bounded-identity correction. Prior source fixes do not close this backend occurrence.

M-126 concerns different tenant-label derivation. The present reproduction is specifically the Phoenix quarantine resource-name/selector producer and is not a new tenant selector or decision-scoring defect. CAT-PHOENIX-LABEL is attached to M-53 as a follow-up. No new issue number is warranted.
