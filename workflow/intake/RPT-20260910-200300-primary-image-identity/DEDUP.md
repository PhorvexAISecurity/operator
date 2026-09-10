# Root-cause comparison — pending peer challenge

M31 addresses vulnerability identity normalization; M141 covers cache freshness,
feed policy and repository fallback. Selecting another named container's digest
occurs before either normalizing that digest or retrieving its cache entry.
Fixing normalization/cache refresh alone cannot recover the intended primary
container. Tentative NEW. Broader all-container vulnerability aggregation is a
separate design question. The independent reviewer must challenge this boundary.
