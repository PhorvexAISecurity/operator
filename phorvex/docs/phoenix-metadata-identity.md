# Phoenix metadata identity

Phorvex derives each Phoenix AMTD name from its namespace and tenant. Names and
tenant labels that were valid before the bounded encoding was introduced remain
byte-for-byte unchanged. A legacy value that exceeds Kubernetes' metadata limit is
replaced by a readable prefix and a versioned digest of the complete raw identity.

Owned AMTDs and SecurityEvents carry the exact namespace and tenant in versioned
`phorvex.ai/*-raw` annotations. Names and labels are lookup aids; the annotations
are the ownership evidence. Phorvex refuses to update an object when its owner
marker or identity annotations are missing, partial, unknown, or inconsistent.

An annotation-free legacy AMTD is adopted automatically only when its tenant was
already canonical (`tenant == sanitize(tenant)`) and its namespace, name, tenant
label, and managed-by marker all match. Legacy noncanonical tenant spelling was
lost during sanitization and cannot be reconstructed safely; an operator must
review and migrate that object explicitly.

This encoding does not make Phoenix rules globally unique. Phoenix detects rule
collisions by comparing complete rule triples for AMTDs whose selectors overlap.
The bounded metadata change preserves those rule triples and their matching
behavior.
