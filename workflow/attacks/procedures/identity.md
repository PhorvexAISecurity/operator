# GP9 — identity and credential invalidation

Name the credential class first: pod-bound service-account token, legacy token,
external API key, certificate or application session. Do not assume they share
revocation semantics. Use a least-privilege test identity and authorized replay
endpoint; retain no token value in evidence.

Demonstrate authorized replay before the move, trigger identity-rotate, and replay
the captured old identity after the documented propagation interval. Check the
replacement identity works and unrelated clients retain their access. Record
real status codes and elapsed times, not a changed identity label.

PASS is scoped old-identity invalidation with service impact within budget.
If only a label changes, the effect test fails. Never claim stolen external keys
were revoked by pod replacement. Cleanup explicitly revokes test credentials and
removes owned artifacts. Historical references: GP9/S1, T10.
