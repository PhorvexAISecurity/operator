# Root-cause dedup

Determination: NEW. Reviewed the closest root causes: M-140 scopes learned state to recreated policy identity, whereas this producer/consumer pair binds a catalogue SecurityEvent to a Pod lifetime. M-9 distinguishes dispatch acknowledgment from actuator effect and does not select the requested Pod. M-155 is a two-controller race after event emission; this issue exists with the console handler alone before either controller acts. M-25 concerns classifier stage and M-136 authentication: preserving these trust boundaries does not validate targetPod/targetUid. M-185 concerns UI hint claims and M-184 capability valuation. None supplies the additive exact-target contract or snapshot UID binding.

Independent handler and actual KubeSource tests are in VERIFICATION.md; fix CAT-EXACT-TARGET is already authorized and implemented within the campaign. No claim of live business mis-targeting or deployed correction is made.
