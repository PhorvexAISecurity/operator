# P-FORENSICS — debugger/custom injection

Use a disposable authorized target with ephemeral-container support and an inert
forensic image. Verify the target identity and a permitted/denied RBAC control.
Invoke only the planned action and confirm the exact ephemeral container or
artifact appears on the intended target, with expected privileges and an audit
receipt. Check evidence reaches the approved sink without leaking credentials.

Test an unsupported/denied case and verify it fails honestly, without claiming an
injection occurred. Preserve workload request outcomes and identity. PASS means
the diagnostic contract holds, not that an attack was neutralized. Ephemeral
containers cannot simply be removed; dispose of the fixture under the approved
cleanup plan. Never inject a diagnostic image into a shared workload by default.
