# Verified repository credential exposure

Codex lead independently compared the authorized private access value in memory against Git's actual `.claude/settings.json` blob at both `418cf20` and `dbf5fa4`, and the current tracked file. All contain the exact supplied SSH password. The value and any password digest are deliberately absent from this evidence. A copy with the value replaced and an unrelated module file both fail the same membership check, establishing a discriminating control.

The credential was already committed before the tier's changes. This is repository exposure through agent tool configuration, distinct from a product endpoint authentication defect or the credential-theft test oracle. No attacker access, public distribution, new successful login, or misuse is claimed. Credential validity was not probed as part of this verification.

Required correction: remove the credential-bearing command from versioned project settings, reference private owner-controlled access where needed, and prevent reintroduction. Removing a current file does not revoke existing copies: DevOps owns credential rotation and any history/access review. Agents must not rotate the credential, rewrite shared history, or change shared infrastructure under the current scope. Track source correction and external rotation separately. This late finding is for the next tier refresh, not a reason to silently alter the completed first-tier product packages.

Evidence: `evidence/verification.json`. The private comparison read the known authorized access file; only boolean results were persisted.
