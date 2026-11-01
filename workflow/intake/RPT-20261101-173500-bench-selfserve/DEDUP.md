# Root-cause comparison

Determination: NEW operability regression in benchmark admission and retained staging capture configuration, with an explicit follow-up relationship to BENCH-STAGE.

The ranked candidates returned by dedup-intake are lexical matches. M-140 concerns learned tenant state surviving policy recreation; this incident observes a correct policy UID but a missing policy/source capture pin, with no policy recreation. M-144 concerns the product lambda update economics; this incident fails before any cost selector executes. M-155 concerns a two-operator attack/test race, whereas these exact capture admission predicates do not launch an attack. M-3 concerns validation of policy spec values, not uploaded benchmark readiness. M-116 concerns guardrail false positives, unrelated to this transport/admission path.

The semantically closer M-168 concerns Console attack availability experiments claiming results after stimulus failure and unsafe restart recovery. This user upload is a distinct offline brain replay path whose syntax-only validation omits policy/source/history readiness, and whose capture access/configuration is lost across staging releases. No attack stimulus or restart oracle is used. M-159 concerns CI test execution, also distinct.

BENCH-STAGE repaired producer transport and introduced source-qualified replay/endpoint studies. Its merged source remains present. The new release omitted non-durable operational settings, the installed bot pin did not follow that source, and the single fixed legacy prompt hash does not describe the edited10day request. BENCH-SELFSERVE already tracks the requested follow-up remediation. No existing canonical M-issue describes this root cause; filing it must not mark the older economics/attack issues fixed.
