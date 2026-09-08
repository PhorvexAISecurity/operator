# 02A — Skeptic blind derivation

Write this before opening the proposal, diff, implementation branch, or
proposal/diff messages.

## Independent root-cause model

Trace incident inputs → producers → decisive values/branches → outcome from
baseline source. Enumerate compound-predicate arms, fallbacks and stale/missing
inputs; identify any assumed upstream fix that is not actually present.

## Expected minimal fix

## Independently predicted behavioral delta

- Class:
- Exact delta or falsifiable bands:
- Expected no-change surface:

## Failure modes and adversarial tests

## Required RED/GREEN and live criteria

## Coverage limits

Seal with:

```bash
python3 workflow/tools/workflow.py seal <fix-id> --by <skeptic-id> --expect-revision N
```
