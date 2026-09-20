# Independently verified empty model readiness

Exact executed source `ce0b697b2176c3a1921a598e1096a275d58ab51e` (contains accepted Tier19 and M179), with current main `8d783a5ba4c8c61a0a650ce36f33182af06595bb` as ancestry. Actual httpVLLM.ModelReady sends one health GET and one models GET to a loopback httptest server. Complete `{"data":[]}` returns ready=true despite no loaded model; the required false assertion fails. The valid nonempty `{"data":[{"id":"model-a"}]}` positive returns true and passes. Each case proves exactly two GETs and zero POSTs. Go1.26.1,0.020s; no cluster or serving mutation. Original source is exercised; no production guard disabled. The unchanged test and raw output are retained.

Root cause gpu_stack.go ModelReady calls parseAdapterInventory with a sentinel to validate syntax then ignores its semantic content, unconditionally returning true. The parser correctly permits empty adapter inventory for authoritative absence; that absence contract must not be broken to repair readiness. Empty model readiness can feed warm candidate promotion/replenishment; actual candidate and authenticated Native/controller controls are required in the fix. Nonempty inventory alone does not prove the expected model or GPU availability; retain those live limits.

Retained evidence SHA256:

- baseline.log: 8012e20860175711bc99d5c33749b9e9c3e199d121a2049cb7010b6962c1e062
- probe.go: 590b94d96d71056928ba12f284803cf2747123bd5dcbe9378ece6ff172792f22
