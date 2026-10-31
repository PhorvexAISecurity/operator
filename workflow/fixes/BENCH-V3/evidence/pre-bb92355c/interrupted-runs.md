# Superseded source verification

Source 773f782bdf8fc3fc068b4293d2ebad8f75328e43 based on 1c23931621d47218ded424b58e4db127344fb33b.

Both preflight processes were interrupted on the lead's integration instruction
when origin/main advanced to bb92355cf7b6c4a696f44caf52bd5fa1268e7303.
Python preflight parents received SIGINT; run_plan cleaned up owned child
process groups, and both shell sessions exited 130. No source was changed until
those sessions exited. Neither run produced a completed receipt or is a PASS.

The initial run passed all 293 workflow unit tests, index/render checks and chart
jobs (299 tooling tests with 9 pre-existing expected failures plus recipe suites),
but doctor failed because the worker put environment notes into the reserved
manifest schema. The malformed file is preserved as ../run-environment.yaml.
The index was restored from existing signed STATUS hashes, producer and timestamp
fields; ../doctor-after-manifest-repair.txt exits 0, with historical warnings only.
No signature, role, approval or source test was waived or rewritten.

The corrected rerun was interrupted during workflow unit tests. Raw output and
per-job logs of both incomplete runs remain retained in this directory and
../preflight-run.txt / ../preflight-rerun.txt. The previous source commit remains
available at branch fix/benchmark-v3-capture-before-bb92355c. New proofs use the
integration-bb92355c directory and the newly pinned source.
