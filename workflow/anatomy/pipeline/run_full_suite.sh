#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

generators=(
  derive
  gen_handlers
  gen_call_inventory
  gen_operations
  build_effect_matrix
  build_operation_matrix
)

audits=(
  repo_census
  validate
  audit_anchors
  audit_completeness
  audit_entrypoints
  audit_delivery
  audit_exec_boundaries
  audit_surfaces
  audit_reachability
  audit_operations
  audit_curation_accuracy
)

for script in "${generators[@]}"; do
  echo "GEN $script"
  python3 "$script.py"
done

for script in "${audits[@]}"; do
  echo "AUDIT $script"
  python3 "$script.py"
done

echo "MUTATION mutation_test"
python3 mutation_test.py

echo "anatomy pipeline: ${#audits[@]}/${#audits[@]} audits PASS"
