# Native marker output

`tools/generate-native-rbac.sh` pins controller-gen v0.17.2 and reads only
`phorvex/internal/actuator`. `role.yaml` is an **unbound review artifact**, the union
of routine and optional code-exec requirements. Do not install/bind it as the
routine role. Raw and Helm installation roles are separately maintained with
routine/code-exec separation. No supported full-manager RBAC generator existed
at the baseline. This command does not replace `config/rbac/role.yaml`.

`tools/check-native-rbac.sh` checks reproducibility plus an independent semantic
contract and rendered routine permissions. Change the justified permission
matrix/test alongside intentional additions. No bindings are generated here.
