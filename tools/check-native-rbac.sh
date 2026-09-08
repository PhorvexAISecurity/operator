#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rbac_tmp=$(mktemp -d)
trap 'rm -rf "$rbac_tmp"' EXIT
./tools/generate-native-rbac.sh "$rbac_tmp/generated"
diff -u phorvex/config/rbac/generated-native/role.yaml "$rbac_tmp/generated/role.yaml"
helm template m007 phorvex/charts/phorvex -n phorvex-system \
 --set 'phorvex.actuatorNamespaces[0]=phorvex-tenant' > "$rbac_tmp/rendered.yaml"
M007_RENDERED_RBAC="$rbac_tmp/rendered.yaml" GOMAXPROCS=2 go -C phorvex test -p 2 ./internal/actuator \
 -run 'TestM007|TestNativeRBAC|TestServiceRestitch|TestRouteRotate' -count=1 -v
