#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-phorvex-system}"
SERVER_SECRET="${SERVER_SECRET:-phorvex-audit-server}"
CLIENT_SECRET="${CLIENT_SECRET:-phorvex-audit-client}"
SERVER_DNS="${SERVER_DNS:-phorvex-stack-phorvex-audit-source.phorvex-system.svc}"
CLIENT_DNS="${CLIENT_DNS:-phorvex-stack-phorvex-console.phorvex-system.svc}"
CERT_DAYS="${CERT_DAYS:-397}"
FORCE_ROTATE="${FORCE_ROTATE:-false}"

for command in kubectl openssl base64 mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

if ! [[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
   ! [[ "$SERVER_SECRET" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
   ! [[ "$CLIENT_SECRET" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
   ! [[ "$SERVER_DNS" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] ||
   ! [[ "$CLIENT_DNS" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] ||
   ! [[ "$CERT_DAYS" =~ ^[1-9][0-9]{0,3}$ ]] ||
   ! [[ "$FORCE_ROTATE" =~ ^(true|false)$ ]]; then
  echo "invalid audit mTLS provisioning input" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/phorvex-audit-mtls.XXXXXX")"
case "$tmp" in
  "${TMPDIR:-/tmp}"/phorvex-audit-mtls.*) ;;
  *) echo "refusing unsafe temporary path: $tmp" >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT
umask 077

read_secret() {
  local name="$1" directory="$2"
  mkdir -p "$directory"
  kubectl -n "$NAMESPACE" get secret "$name" -o jsonpath='{.data.tls\.crt}' |
    base64 --decode > "$directory/tls.crt"
  kubectl -n "$NAMESPACE" get secret "$name" -o jsonpath='{.data.tls\.key}' |
    base64 --decode > "$directory/tls.key"
  kubectl -n "$NAMESPACE" get secret "$name" -o jsonpath='{.data.ca\.crt}' |
    base64 --decode > "$directory/ca.crt"
  test -s "$directory/tls.crt" -a -s "$directory/tls.key" -a -s "$directory/ca.crt"
}

valid_leaf() {
  local directory="$1" dns="$2" purpose="$3"
  openssl x509 -in "$directory/tls.crt" -noout -checkhost "$dns" >/dev/null 2>&1 &&
    openssl x509 -in "$directory/tls.crt" -noout -checkend 0 >/dev/null 2>&1 &&
    openssl verify -purpose "$purpose" -CAfile "$directory/ca.crt" \
      "$directory/tls.crt" >/dev/null 2>&1 &&
    test "$(openssl x509 -in "$directory/tls.crt" -pubkey -noout | openssl sha256)" = \
         "$(openssl pkey -in "$directory/tls.key" -pubout | openssl sha256)"
}

server_ok=false
client_ok=false
if read_secret "$SERVER_SECRET" "$tmp/current-server" 2>/dev/null &&
   valid_leaf "$tmp/current-server" "$SERVER_DNS" sslserver; then
  server_ok=true
fi
if read_secret "$CLIENT_SECRET" "$tmp/current-client" 2>/dev/null &&
   valid_leaf "$tmp/current-client" "$CLIENT_DNS" sslclient; then
  client_ok=true
fi

if [ "$FORCE_ROTATE" = false ] &&
   [ "$server_ok" = true ] && [ "$client_ok" = true ] &&
   cmp -s "$tmp/current-server/ca.crt" "$tmp/current-client/ca.crt"; then
  echo "audit mTLS Secrets are present, unexpired, identity-bound, and share one CA"
  exit 0
fi

echo "provisioning a fresh audit transport CA and two identity-scoped leaf certificates"
mkdir -p "$tmp/server" "$tmp/client"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$CERT_DAYS" \
  -subj '/CN=Phorvex audit transport CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tmp/ca.key" -out "$tmp/ca.crt" >/dev/null 2>&1

issue_leaf() {
  local directory="$1" dns="$2" usage="$3"
  openssl req -new -newkey rsa:2048 -sha256 -nodes -subj "/CN=$dns" \
    -keyout "$directory/tls.key" -out "$directory/tls.csr" >/dev/null 2>&1
  cat > "$directory/extensions.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usage
subjectAltName=DNS:$dns
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -sha256 -days "$CERT_DAYS" \
    -in "$directory/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
    -extfile "$directory/extensions.cnf" -out "$directory/tls.crt" >/dev/null 2>&1
  cp "$tmp/ca.crt" "$directory/ca.crt"
}

issue_leaf "$tmp/server" "$SERVER_DNS" serverAuth
issue_leaf "$tmp/client" "$CLIENT_DNS" clientAuth
valid_leaf "$tmp/server" "$SERVER_DNS" sslserver
valid_leaf "$tmp/client" "$CLIENT_DNS" sslclient

kubectl -n "$NAMESPACE" create secret generic "$SERVER_SECRET" \
  --from-file=tls.crt="$tmp/server/tls.crt" \
  --from-file=tls.key="$tmp/server/tls.key" \
  --from-file=ca.crt="$tmp/server/ca.crt" \
  --dry-run=client -o yaml > "$tmp/server-secret.yaml"
kubectl -n "$NAMESPACE" create secret generic "$CLIENT_SECRET" \
  --from-file=tls.crt="$tmp/client/tls.crt" \
  --from-file=tls.key="$tmp/client/tls.key" \
  --from-file=ca.crt="$tmp/client/ca.crt" \
  --dry-run=client -o yaml > "$tmp/client-secret.yaml"
{
  sed '/^[[:space:]]*creationTimestamp: null$/d' "$tmp/server-secret.yaml"
  printf '%s\n' '---'
  sed '/^[[:space:]]*creationTimestamp: null$/d' "$tmp/client-secret.yaml"
} | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" label secret "$SERVER_SECRET" "$CLIENT_SECRET" \
  app.kubernetes.io/managed-by=phorvex-audit-mtls-bootstrap \
  phorvex.ai/purpose=audit-transport --overwrite >/dev/null
kubectl -n "$NAMESPACE" annotate secret "$SERVER_SECRET" \
  phorvex.ai/dns-name="$SERVER_DNS" --overwrite >/dev/null
kubectl -n "$NAMESPACE" annotate secret "$CLIENT_SECRET" \
  phorvex.ai/dns-name="$CLIENT_DNS" --overwrite >/dev/null

# Validate the stored objects, not just the files used to build them. The CA signing key
# remains only in the protected temporary directory and is removed by the EXIT trap.
read_secret "$SERVER_SECRET" "$tmp/stored-server"
read_secret "$CLIENT_SECRET" "$tmp/stored-client"
valid_leaf "$tmp/stored-server" "$SERVER_DNS" sslserver
valid_leaf "$tmp/stored-client" "$CLIENT_DNS" sslclient
cmp -s "$tmp/stored-server/ca.crt" "$tmp/stored-client/ca.crt"
echo "audit mTLS Secrets provisioned and verified in namespace $NAMESPACE"
