#!/usr/bin/env bash
# Provisions the services' gRPC mutual TLS Secrets (docs/services/service-tls.md):
# one CA and four identity-bound leaf certificates, one Secret per end, in the
# release's namespace:
#   <release>-dispatcher-grpc-tls  client  DNS:<release>-dispatcher.<namespace>.svc
#   <release>-brain-grpc-tls       server  DNS:<release>-brain, <release>-brain.<namespace>.svc
#   <release>-sensor-grpc-tls      server  DNS:<release>-sensor, ...
#   <release>-actuator-grpc-tls    server  DNS:<release>-actuator, ...
# Each Secret holds tls.crt, tls.key and ca.crt. The CA's signing key never leaves
# the temporary directory, which is removed on exit: rotating means issuing all four
# again (FORCE_ROTATE=true). The services read their Secrets on every handshake; the
# dispatcher reads its CA when it starts, so restart it after a rotation.
set -euo pipefail

NAMESPACE="${NAMESPACE:-phorvex-staging}"
RELEASE="${RELEASE:-staging}"
CERT_DAYS="${CERT_DAYS:-397}"
FORCE_ROTATE="${FORCE_ROTATE:-false}"

for command in kubectl openssl base64 mktemp cmp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done
if ! [[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
   ! [[ "$RELEASE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
   ! [[ "$CERT_DAYS" =~ ^[1-9][0-9]{0,3}$ ]] ||
   ! [[ "$FORCE_ROTATE" =~ ^(true|false)$ ]]; then
  echo "invalid service mTLS provisioning input" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/phorvex-service-mtls.XXXXXX")"
case "$tmp" in
  "${TMPDIR:-/tmp}"/phorvex-service-mtls.*) ;;
  *) echo "refusing unsafe temporary path: $tmp" >&2; exit 1 ;;
esac
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"

ends=(dispatcher brain sensor actuator)
secret() { printf '%s-%s-grpc-tls' "$RELEASE" "$1"; }
# The name a certificate is checked against: the dispatcher's identity, or the
# Service name the dispatcher dials.
identity() {
  if [ "$1" = dispatcher ]; then
    printf '%s-dispatcher.%s.svc' "$RELEASE" "$NAMESPACE"
  else
    printf '%s-%s' "$RELEASE" "$1"
  fi
}
purpose() { if [ "$1" = dispatcher ]; then echo sslclient; else echo sslserver; fi; }

read_secret() {
  local name="$1" directory="$2"
  mkdir -p "$directory"
  for file in tls.crt tls.key ca.crt; do
    kubectl -n "$NAMESPACE" get secret "$name" -o jsonpath="{.data.${file//./\\.}}" |
      base64 --decode > "$directory/$file"
  done
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

# The Secrets are kept when all four are present, unexpired, identity-bound and
# share one CA.
current_ok=true
for end in "${ends[@]}"; do
  if ! read_secret "$(secret "$end")" "$tmp/current-$end" 2>/dev/null ||
     ! valid_leaf "$tmp/current-$end" "$(identity "$end")" "$(purpose "$end")" ||
     ! cmp -s "$tmp/current-dispatcher/ca.crt" "$tmp/current-$end/ca.crt"; then
    current_ok=false
  fi
done
if [ "$FORCE_ROTATE" = false ] && [ "$current_ok" = true ]; then
  echo "service mTLS Secrets are present, unexpired, identity-bound, and share one CA"
  exit 0
fi

echo "provisioning a fresh service CA and four identity-bound leaf certificates"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$CERT_DAYS" \
  -subj "/CN=Phorvex $RELEASE service CA" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tmp/ca.key" -out "$tmp/ca.crt" >/dev/null 2>&1

issue_leaf() {
  local end="$1" directory="$tmp/$1" dns usage names
  dns="$(identity "$end")"
  mkdir -p "$directory"
  if [ "$end" = dispatcher ]; then
    usage=clientAuth
    names="DNS:$dns"
  else
    usage=serverAuth
    names="DNS:$dns,DNS:$dns.$NAMESPACE,DNS:$dns.$NAMESPACE.svc,DNS:$dns.$NAMESPACE.svc.cluster.local"
  fi
  openssl req -new -newkey rsa:2048 -sha256 -nodes -subj "/CN=$dns" \
    -keyout "$directory/tls.key" -out "$directory/tls.csr" >/dev/null 2>&1
  cat > "$directory/extensions.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usage
subjectAltName=$names
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -sha256 -days "$CERT_DAYS" \
    -in "$directory/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
    -extfile "$directory/extensions.cnf" -out "$directory/tls.crt" >/dev/null 2>&1
  cp "$tmp/ca.crt" "$directory/ca.crt"
  valid_leaf "$directory" "$dns" "$(purpose "$end")"
}

manifests="$tmp/secrets.yaml"
: > "$manifests"
for end in "${ends[@]}"; do
  issue_leaf "$end"
  kubectl -n "$NAMESPACE" create secret generic "$(secret "$end")" \
    --from-file=tls.crt="$tmp/$end/tls.crt" \
    --from-file=tls.key="$tmp/$end/tls.key" \
    --from-file=ca.crt="$tmp/$end/ca.crt" \
    --dry-run=client -o yaml | sed '/^[[:space:]]*creationTimestamp: null$/d' >> "$manifests"
  printf '%s\n' '---' >> "$manifests"
done
kubectl apply -f "$manifests" >/dev/null

for end in "${ends[@]}"; do
  kubectl -n "$NAMESPACE" label secret "$(secret "$end")" \
    app.kubernetes.io/managed-by=phorvex-service-mtls-bootstrap \
    phorvex.ai/purpose=service-grpc-tls --overwrite >/dev/null
  kubectl -n "$NAMESPACE" annotate secret "$(secret "$end")" \
    phorvex.ai/dns-name="$(identity "$end")" --overwrite >/dev/null
done

# Validate the stored objects, not just the files used to build them.
for end in "${ends[@]}"; do
  read_secret "$(secret "$end")" "$tmp/stored-$end"
  valid_leaf "$tmp/stored-$end" "$(identity "$end")" "$(purpose "$end")"
  cmp -s "$tmp/stored-dispatcher/ca.crt" "$tmp/stored-$end/ca.crt"
done
echo "service mTLS Secrets provisioned and verified in namespace $NAMESPACE"
